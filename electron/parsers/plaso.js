// ── Plaso (.plaso) SQLite parser ─────────────────────────────────────

const fs = require("fs");
const zlib = require("zlib");
const { dbg } = require("../logger");

const BATCH_SIZE_DEFAULT = 100000;
const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch

/**
 * Validate that a file is a genuine Plaso SQLite database.
 * @returns {{ valid: boolean, formatVersion?: string, compressionFormat?: string }}
 */
function validatePlasoFile(filePath) {
  const Database = require("better-sqlite3");
  let plasoDb;
  try {
    plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
    const hasMeta = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'"
    ).get();
    if (!hasMeta) return { valid: false };
    const fmtRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'format_version'"
    ).get();
    if (!fmtRow) return { valid: false };
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    return {
      valid: true,
      formatVersion: String(fmtRow.value),
      compressionFormat: compRow ? String(compRow.value) : "none",
    };
  } catch {
    return { valid: false };
  } finally {
    try { plasoDb?.close(); } catch {}
  }
}

/**
 * Decompress and parse a Plaso event_data blob.
 * Handles both zlib-compressed BLOBs and plain-text JSON.
 */
function parsePlasoBlob(data, useZlib) {
  if (data == null) return {};
  try {
    let jsonStr;
    if (useZlib && Buffer.isBuffer(data)) {
      // Guard against decompression bombs — cap at 64MB per blob
      const inflated = zlib.inflateSync(data, { maxOutputLength: 64 * 1024 * 1024 });
      jsonStr = inflated.toString("utf-8");
    } else {
      jsonStr = typeof data === "string" ? data : data.toString("utf-8");
    }
    return JSON.parse(jsonStr);
  } catch {
    return {};
  }
}

/**
 * Parse a Plaso (.plaso) SQLite file and insert events into TimelineDB.
 *
 * Plaso schema:
 *   metadata: key/value pairs (format_version, compression_format)
 *   event: _timestamp (int64 microseconds), _timestamp_desc, _event_data_row_identifier
 *   event_data: _identifier (PK), _data (JSON text or zlib-compressed blob)
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parsePlasoFile(filePath, tabId, db, onProgress) {
  const Database = require("better-sqlite3");
  let plasoDb;
  try {
    plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
  } catch (e) {
    throw new Error(`Cannot open Plaso file: ${e.message}`);
  }
  plasoDb.pragma("mmap_size = 268435456"); // 256MB mmap for read-only Plaso file
  plasoDb.pragma("cache_size = -65536");  // 64MB cache (read-only, sequential scan)

  try {
    // Read compression setting
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    const useZlib = compRow?.value?.toString().toUpperCase() === "ZLIB";

    // Detect schema — check which tables exist
    const tables = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'"
    ).all().map((r) => r.name);
    const hasEventData = tables.includes("event_data");
    const hasEvent = tables.includes("event");
    if (!hasEvent) throw new Error("Plaso file missing 'event' table");

    // Detect event table column names (varies between Plaso format versions)
    // Old format: _timestamp, _timestamp_desc, _event_data_row_identifier
    // New format (20230327+): timestamp, timestamp_desc, _event_data_identifier
    const eventCols = plasoDb.pragma("table_info(event)").map((c) => c.name);
    const tsCol = eventCols.includes("_timestamp") ? "_timestamp" : "timestamp";
    const tsDescCol = eventCols.includes("_timestamp_desc") ? "_timestamp_desc" : "timestamp_desc";
    const edRefCol = eventCols.includes("_event_data_row_identifier")
      ? "_event_data_row_identifier"
      : eventCols.includes("_event_data_identifier")
        ? "_event_data_identifier"
        : null;

    // Detect if the reference column uses "event_data.N" format (new) vs plain integer (old)
    let joinIsTextRef = false;
    if (edRefCol && hasEventData) {
      const sample = plasoDb.prepare(`SELECT ${edRefCol} FROM event LIMIT 1`).get();
      if (sample) {
        const val = String(sample[edRefCol]);
        joinIsTextRef = val.startsWith("event_data.");
      }
    }

    // Count events for progress
    const totalEvents = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event").get().cnt;

    // Phase 1: Column discovery — sample event_data entries to find all field keys
    const FIXED_FIELDS = ["datetime", "timestamp_desc", "data_type"];
    const fieldSet = new Set();

    if (hasEventData) {
      // Sample from start + middle + end in a single query to discover all field keys
      const edCount = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event_data").get().cnt;
      const midOffset = Math.max(0, Math.floor(edCount / 2));
      const endOffset = Math.max(0, edCount - 200);
      const sampleSql = `SELECT _data FROM (SELECT _data FROM event_data LIMIT 300) UNION ALL SELECT _data FROM (SELECT _data FROM event_data LIMIT 200 OFFSET ${midOffset}) UNION ALL SELECT _data FROM (SELECT _data FROM event_data LIMIT 200 OFFSET ${endOffset})`;
      for (const row of plasoDb.prepare(sampleSql).iterate()) {
        const obj = parsePlasoBlob(row._data, useZlib);
        for (const key of Object.keys(obj)) {
          if (!key.startsWith("__") && !key.startsWith("_")) fieldSet.add(key);
        }
      }
    }

    // Remove fields handled in fixed positions
    fieldSet.delete("data_type");
    fieldSet.delete("timestamp_desc");
    const discoveredFields = [...fieldSet].sort();
    const headers = [...FIXED_FIELDS, ...discoveredFields];
    const colCount = headers.length;

    // Create the TLE tab with discovered headers
    db.createTab(tabId, headers);

    // Phase 2: Stream events in batches
    // For text-ref format ("event_data.N"), extract the integer and match against PK
    // to enable SEARCH USING INTEGER PRIMARY KEY instead of full table scan.
    // Skip ORDER BY — events are stored in chronological order; app sorts after import.
    let eventStmt;
    if (hasEventData && edRefCol) {
      // Text-ref: "event_data.N" → extract N via SUBSTR(col, 12) and match against integer PK
      const joinCondition = joinIsTextRef
        ? `ed._identifier = CAST(SUBSTR(e.${edRefCol}, 12) AS INTEGER)`
        : `e.${edRefCol} = ed._identifier`;
      eventStmt = plasoDb.prepare(`
        SELECT e.${tsCol} AS ts, e.${tsDescCol} AS ts_desc, ed._data
        FROM event e
        LEFT JOIN event_data ed ON ${joinCondition}
      `);
    } else {
      eventStmt = plasoDb.prepare(`
        SELECT ${tsCol} AS ts, ${tsDescCol} AS ts_desc, _data FROM event
      `);
    }

    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;
    const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));

    for (const row of eventStmt.iterate()) {
      // Convert microseconds → ISO string "YYYY-MM-DD HH:MM:SS.ffffff"
      let datetime = "";
      if (row.ts != null && row.ts !== 0) {
        try {
          const tsNum = Number(row.ts);
          const ms = tsNum / 1000;
          const d = new Date(ms);
          if (!isNaN(d.getTime())) {
            const iso = d.toISOString(); // YYYY-MM-DDTHH:MM:SS.mmmZ
            const micros = String(Math.abs(tsNum % 1000000)).padStart(6, "0");
            datetime = iso.slice(0, 10) + " " + iso.slice(11, 19) + "." + micros;
          }
        } catch { /* leave empty */ }
      }

      // Parse event_data JSON
      const eventObj = parsePlasoBlob(row._data, useZlib);

      // Build row array in header order
      const values = new Array(colCount);
      values[0] = datetime;
      values[1] = row.ts_desc || eventObj.timestamp_desc || "";
      values[2] = eventObj.data_type || "";
      for (let i = 3; i < colCount; i++) {
        const val = eventObj[headers[i]];
        if (val == null) {
          values[i] = "";
        } else if (typeof val === "object") {
          values[i] = JSON.stringify(val);
        } else {
          values[i] = String(val);
        }
      }

      batch.push(values);
      rowCount++;

      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          if (onProgress) onProgress(rowCount, rowCount, totalEvents);
        }
      }
    }

    // Insert remaining batch
    if (batch.length > 0) {
      db.insertBatchArrays(tabId, batch);
    }

    if (onProgress) onProgress(rowCount, totalEvents, totalEvents);
    const result = db.finalizeImport(tabId);

    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  } finally {
    try { plasoDb.close(); } catch {}
  }
}

module.exports = { validatePlasoFile, parsePlasoFile };
