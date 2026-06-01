/**
 * import.js — File import pipeline
 *
 * Extracted from main.js. Handles file validation, sheet selection,
 * parse orchestration, post-import index/FTS scheduling, and USN path resolution.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { dialog } = require("electron");
const { dbg } = require("./logger");
const { resolveTempDir } = require("./utils/temp-dir");

/**
 * Import a file into the application.
 *
 * @param {string} filePath - Path to the file to import
 * @param {string|null} preTabId - Pre-assigned tab ID (for session restore)
 * @param {string|null} preSheetName - Pre-assigned sheet name (for XLSX)
 * @param {object} deps - Dependencies from main.js
 */
async function importFile(filePath, preTabId, preSheetName, deps) {
  const { mainWindow, safeSend, activeWindow, getXLSXSheets, enqueueImport, nextTabId } = deps;

  const tabId = preTabId || nextTabId();
  let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  const ext = path.extname(filePath).toLowerCase();
  dbg("IMPORT", `importFile called`, { filePath, tabId, ext, preSheetName });

  // Pre-flight check for very large files
  let fileSize = 0;
  try { fileSize = fs.statSync(filePath).size; } catch {}
  const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024 * 1024; // 10GB

  // XLSX/XLSM this large is not a practical import target for the current parser.
  if ((ext === ".xlsx" || ext === ".xlsm") && fileSize > LARGE_FILE_THRESHOLD) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const limitGB = (LARGE_FILE_THRESHOLD / (1024 ** 3)).toFixed(0);
    if (mainWindow) {
      await dialog.showMessageBox(activeWindow(), {
        type: "error",
        title: "XLSX Too Large",
        message: `This workbook is ${sizeGB} GB`,
        detail: `XLSX/XLSM imports above ${limitGB} GB are not supported in this build. Convert the workbook to CSV and import the CSV instead.`,
        buttons: ["OK"],
      });
    }
    dbg("IMPORT", `Blocked oversized XLSX import`, { filePath, sizeGB, limitGB });
    safeSend("import-error", {
      tabId,
      fileName,
      error: `XLSX/XLSM imports above ${limitGB} GB are not supported — convert to CSV first`,
    });
    return;
  }

  if (fileSize > LARGE_FILE_THRESHOLD && mainWindow) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const ramGB = Math.round(os.totalmem() / (1024 ** 3));
    const { response } = await dialog.showMessageBox(activeWindow(), {
      type: "warning",
      title: "Large File Warning",
      message: `This file is ${sizeGB} GB`,
      detail: `Importing very large files requires significant memory and may take a long time. The application may become unresponsive or crash.\n\nSystem RAM: ${ramGB} GB\n\nFor Plaso files this large, consider using psort to export a filtered CSV first.`,
      buttons: ["Import Anyway", "Cancel"],
      defaultId: 1,
      cancelId: 1,
    });
    if (response === 1) {
      dbg("IMPORT", `User cancelled large file import`, { filePath, sizeGB });
      safeSend("import-error", { tabId, fileName, error: `Import cancelled — file is ${sizeGB} GB` });
      return;
    }
    dbg("IMPORT", `User chose to proceed with large file`, { filePath, sizeGB, ramGB });
  }

  // If sheetName is pre-assigned (from select-sheet or session restore), skip sheet detection
  let sheetName = preSheetName;
  if (sheetName && (ext === ".xlsx" || ext === ".xlsm") && !Number.isFinite(Number(sheetName))) {
    try {
      const sheets = await getXLSXSheets(filePath);
      const matched = sheets.find((s) => s.name === sheetName);
      if (matched) sheetName = matched.id;
    } catch (e) {
      dbg("IMPORT", `sheet name remap failed`, { filePath, sheetName, error: e.message });
    }
  }
  if (!sheetName && (ext === ".xlsx" || ext === ".xls" || ext === ".xlsm")) {
    try {
      dbg("IMPORT", `getXLSXSheets calling...`, { filePath });
      const sheets = await getXLSXSheets(filePath);
      dbg("IMPORT", `getXLSXSheets returned`, { sheetCount: sheets.length, sheets: sheets.map(s => s.name) });
      if (sheets.length > 1) {
        safeSend("sheet-selection", {
          tabId,
          fileName,
          filePath,
          sheets,
        });
        return;
      }
    } catch (e) {
      dbg("IMPORT", `getXLSXSheets failed`, { error: e.message, stack: e.stack });
    }
  }

  dbg("IMPORT", `calling startImport`, { tabId, sheetName });
  await startImport(filePath, tabId, fileName, sheetName, fileSize, deps);
}

async function startImport(filePath, tabId, fileName, sheetName, preFileSize, deps) {
  const { safeSend, db, runImportJob, scheduleIndexBuild, importQueue, pendingIndexTabs, tabMeta } = deps;

  dbg("IMPORT", `startImport begin`, { filePath, tabId, fileName, sheetName });
  let fileSize = preFileSize || 0;
  if (!fileSize) { try { fileSize = fs.statSync(filePath).size; } catch {} }
  dbg("IMPORT", `fileSize`, { fileSize });

  // ── Free-disk guardrail ──────────────────────────────────────────
  // The temp SQLite DB + per-column indexes (and, for files ≤5GB, the trigram FTS index)
  // live on the os.tmpdir() volume and can total several times the source size. Refuse up
  // front if the volume clearly lacks headroom, rather than failing with SQLITE_FULL
  // mid-build — which silently leaves a half-indexed DB and a stuffed system disk.
  if (fileSize > 0 && typeof fs.statfsSync === "function") {
    const tempDir = resolveTempDir(); // the volume the temp DB + indexes will be written to
    const FTS_GATE = 5 * 1024 * 1024 * 1024; // matches db.js isLargeFile (FTS is skipped above this)
    const ftsWillRun = fileSize <= FTS_GATE;
    // db (~1.2x) + all-column indexes (~1.5x) + WAL/temp slack, plus trigram FTS (~2.5x) when it runs.
    const requiredBytes = Math.round(fileSize * (ftsWillRun ? 5 : 2.5));
    let freeBytes = Infinity;
    try { const st = fs.statfsSync(tempDir); freeBytes = st.bavail * st.bsize; } catch {}
    if (freeBytes < requiredBytes) {
      const gb = (n) => (n / (1024 ** 3)).toFixed(0);
      dbg("IMPORT", `Refusing import — insufficient temp disk`, { fileSize, requiredBytes, freeBytes, tempDir });
      safeSend("import-error", {
        tabId, fileName,
        error: `Not enough free disk space to import this file. IRFlow needs roughly ${gb(requiredBytes)} GB free on the temp volume (${tempDir}) for the database and indexes, but only ${gb(freeBytes)} GB is available. Free up space, or choose a folder on a larger volume via Tools ▸ Set Temp Storage Folder…, and try again.`,
      });
      return;
    }
  }

  // Notify renderer that import has started
  safeSend("import-start", {
    tabId,
    fileName,
    filePath,
    fileSize,
  });

  try {
    dbg("IMPORT", `starting import worker...`);
    const result = await runImportJob(filePath, tabId, sheetName, fileSize);
    dbg("IMPORT", `parseFile complete`, { headers: result.headers?.length, rowCount: result.rowCount, tsColumns: result.tsColumns?.length });

    // Track original file path + format for features like resident data extraction
    tabMeta.set(tabId, { filePath, sourceFormat: result.sourceFormat || null });

    // ── USN Journal Rewind: resolve parent paths from the journal's own directory records ──
    let resolveStats = null;
    if (result.sourceFormat === "raw-usnjrnl") {
      let mftTabId = null;
      for (const [tid, tmeta] of tabMeta) {
        if (tmeta.sourceFormat === "raw-mft") { mftTabId = tid; break; }
      }
      dbg("IMPORT", `Resolving USN parent paths (rewind)`, { mftAvailable: !!mftTabId });
      resolveStats = db.resolveUsnPaths(tabId, mftTabId);
      dbg("IMPORT", `USN path resolution complete`, resolveStats);
    }

    // ── MFT imported: re-resolve any existing USN Journal tabs ──
    if (result.sourceFormat === "raw-mft") {
      for (const [tid, tmeta] of tabMeta) {
        if (tmeta.sourceFormat === "raw-usnjrnl") {
          dbg("IMPORT", `Re-resolving USN paths for ${tid} with new MFT data`);
          const reResolve = db.resolveUsnPaths(tid, tabId);
          dbg("IMPORT", `USN re-resolution complete`, reResolve);
          safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
        }
      }
    }

    // Fetch initial window of data (windowed — not all rows)
    dbg("IMPORT", `querying initial rows...`);
    const initialData = db.queryRows(tabId, {
      offset: 0,
      limit: 5000,
      sortCol: null,
      sortDir: "asc",
    });
    dbg("IMPORT", `initial rows fetched`, { rowCount: initialData.rows?.length, totalFiltered: initialData.totalFiltered });

    const emptyColumns = db.getEmptyColumns(tabId);
    dbg("IMPORT", `sending import-complete`);

    safeSend("import-complete", {
      tabId,
      fileName,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
      sourceFormat: result.sourceFormat || null,
      evtxMessageMode: result.evtxMessageMode || null,
      messagesDeferred: !!result.messagesDeferred,
      resolveStats,
    });

    // Security.evtx auto-detection: prompt analyst to open Lateral Movement Tracker
    // Detect by filename pattern or by checking if the dataset has Security logon event columns
    const isSecurityEvtx = /security\.evtx$/i.test(filePath)
      || (/\.evtx$/i.test(filePath) && result.headers?.some(h => /^TargetUserName$/i.test(h)) && result.headers?.some(h => /^LogonType$/i.test(h)));
    const isEvtxECmdWithLogons = result.headers?.some(h => /^RemoteHost$/i.test(h))
      && result.headers?.some(h => /^PayloadData1$/i.test(h));
    if (isSecurityEvtx || isEvtxECmdWithLogons) {
      safeSend("security-evtx-detected", { tabId, fileName, isSecurityEvtx, isEvtxECmd: isEvtxECmdWithLogons });
    }

    // Defer index/FTS builds when more imports are queued to avoid memory spikes
    if (importQueue.length > 0) {
      dbg("IMPORT", `Deferring index/FTS build for ${tabId} (${importQueue.length} imports queued)`);
      pendingIndexTabs.push(tabId);
    } else {
      // No more imports queued — build in the background worker pool immediately
      scheduleIndexBuild(tabId);
    }
  } catch (err) {
    dbg("IMPORT", `startImport FAILED`, { error: err.message, stack: err.stack });
    // Clean up partially-imported tab on failure
    try { db.closeTab(tabId); } catch (_) {}
    safeSend("import-error", {
      tabId,
      fileName,
      error: err.message,
    });
  }
}

module.exports = { importFile };
