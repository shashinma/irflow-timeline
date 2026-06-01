const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const { dialog, app } = require("electron");

module.exports = function registerSessionHandlers(safeHandle, safeSend, ctx) {
  const { db, _activeWindow, enqueueImport, _loadRecentFiles, _saveRecentFiles, _rebuildMenu, _tabMeta, _pendingIndexTabs, nextTabId, updateController, jobManager, scheduleIndexBuild } = ctx;

  // Open file dialog
  safeHandle("open-file-dialog", async () => {
    const result = await dialog.showOpenDialog(_activeWindow(), {
      properties: ["openFile", "multiSelections"],
      filters: [
        { name: "All Supported Files", extensions: ["*"] },
        { name: "CSV Files", extensions: ["csv", "tsv", "txt", "log"] },
        { name: "Excel Files", extensions: ["xlsx", "xls", "xlsm"] },
        { name: "EVTX Files", extensions: ["evtx"] },
        { name: "Plaso / Timeline Files", extensions: ["plaso", "timeline"] },
        { name: "NTFS Artifacts ($MFT, $J)", extensions: ["mft", "bin"] },
      ],
    });
    if (result.canceled) return null;
    for (const fp of result.filePaths) enqueueImport(fp);
    return true;
  });

  safeHandle("check-for-updates", async () => updateController.checkForUpdatesFromRenderer());
  safeHandle("install-update", async () => updateController.installUpdate());

  // Recent files
  safeHandle("get-recent-files", () => _loadRecentFiles());

  safeHandle("open-recent-file", (event, { filePath }) => {
    if (fs.existsSync(filePath)) {
      enqueueImport(filePath);
      return true;
    }
    // Remove stale entry
    const files = _loadRecentFiles().filter((f) => f !== filePath);
    _saveRecentFiles(files);
    _rebuildMenu();
    return { error: "File not found" };
  });

  safeHandle("clear-recent-files", () => {
    _saveRecentFiles([]);
    _rebuildMenu();
    return true;
  });

  // IOC matching
  safeHandle("load-ioc-file", async () => {
    const result = await dialog.showOpenDialog(_activeWindow(), {
      properties: ["openFile"],
      filters: [
        { name: "IOC Files", extensions: ["txt", "csv", "ioc", "tsv", "xlsx", "xls"] },
        { name: "All Files", extensions: ["*"] },
      ],
      title: "Open IOC List",
    });
    if (result.canceled || !result.filePaths.length) return null;
    const filePath = result.filePaths[0];
    const fileName = path.basename(filePath);
    const ext = path.extname(filePath).toLowerCase();
    // Common IOC value column names (lowercase for matching)
    const IOC_VALUE_HEADERS = new Set([
      "ioc_value", "ioc", "indicator", "value", "observable", "artifact",
      "indicator_value", "observable_value", "ioc_data", "data", "pattern",
    ]);

    // Detect IOC value column index from a header row
    function findIocColumn(headerRow) {
      if (!headerRow || headerRow.length === 0) return -1;
      for (let i = 0; i < headerRow.length; i++) {
        const h = String(headerRow[i]).trim().toLowerCase().replace(/[\s-]+/g, "_");
        if (IOC_VALUE_HEADERS.has(h)) return i;
      }
      return -1;
    }

    // Check if a row looks like a header (all cells are short non-IOC-like strings)
    function looksLikeHeader(row) {
      return row.length > 1 && row.every((c) => {
        const s = String(c).trim();
        return s.length < 30 && /^[a-zA-Z_\s-]+$/.test(s);
      });
    }

    try {
      if (ext === ".xlsx" || ext === ".xls") {
        const XLSX = require("xlsx");
        const wb = XLSX.readFile(filePath);
        const values = [];
        for (const sheetName of wb.SheetNames) {
          const sheet = wb.Sheets[sheetName];
          const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: "" });
          if (rows.length === 0) continue;
          // Try to detect structured data with a header row
          const iocCol = looksLikeHeader(rows[0]) ? findIocColumn(rows[0]) : -1;
          if (iocCol >= 0) {
            // Structured: extract only the IOC value column, skip header
            for (let r = 1; r < rows.length; r++) {
              const v = String(rows[r][iocCol] || "").trim();
              if (v) values.push(v);
            }
          } else {
            // Flat list or unknown structure: extract all cells
            for (const row of rows) {
              for (const cell of row) {
                const v = String(cell).trim();
                if (v) values.push(v);
              }
            }
          }
        }
        return { content: values.join("\n"), fileName };
      }
      // Plain text formats: .txt, .csv, .ioc, .tsv
      let raw = fs.readFileSync(filePath, "utf-8");
      if (ext === ".csv" || ext === ".tsv") {
        const delim = ext === ".tsv" ? "\t" : ",";
        const lines = raw.split(/\r?\n/);
        if (lines.length > 1) {
          const headerCells = lines[0].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
          const iocCol = looksLikeHeader(headerCells) ? findIocColumn(headerCells) : -1;
          if (iocCol >= 0) {
            // Structured CSV/TSV: extract only IOC value column, skip header
            const values = [];
            for (let i = 1; i < lines.length; i++) {
              const cells = lines[i].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
              const v = (cells[iocCol] || "").trim();
              if (v) values.push(v);
            }
            raw = values.join("\n");
          } else {
            // No recognized header: split all cells onto separate lines
            raw = lines.map((l) => l.split(delim).map((c) => c.trim().replace(/^"|"$/g, "")).join("\n")).join("\n");
          }
        }
      }
      return { content: raw, fileName };
    } catch (e) {
      return { error: e.message };
    }
  });

  // Close tab
  safeHandle("close-tab", (event, { tabId }) => {
    // Remove from pending index queue so deferred build doesn't fire on a closed DB
    const pendingIdx = _pendingIndexTabs.indexOf(tabId);
    if (pendingIdx !== -1) _pendingIndexTabs.splice(pendingIdx, 1);
    jobManager?.cancelWhere?.((job) => {
      const meta = job.metadata || {};
      return meta.tabId === tabId || (Array.isArray(meta.tabIds) && meta.tabIds.includes(tabId));
    });
    try {
      db.closeTab(tabId);
    } finally {
      // Always clean up metadata even if db.closeTab throws
      _tabMeta.delete(tabId);
    }
    return true;
  });

  // Sheet selection response (for multi-sheet XLSX) — route through queue
  safeHandle("select-sheet", (event, { filePath, tabId, fileName, sheetName }) => {
    enqueueImport(filePath, { tabId, sheetName, skipRecent: true });
  });

  // Merge multiple tabs into a single chronological timeline
  safeHandle("merge-tabs", async (event, { mergedTabId, sources }) => {
    try {
      safeSend("import-start", {
        tabId: mergedTabId,
        fileName: "Merged Timeline",
        filePath: "(merged)",
      });

      const result = await db.mergeTabs(mergedTabId, sources, (progress) => {
        safeSend("import-progress", {
          tabId: mergedTabId,
          rowsImported: progress.current,
          bytesRead: progress.current,
          totalBytes: progress.total,
          percent: progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0,
        });
      });

      // Fetch initial window sorted by unified datetime
      const initialData = db.queryRows(mergedTabId, {
        offset: 0,
        limit: 5000,
        sortCol: "datetime",
        sortDir: "asc",
      });

      const emptyColumns = db.getEmptyColumns(mergedTabId);

      safeSend("import-complete", {
        tabId: mergedTabId,
        fileName: "Merged Timeline",
        headers: result.headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns || [],
        initialRows: initialData.rows,
        totalFiltered: initialData.totalFiltered,
        emptyColumns,
      });

      // Build indexes + FTS (same worker-backed path as normal import flow)
      if (scheduleIndexBuild) scheduleIndexBuild(mergedTabId);

      return { success: true, rowCount: result.rowCount };
    } catch (err) {
      try { db.closeTab(mergedTabId); } catch (_) {}
      safeSend("import-error", {
        tabId: mergedTabId,
        fileName: "Merged Timeline",
        error: err.message,
      });
      return { success: false, error: err.message };
    }
  });

  // Session save
  safeHandle("save-session", async (event, { sessionData }) => {
    const result = await dialog.showSaveDialog(_activeWindow(), {
      defaultPath: "session.tle",
      filters: [{ name: "TLE Session", extensions: ["tle"] }],
    });
    if (result.canceled) return null;
    await fsp.writeFile(result.filePath, JSON.stringify(sessionData, null, 2), "utf-8");
    return result.filePath;
  });

  // Session load
  safeHandle("load-session", async () => {
    const result = await dialog.showOpenDialog(_activeWindow(), {
      properties: ["openFile"],
      filters: [{ name: "TLE Session", extensions: ["tle"] }],
    });
    if (result.canceled || !result.filePaths.length) return null;
    try {
      const raw = fs.readFileSync(result.filePaths[0], "utf-8");
      return JSON.parse(raw);
    } catch (e) {
      return { error: e.message };
    }
  });

  // Auto-save: write to a fixed path in userData, no dialog. Used by the
  // renderer's debounced auto-save effect to capture in-flight investigation
  // state so it survives crashes.
  const _autoSavePath = path.join(app.getPath("userData"), "autosave.tle");
  safeHandle("auto-save-session", async (event, { sessionData }) => {
    try {
      await fsp.writeFile(_autoSavePath, JSON.stringify(sessionData), "utf-8");
      return { ok: true, path: _autoSavePath };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  });

  // Read the auto-save file if present. Returns null if no autosave exists,
  // so the renderer can decide whether to offer restore.
  safeHandle("load-auto-save", async () => {
    try {
      if (!fs.existsSync(_autoSavePath)) return null;
      const raw = await fsp.readFile(_autoSavePath, "utf-8");
      return JSON.parse(raw);
    } catch (e) {
      return { error: e.message };
    }
  });

  // Delete the auto-save file (after a successful restore or explicit dismiss).
  safeHandle("clear-auto-save", async () => {
    try {
      if (fs.existsSync(_autoSavePath)) await fsp.unlink(_autoSavePath);
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  });

  // Import files by path (used for drag-and-drop)
  safeHandle("import-files", async (event, { filePaths }) => {
    for (const fp of filePaths) { if (fs.existsSync(fp)) enqueueImport(fp); }
    return true;
  });

  // Import file for session restore (no dialog)
  safeHandle("import-file-for-restore", async (event, { filePath, sheetName }) => {
    if (!fs.existsSync(filePath)) return { error: `File not found: ${filePath}` };
    const tabId = nextTabId();
    let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
    enqueueImport(filePath, { tabId, sheetName: sheetName || undefined, skipRecent: true });
    return { tabId, fileName };
  });

  // ── Filter Presets (persistent storage) ─────────────────────────────
  const presetsPath = path.join(app.getPath("userData"), "filter-presets.json");
  const sigmaScanPresetsPath = path.join(app.getPath("userData"), "sigma-scan-presets.json");
  const piAnalystProfilePath = path.join(app.getPath("userData"), "process-inspector-profile.json");

  safeHandle("load-filter-presets", () => {
    try { return JSON.parse(fs.readFileSync(presetsPath, "utf-8")); }
    catch { return []; }
  });

  safeHandle("save-filter-presets", async (event, { presets }) => {
    await fsp.writeFile(presetsPath, JSON.stringify(presets, null, 2));
    return true;
  });

  safeHandle("load-sigma-scan-presets", () => {
    try {
      const presets = JSON.parse(fs.readFileSync(sigmaScanPresetsPath, "utf-8"));
      return Array.isArray(presets) ? presets : [];
    } catch {
      return [];
    }
  });

  safeHandle("save-sigma-scan-presets", async (event, { presets }) => {
    const safePresets = Array.isArray(presets) ? presets : [];
    await fsp.writeFile(sigmaScanPresetsPath, JSON.stringify(safePresets, null, 2));
    return true;
  });

  safeHandle("load-pi-analyst-profile", () => {
    try {
      const raw = JSON.parse(fs.readFileSync(piAnalystProfilePath, "utf-8"));
      return {
        version: 1,
        suppressions: Array.isArray(raw?.suppressions) ? raw.suppressions : [],
        baselines: Array.isArray(raw?.baselines) ? raw.baselines : [],
        updatedAt: raw?.updatedAt || null,
      };
    } catch {
      return { version: 1, suppressions: [], baselines: [], updatedAt: null };
    }
  });

  safeHandle("save-pi-analyst-profile", async (event, { profile }) => {
    const next = {
      version: 1,
      suppressions: Array.isArray(profile?.suppressions) ? profile.suppressions : [],
      baselines: Array.isArray(profile?.baselines) ? profile.baselines : [],
      updatedAt: new Date().toISOString(),
    };
    await fsp.writeFile(piAnalystProfilePath, JSON.stringify(next, null, 2));
    return next;
  });
};
