module.exports = function registerQueryHandlers(safeHandle, safeSend, { db, runAnalyzerJob, startAnalyzerJob }) {
  const analyze = (method, payload, fallback) => {
    if (runAnalyzerJob) return runAnalyzerJob(method, payload);
    return fallback();
  };

  safeHandle("query-rows", (event, { tabId, options }) => {
    return db.queryRows(tabId, options);
  });

  safeHandle("get-rows-by-ids", (event, { tabId, rowIds }) => {
    return db.getRowsByIds(tabId, rowIds);
  });

  safeHandle("get-bookmarked-ids", (event, { tabId }) => {
    return db.getBookmarkedIds(tabId);
  });

  safeHandle("get-column-stats", (event, { tabId, colName, options }) => {
    return db.getColumnStats(tabId, colName, options);
  });

  safeHandle("get-column-unique-values", (event, { tabId, colName, options }) => {
    return db.getColumnUniqueValues(tabId, colName, options);
  });

  safeHandle("get-column-values", (event, { tabId, colName, options }) => {
    return db.getColumnValues(tabId, colName, options);
  });

  safeHandle("get-empty-columns", (event, { tabId }) => {
    return db.getEmptyColumns(tabId);
  });

  safeHandle("get-group-values", (event, { tabId, groupCol, options }) => {
    return db.getGroupValues(tabId, groupCol, options);
  });

  safeHandle("get-tab-info", (event, { tabId }) => {
    return db.getTabInfo(tabId);
  });

  safeHandle("get-fts-status", (event, { tabId }) => {
    return db.getFtsStatus(tabId);
  });

  safeHandle("search-count", (event, { tabId, searchTerm, searchMode, searchCondition }) => {
    return db.searchCount(tabId, searchTerm, searchMode, searchCondition);
  });

  safeHandle("get-histogram-data", (event, { tabId, colName, options }) => {
    return db.getHistogramData(tabId, colName, options);
  });

  safeHandle("get-stacking-data", (event, { tabId, colName, options }) => {
    return db.getStackingData(tabId, colName, options);
  });

  safeHandle("get-gap-analysis", (event, { tabId, colName, gapThresholdMinutes, options }) => {
    return db.getGapAnalysis(tabId, colName, gapThresholdMinutes, options);
  });

  safeHandle("get-log-source-coverage", (event, { tabId, sourceCol, tsCol, options }) => {
    return db.getLogSourceCoverage(tabId, sourceCol, tsCol, options);
  });

  safeHandle("get-burst-analysis", (event, { tabId, colName, windowMinutes, thresholdMultiplier, options }) => {
    return db.getBurstAnalysis(tabId, colName, windowMinutes, thresholdMultiplier, options);
  });

  safeHandle("get-process-tree", (event, { tabId, options }) => {
    return analyze("getProcessTree", { tabId, options }, () => db.getProcessTree(tabId, options));
  });

  safeHandle("start-process-tree", (event, { tabId, options }) => {
    if (!startAnalyzerJob) {
      return { result: db.getProcessTree(tabId, options) };
    }

    const { jobId, promise } = startAnalyzerJob("getProcessTree", { tabId, options }, {
      metadata: { feature: "processTree" },
    });
    promise
      .then((result) => safeSend("process-tree-complete", { jobId, result }))
      .catch((err) => safeSend("process-tree-complete", {
        jobId,
        error: err?.message || "Process tree analysis failed",
        cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
      }));
    return { jobId };
  });

  safeHandle("preview-process-tree", (event, { tabId, options }) => {
    return analyze("previewProcessTree", { tabId, options }, () => db.previewProcessTree(tabId, options));
  });

  safeHandle("get-process-inspector-context", (event, { tabId, options }) => {
    return analyze("getProcessInspectorContext", { tabId, options }, () => db.getProcessInspectorContext(tabId, options));
  });

  safeHandle("preview-lateral-movement", (event, { tabId, options }) => {
    return analyze("previewLateralMovement", { tabId, options }, () => db.previewLateralMovement(tabId, options));
  });

  safeHandle("detect-kape-collection-host", (event, { tabId }) => {
    return analyze("detectKapeCollectionHost", { tabId }, () => db.detectKapeCollectionHost(tabId));
  });

  safeHandle("get-lateral-movement", (event, { tabId, options }) => {
    return analyze("getLateralMovement", { tabId, options }, () => db.getLateralMovement(tabId, options));
  });

  safeHandle("get-multi-source-lateral-movement", (event, { tabIds, options }) => {
    return analyze("getMultiSourceLateralMovement", { tabIds, options }, () => db.getMultiSourceLateralMovement(tabIds, options));
  });

  safeHandle("preview-multi-source-lateral-movement", (event, { tabIds, options }) => {
    return analyze("previewMultiSourceLateralMovement", { tabIds, options }, () => db.previewMultiSourceLateralMovement(tabIds, options));
  });

  safeHandle("lateral-movement-load-triage", (event, { scope } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.loadLateralMovementTriage(scope || {});
  });

  safeHandle("lateral-movement-save-triage", (event, { scope, triageState } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.saveLateralMovementTriage(scope || {}, triageState || {});
  });

  safeHandle("lateral-movement-clear-triage", (event, { scope } = {}) => {
    const store = require("../analyzers/lateral-movement/triage-store");
    return store.clearLateralMovementTriage(scope || {});
  });

  safeHandle("preview-persistence-analysis", (event, { tabId, options }) => {
    return analyze("previewPersistenceAnalysis", { tabId, options }, () => db.previewPersistenceAnalysis(tabId, options));
  });

  safeHandle("get-persistence-analysis", (event, { tabId, options }) => {
    return analyze("getPersistenceAnalysis", { tabId, options }, () => db.getPersistenceAnalysis(tabId, options));
  });

};
