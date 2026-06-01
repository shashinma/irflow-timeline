const { parentPort, workerData } = require("worker_threads");

if (workerData?.userDataPath) {
  process.env.TLE_USER_DATA_PATH = workerData.userDataPath;
}

const TimelineDB = require("../db");
const { scanSigmaRules } = require("../analyzers/sigma");
const { createTempResultPath } = require("../analyzers/sigma/result-store");

let cancelled = false;

parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, ...payload } });
}

function assertNotCancelled() {
  if (cancelled) throw Object.assign(new Error("Job cancelled"), { cancelled: true });
}

(async () => {
  const { tabId, descriptor, options = {} } = workerData;
  const db = new TimelineDB();
  try {
    if (!descriptor?.dbPath) throw new Error("Tab database descriptor missing");
    db.adoptTabFromFile(tabId, descriptor);
    const meta = db.databases.get(tabId);
    if (!meta) throw new Error("Tab not found in worker");

    const resultStorePath = options.resultStorePath || createTempResultPath();
    progress({ phase: "compiling", progress: 0, tabId, text: "Loading and compiling Sigma rules..." });
    assertNotCancelled();

    const result = await scanSigmaRules(meta, {
      ...options,
      resultStorePath,
      previewLimit: options.previewLimit || 2000,
      isCancelled: () => cancelled,
    }, (p) => {
      if (cancelled) return;
      progress({ tabId, ...p });
    });

    assertNotCancelled();
    db.releaseTab(tabId);
    db.closeAll();
    parentPort.postMessage({ type: "result", result });
  } catch (err) {
    try { db.releaseTab(tabId); } catch {}
    try { db.closeAll(); } catch {}
    if (err?.cancelled) {
      process.exit(1);
      return;
    }
    parentPort.postMessage({
      type: "result",
      result: { matches: [], eventRows: [], stats: {}, errors: [err?.message || "Sigma scan failed"] },
    });
  }
})();
