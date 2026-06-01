/**
 * analyzers/index.js — Registry of extracted analysis modules
 *
 * Each analyzer is a standalone function that receives the tab's
 * database metadata (`meta`) instead of a `tabId` + class instance.
 * The TimelineDB class delegates to these via thin wrapper methods.
 */

const { detectTimestomping } = require("./timestomping");
const { analyzeADS } = require("./ads");
const { getFileActivityHeatmap } = require("./file-activity");
const { scanRansomwareExtensions, analyzeRansomware } = require("./ransomware");
const { analyzeUsnJournal, resolveUsnPaths } = require("./usn-journal");
const rdpBitmapCache = require("./rdp-bitmap-cache");

module.exports = {
  detectTimestomping,
  analyzeADS,
  getFileActivityHeatmap,
  scanRansomwareExtensions,
  analyzeRansomware,
  analyzeUsnJournal,
  resolveUsnPaths,
  rdpBitmapCache,
};
