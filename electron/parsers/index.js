/**
 * parsers/index.js — Unified parser dispatcher for IRFlow Timeline
 *
 * Auto-detects file type and delegates to the appropriate format-specific parser.
 * Re-exports all public symbols so consumers can `require("./parsers")`.
 */

const path = require("path");

const { parseCSVLine, parseCSVStream, detectDelimiter } = require("./csv");
const { parseXLSXStream, parseXLSFile, getXLSXSheets } = require("./xlsx");
const { validatePlasoFile, parsePlasoFile } = require("./plaso");
const { parseEvtxFile } = require("./evtx");
const { isMftFile, parseMftFile, extractResidentData } = require("./mft");
const { isUsnJrnlFile, parseUsnJrnlFile } = require("./usn");

/**
 * Auto-detect file type and parse accordingly
 */
async function parseFile(filePath, tabId, db, onProgress, sheetName, fileSize) {
  // Pass fileSize hint to db.createTab for pragma scaling on large files
  if (fileSize) db._fileSizeHint = fileSize;
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".xls") {
    return parseXLSFile(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".xlsx" || ext === ".xlsm") {
    return parseXLSXStream(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".evtx") {
    return parseEvtxFile(filePath, tabId, db, onProgress);
  }
  if (ext === ".plaso" || ext === ".timeline") {
    const check = validatePlasoFile(filePath);
    if (ext === ".plaso" && !check.valid) throw new Error("Not a valid Plaso database (missing metadata table or format_version)");
    // .timeline files: if valid Plaso SQLite, parse as Plaso; otherwise fall through to CSV
    if (check.valid) return parsePlasoFile(filePath, tabId, db, onProgress);
    if (ext === ".timeline") { /* not Plaso — fall through to CSV below */ }
  }
  if (ext === ".mft") {
    return parseMftFile(filePath, tabId, db, onProgress);
  }
  // Auto-detect raw forensic files by name/magic bytes
  const baseName = path.basename(filePath).toUpperCase();
  if (!ext || baseName.includes("MFT") || baseName.includes("USNJRNL") || baseName === "$J") {
    // Check $J (USN Journal) first — filename-based detection
    if (isUsnJrnlFile(filePath)) {
      return parseUsnJrnlFile(filePath, tabId, db, onProgress);
    }
    // Check $MFT — magic byte detection
    if (isMftFile(filePath)) {
      return parseMftFile(filePath, tabId, db, onProgress);
    }
  }
  // Default to CSV parsing (handles .csv, .tsv, .txt, .log, etc.)
  return parseCSVStream(filePath, tabId, db, onProgress);
}

module.exports = {
  parseCSVStream,
  parseXLSXStream,
  parseXLSFile,
  parsePlasoFile,
  parseEvtxFile,
  parseMftFile,
  isMftFile,
  extractResidentData,
  parseUsnJrnlFile,
  isUsnJrnlFile,
  validatePlasoFile,
  getXLSXSheets,
  parseFile,
  parseCSVLine,
  detectDelimiter,
};
