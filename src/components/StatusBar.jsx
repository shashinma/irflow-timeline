import useUIStore from "../store/useUIStore.js";
import { formatNumber } from "../utils/format.js";
import { Tooltip } from "./primitives/index.js";

/**
 * StatusBar — bottom bar showing file path, row counts, filter summary, etc.
 *
 * Props:
 *   th                  – theme object
 *   ct                  – current tab object
 *   isGrouped           – whether grouping is active
 *   selectedRows        – Set of selected row indices
 *   lastClickedRow      – last clicked row index
 *   copiedMsg           – boolean, true when "Copied!" should flash
 *   setCopiedMsg        – setter for copiedMsg
 *   pinnedH             – array of pinned header names
 *   allVisH             – array of all visible header names
 *   searchLoading       – boolean, search in progress
 *   activeCheckboxCount – number of active checkbox filters
 *   totalActiveFilters  – total active filter count
 *   clearAllFilters     – function to clear all filters
 *   up                  – function to update current tab field
 */
export default function StatusBar({
  th,
  ct,
  isGrouped,
  selectedRows,
  lastClickedRow,
  copiedMsg,
  setCopiedMsg,
  pinnedH,
  allVisH,
  searchLoading,
  searchElapsed = 0,
  activeCheckboxCount,
  totalActiveFilters,
  clearAllFilters,
  up,
}) {
  const setModal = useUIStore((s) => s.setModal);
  const timezone = useUIStore((s) => s.timezone);

  if (!ct || !ct.dataReady) return null;

  const Sdiv = () => <span style={{ width: 1, height: 12, background: th.border, display: "inline-block" }} />;

  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "3px 12px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderTop: `1px solid ${th.glassBorder}`, fontSize: 11, color: th.textDim, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Tooltip content={ct.filePath ? `Double-click to copy: ${ct.filePath}` : ct.name}>
          <span style={{ color: th.accent, fontWeight: 500, cursor: "pointer", maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "inline-block", verticalAlign: "middle" }}
            onDoubleClick={() => { if (ct.filePath) { navigator.clipboard?.writeText?.(ct.filePath); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); } }}>
            {ct.filePath || ct.name}
          </span>
        </Tooltip>
        <Sdiv />
        <Tooltip content="Active timezone for timestamp display"><span>TZ: <b style={{ color: timezone === "UTC" ? th.textDim : th.warning }}>{timezone}</b></span></Tooltip>
        <Sdiv /><span>Total: <b>{formatNumber(ct.totalRows)}</b></span>
        {!isGrouped && <><Sdiv /><span>Filtered: <b style={{ color: ct.totalFiltered < ct.totalRows ? th.warning : th.success, opacity: searchLoading ? 0.5 : 1, transition: "opacity var(--m-base)" }}>{formatNumber(ct.totalFiltered)}</b>{searchLoading && <span style={{ color: th.accent, marginLeft: 3, fontFamily: "'SF Mono',Menlo,monospace" }}>{searchElapsed >= 2 ? ` searching ${formatNumber(ct.totalRows)} rows… ${searchElapsed}s` : "..."}</span>}</span></>}
        {!isGrouped && <><Sdiv /><span>Showing: <b>{formatNumber(ct.totalFiltered)}</b></span></>}
        {isGrouped && <><Sdiv /><span>Groups: <b style={{ color: th.accent }}>{ct.groupData?.length || 0}</b></span></>}
        {ct.bookmarkedSet?.size > 0 && <><Sdiv /><span>Flagged: <b style={{ color: th.warning }}>{ct.bookmarkedSet.size}</b></span></>}
        {ct.sortCol && ct.sortCol !== "__tags__" && <><Sdiv /><span>Sort: {ct.sortCol} {ct.sortDir === "asc" ? "↑" : "↓"}</span></>}
        {selectedRows.size > 0 && <><Sdiv /><span>{selectedRows.size === 1 ? `Row: ${(lastClickedRow ?? 0) + 1}` : `${selectedRows.size} rows selected`}</span></>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {copiedMsg && <span style={{ color: th.success }}>Copied!</span>}
        {pinnedH.length > 0 && <span>📌 {pinnedH.length}</span>}
        <span>{allVisH.length}/{ct.headers.length} cols</span>
        {ct.colorRules.length > 0 && <span>{ct.colorRules.length} color rule{ct.colorRules.length > 1 ? "s" : ""}</span>}
        {activeCheckboxCount > 0 && <span style={{ color: th.borderAccent }}>{activeCheckboxCount} value filter{activeCheckboxCount > 1 ? "s" : ""}</span>}
        {ct.tagFilter && <span style={{ color: th.danger }}>Tag filter ({Array.isArray(ct.tagFilter) ? ct.tagFilter.length : 1})</span>}
        {Array.isArray(ct.rowIdFilter) && ct.rowIdFilter.length > 0 && (
          <span
            onClick={() => { up("rowIdFilter", null); up("rowIdFilterLabel", null); }}
            style={{ color: th.accent, cursor: "pointer" }}
            title={ct.rowIdFilterLabel ? `Exact matched rows for: ${ct.rowIdFilterLabel}. Click to clear.` : "Exact matched rows. Click to clear."}
          >
            Matched rows ({formatNumber(ct.rowIdFilter.length)}) x
          </span>
        )}
        {Object.keys(ct.dateRangeFilters || {}).length > 0 && <span style={{ color: th.warning }}>{Object.keys(ct.dateRangeFilters).length} date filter{Object.keys(ct.dateRangeFilters).length > 1 ? "s" : ""}</span>}
        {(ct.advancedFilters?.length > 0) && <span style={{ color: th.accent }}>{ct.advancedFilters.length} advanced filter{ct.advancedFilters.length > 1 ? "s" : ""}</span>}
        {ct.searchHighlight && ct.searchTerm && <span style={{ color: th.warning }}>Highlight mode</span>}
        {ct.iocHighlights?.length > 0 && (
          <Tooltip content="IOC matches are highlighted — click to clear">
            <span onClick={() => up("iocHighlights", null)} style={{ color: th.warning, cursor: "pointer" }}>IOC Highlights ({ct.iocHighlights.length}) ✕</span>
          </Tooltip>
        )}
        {ct._detectedProfile && <span style={{ color: th.success }}>{ct._detectedProfile}</span>}
        {totalActiveFilters > 0 && (
          <Tooltip content={`Clear all ${totalActiveFilters} active filter${totalActiveFilters > 1 ? "s" : ""}`}>
            <span onClick={clearAllFilters} style={{ cursor: "pointer", color: th.danger, fontWeight: 600, textDecoration: "underline", textDecorationStyle: "dotted" }}>Clear All ({totalActiveFilters})</span>
          </Tooltip>
        )}
        <span onClick={() => { if (ct?.dataReady) setModal({ type: "editFilter" }); }} style={{ cursor: ct?.dataReady ? "pointer" : "default", color: ct?.advancedFilters?.length > 0 ? th.accent : th.textMuted, textDecoration: ct?.dataReady ? "underline" : "none" }}>Edit Filter</span>
        <span style={{ color: th.textMuted }}>SQLite-backed</span>
      </div>
    </div>
  );
}
