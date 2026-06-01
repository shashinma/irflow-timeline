import { useState, useRef, useEffect, useCallback } from "react";
import useUIStore from "../../../store/useUIStore.js";
import useTabStore from "../../../store/useTabStore.js";
import useCurrentTab from "../../../hooks/useCurrentTab.js";
import useTheme from "../../../hooks/useTheme.js";
import { _integrityShort, _providerShort, _ptFormatDuration, PI_ALL_RULES, PI_TECHNIQUE_GROUPS, piSevColorsFor } from "../../../utils/process-inspector.js";
import { analyzeCommandLine, tokenizeCommandLine } from "../../../utils/cmdline-decode.js";
import {
  buildByKeyMap,
  buildChildMap,
  buildDetectionMap,
  buildPrevalenceSummary,
  buildSequenceMap,
  buildChainClusters,
  buildNodeClusterMap,
  buildIncidentStories,
  buildNodeStoryMap,
  consistentParentKey,
  makeDetMapRuleKey,
  customRuleErrors,
  validateCustomRulePattern,
} from "../../../utils/process-inspector-pipeline.js";
import { normalizeTimestamp, normalizeHost } from "../../../utils/forensic-normalize.js";
import { susColorsFor, intColorFor } from "../../../constants/presets.js";
import { PT_ICON_STYLE, PT_VIEW_MODES } from "../constants.js";
import { DraggableResizableModal } from "../../primitives/index.js";
import useModalChrome from "../../../hooks/useModalChrome.js";
import { useProcessAnalyzerContext } from "../ProcessAnalyzerContext.js";

export default function ProcessTreeModal() {
  const {
    piAnalystProfile,
    setPiAnalystProfile,
    activeFilters,
    openPiSourceEvent,
    makePiAnalystEntry,
    upsertPiAnalystEntry,
    removePiAnalystEntry,
  } = useProcessAnalyzerContext();
  const modal = useUIStore(s => s.modal);
  const setModal = useUIStore(s => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  // Theme-aware severity palettes — shadow the static names so existing call-sites
  // (SUS_COLORS[x], INT_COLOR[x], PI_SEV_COLORS[x]) keep working without per-line edits.
  const SUS_COLORS = susColorsFor(th);
  const INT_COLOR = intColorFor(th);
  const PI_SEV_COLORS = piSevColorsFor(th);
  const tle = typeof window !== "undefined" ? window.tle : null;
  const updateActiveTab = useTabStore(s => s.updateActiveTab);

  // Local refs — only used by this modal
  const ptCacheRef = useRef({ flatNodes: [], byKeyMap: new Map(), deps: null });
  const ptScrollRef = useRef(null);
  const ptHeaderRef = useRef(null);
  const ptRafRef = useRef(null);
  const ptResizingRef = useRef(false);
  const ptPreviewTimerRef = useRef(null);
  // Holds the latest render values the keyboard handler needs, so the window
  // listener (attached once) never reads a stale closure. Updated each render below.
  const ptNavRef = useRef(null);
  const [ptScroll, setPtScroll] = useState({ top: 0, h: 600 });

  // Modal styles (replicated from parent ms object)
  const ms = useModalChrome();

  // Export helpers (replicated from parent)
  const _downloadFile = (content, filename, mime) => {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const _toCSV = (rows) => {
    if (!rows.length) return "";
    const keys = Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    return [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n");
  };

  // Shorthand for tab updates
  const up = (key, value) => updateActiveTab({ [key]: value });

  const refreshPtPreview = useCallback((colOverrides) => {
    if (!tle?.previewProcessTree || !ct) {
      setModal(p => p?.type === "processTree" ? { ...p, ptPreviewLoading: false } : p);
      return;
    }

    if (ptPreviewTimerRef.current) clearTimeout(ptPreviewTimerRef.current);
    ptPreviewTimerRef.current = setTimeout(() => {
      setModal(p => {
        if (!p || p.type !== "processTree") return p;
        const c = colOverrides || p.columns || {};
        const af = activeFilters(ct);
        const seq = (p._ptPreviewSeq || 0) + 1;
        tle.previewProcessTree(ct.id, {
          pidCol: c.pid, ppidCol: c.ppid, guidCol: c.guid, parentGuidCol: c.parentGuid,
          imageCol: c.image, cmdLineCol: c.cmdLine, userCol: c.user,
          tsCol: c.ts, eventIdCol: c.eventId, providerCol: c.provider,
          eventIdValue: p.eventIdValue == null ? "1,4688" : p.eventIdValue,
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode,
          searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly,
          dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        }).then(prev => {
          setModal(q => q?.type === "processTree" && (q._ptPreviewSeq || 0) === seq ? { ...q, ptPreview: prev, ptPreviewLoading: false } : q);
        }).catch(() => {
          setModal(q => q?.type === "processTree" && (q._ptPreviewSeq || 0) === seq ? { ...q, ptPreviewLoading: false } : q);
        });
        return { ...p, ptPreviewLoading: true, _ptPreviewSeq: seq };
      });
    }, 600);
  }, [activeFilters, ct, setModal, tle]);

  useEffect(() => () => {
    if (ptPreviewTimerRef.current) clearTimeout(ptPreviewTimerRef.current);
  }, []);

  useEffect(() => {
    if (!modal || modal.type !== "processTree" || !modal._ptNeedsPreview) return;
    setModal(p => p?.type === "processTree" ? { ...p, _ptNeedsPreview: false } : p);
    refreshPtPreview();
  }, [modal?._ptNeedsPreview, modal?.type, refreshPtPreview, setModal]);

  // Keyboard navigation over the process list/tree. Attached once while the modal is
  // open; the handler reads ptNavRef.current (refreshed each render) to avoid stale state.
  useEffect(() => {
    if (modal?.type !== "processTree" || modal?.phase !== "results") return;
    const onKey = (e) => {
      const nav = ptNavRef.current;
      if (!nav || !nav.flatNodes.length) return;
      const tag = (e.target && e.target.tagName) || "";
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag) || e.target?.isContentEditable) return; // don't hijack typing
      const { flatNodes, selectedKey, expandedNodes, byKeyMap, childMap, setModal: sm, ptScrollRef: sr } = nav;
      const idx = flatNodes.findIndex((n) => n.key === selectedKey);
      const PT_ROW_H = nav.rowH || 34;
      const ensureVisible = (i) => {
        const el = sr.current; if (!el) return;
        const top = i * PT_ROW_H, bot = top + PT_ROW_H;
        if (top < el.scrollTop) el.scrollTop = top;
        else if (bot > el.scrollTop + el.clientHeight) el.scrollTop = bot - el.clientHeight;
      };
      const select = (i) => { sm((p) => p ? { ...p, selectedKey: flatNodes[i].key } : p); ensureVisible(i); };
      if (e.key === "ArrowDown") { e.preventDefault(); select(idx < 0 ? 0 : Math.min(flatNodes.length - 1, idx + 1)); }
      else if (e.key === "ArrowUp") { e.preventDefault(); select(idx < 0 ? flatNodes.length - 1 : Math.max(0, idx - 1)); }
      else if (idx >= 0) {
        const node = flatNodes[idx];
        const hasKids = (childMap.get(node.key) || []).length > 0;
        if (e.key === "Enter" && hasKids) { e.preventDefault(); sm((p) => { const en = { ...p.expandedNodes }; if (en[node.key]) delete en[node.key]; else en[node.key] = true; return { ...p, expandedNodes: en }; }); }
        else if (e.key === "ArrowRight" && hasKids && !expandedNodes[node.key]) { e.preventDefault(); sm((p) => ({ ...p, expandedNodes: { ...p.expandedNodes, [node.key]: true } })); }
        else if (e.key === "ArrowLeft") {
          if (hasKids && expandedNodes[node.key]) { e.preventDefault(); sm((p) => { const en = { ...p.expandedNodes }; delete en[node.key]; return { ...p, expandedNodes: en }; }); }
          else if (node.parentKey && byKeyMap.has(node.parentKey)) {
            // Only jump to the parent if it is actually a visible row — in flat mode
            // (search/severity/susOnly) the parent isn't in flatNodes, so this is a no-op
            // rather than selecting an off-screen node and breaking Up/Down continuity.
            const pIdx = flatNodes.findIndex((n) => n.key === node.parentKey);
            if (pIdx >= 0) { e.preventDefault(); select(pIdx); }
          }
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [modal?.type, modal?.phase, setModal]);

  if (!modal || modal.type !== "processTree" || !ct) return null;

const { phase, columns: cols, eventIdValue, data, expandedNodes, searchText } = modal;
const hasCols = (cols.pid && cols.ppid) || (cols.guid && cols.parentGuid);

// Process type icons — inline 14x14 SVGs (uses hoisted PT_ICON_STYLE)
const ptIcon = (name) => {
  const n = (name || "").toLowerCase();
  if (/^explorer/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M2 3h12v2H2zm0 3h12v7H2z" fill={th.accent + "66"} stroke={th.accent} strokeWidth="1"/></svg>;
  if (/^(winword|excel|powerpnt|outlook|onenote|msaccess|acrobat|acrord32)/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M4 1h5l4 4v10H4z" fill={th.textDim} fillOpacity=".2" stroke={th.textDim} strokeWidth="1"/><path d="M9 1v4h4" stroke={th.textDim} strokeWidth="1"/></svg>;
  if (/^(cmd|powershell|pwsh|bash|sh|conhost)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><rect x="1" y="2" width="14" height="12" rx="2" fill={th.text + "11"} stroke={th.textDim} strokeWidth="1"/><path d="M4 6l3 2.5L4 11" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><line x1="9" y1="11" x2="12" y2="11" stroke={th.textDim} strokeWidth="1.5" strokeLinecap="round"/></svg>;
  if (/^(svchost|services|lsass|csrss|smss|wininit|winlogon|spoolsv|lsm)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5" fill={th.textDim + "22"} stroke={th.textDim} strokeWidth="1"/><circle cx="8" cy="8" r="1.5" fill={th.textDim}/><path d="M8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M3.8 12.2l1.4-1.4M10.8 5.2l1.4-1.4" stroke={th.textDim} strokeWidth="1"/></svg>;
  if (/^(chrome|firefox|msedge|iexplore|opera|brave|safari)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill={th.textDim + "22"} stroke={th.textDim} strokeWidth="1"/><ellipse cx="8" cy="8" rx="2.5" ry="6" stroke={th.textDim} strokeWidth=".7"/><line x1="2" y1="6" x2="14" y2="6" stroke={th.textDim} strokeWidth=".7"/><line x1="2" y1="10" x2="14" y2="10" stroke={th.textDim} strokeWidth=".7"/></svg>;
  return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill={th.textDim + "33"} stroke={th.textDim} strokeWidth="1"/></svg>;
};

// Clickable MITRE ATT&CK technique badge. Opens the technique page in the system browser
// (T1003.001 -> attack.mitre.org/techniques/T1003/001/). Reused across both detail panels
// and the story/cluster cards so every technique ID in the modal is a live pivot.
const ptMitreBadge = (tid, key) => (
  <span
    key={key ?? tid}
    onClick={(e) => { e.stopPropagation(); window.tle?.openExternal?.(`https://attack.mitre.org/techniques/${String(tid).replace(".", "/")}/`); }}
    title={`Open ${tid} on attack.mitre.org`}
    style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}18`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${th.accent}33`, cursor: "pointer", fontWeight: 600, letterSpacing: "0.02em", transition: "all var(--m-base)" }}
    onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}30`; e.currentTarget.style.textDecoration = "underline"; }}
    onMouseLeave={(e) => { e.currentTarget.style.background = `${th.accent}18`; e.currentTarget.style.textDecoration = "none"; }}
  >{tid}</span>
);

// Pull the strongest file hash (SHA256 > SHA1 > MD5) out of a Sysmon/EvtxECmd Hashes
// field (e.g. "SHA1=...,MD5=...,SHA256=...,IMPHASH=...") for a VirusTotal pivot.
// Labeled keys are matched first so we never pivot on IMPHASH (an import hash, not a
// file hash, but also 32 hex). Falls back to length for an unlabeled single hash.
const ptExtractHash = (s) => {
  if (!s || typeof s !== "string") return null;
  for (const re of [/SHA256=([a-fA-F0-9]{64})/i, /SHA1=([a-fA-F0-9]{40})/i, /MD5=([a-fA-F0-9]{32})/i]) {
    const m = s.match(re);
    if (m) return m[1];
  }
  // A labeled field with only IMPHASH (also 32 hex) has no usable file hash — never pivot on it.
  if (/IMPHASH=/i.test(s)) return null;
  return (s.match(/\b[a-fA-F0-9]{64}\b/) || s.match(/\b[a-fA-F0-9]{40}\b/) || s.match(/\b[a-fA-F0-9]{32}\b/) || [null])[0];
};

// Inline command-line token highlighting (urls/ips/flags/paths/base64) for the
// detail-panel Command Line field — makes the interesting parts pop without leaving the row.
const _ptTokColor = { url: th.textDim, ip: th.sev.high, flag: th.accent, path: th.sev.med, base64: th.textDim };
const ptHighlightCmd = (cmd) => {
  if (!cmd) return "—";
  return tokenizeCommandLine(cmd).map((s, i) => {
    const col = _ptTokColor[s.type];
    return col ? <span key={i} style={{ color: col, fontWeight: s.type === "url" || s.type === "ip" ? 600 : 400 }}>{s.text}</span> : <span key={i}>{s.text}</span>;
  });
};

// "Decoded Command" panel: surfaces base64 / -EncodedCommand payloads (incl. nested
// layers and gzip flags) so the analyst sees the real intent without an external decoder.
const ptDecodePanel = (cmd, gLbl) => {
  const { decodings } = analyzeCommandLine(cmd);
  if (!decodings.length) return null;
  return (
    <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.high + "10", borderRadius: 6, border: `1px solid ${th.sev.high}2a` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <span style={{ ...gLbl, color: th.sev.high, paddingTop: 0 }}>Decoded Command</span>
        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.high + "1a", color: th.sev.high, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600 }}>{decodings.length} layer{decodings.length !== 1 ? "s" : ""}</span>
      </div>
      {decodings.map((d, i) => (
        <div key={i} style={{ marginBottom: i < decodings.length - 1 ? 8 : 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, flexWrap: "wrap" }}>
            <span style={{ fontSize: 9, color: th.textDim, fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>{d.source}</span>
            <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: th.textMuted + "18", color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>{d.encoding}</span>
            {d.decoded && <span onClick={() => navigator.clipboard?.writeText?.(d.decoded)} title="Copy decoded text" style={{ fontSize: 8, padding: "0px 5px", borderRadius: 2, background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer" }}>copy</span>}
          </div>
          {d.decoded
            ? <pre style={{ margin: 0, fontSize: 10.5, fontFamily: "'SF Mono', Menlo, monospace", color: th.danger, background: `${th.accent}08`, padding: "6px 8px", borderRadius: 4, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 220, overflow: "auto", lineHeight: 1.5 }}>{ptHighlightCmd(d.decoded)}{d.truncated ? `\n\n… ${d.truncated - d.decoded.length} more chars truncated` : ""}</pre>
            : <div style={{ fontSize: 10, color: th.textMuted, fontStyle: "italic", fontFamily: "-apple-system, sans-serif" }}>{d.note || "Could not decode to readable text."}</div>}
        </div>
      ))}
    </div>
  );
};

// Process tree column configuration
	const ptHeaders = ["Timestamp", "Detection", "Prevalence", "Parent Process", "Process", "Command Line", "PID", "PPID", "User", "Provider", "Event ID", "Integrity"];
	const ptDefWidths = { Timestamp: 195, Provider: 100, "Event ID": 65, "Parent Process": 170, Process: 280, Detection: 290, Prevalence: 150, PID: 75, PPID: 75, User: 150, "Command Line": 300, Integrity: 80 };
const ptColWidths = modal.ptColWidths || ptDefWidths;
const ptSortCol = modal.ptSortCol || "Timestamp";
const ptSortDir = modal.ptSortDir || "asc";
const ptColFilters = modal.ptColFilters || {};
// Pre-compute detection results for all processes. The pure pipeline lives in
// src/utils/process-inspector-pipeline.js — this wrapper just memoizes the
// result on the cache ref so we don't recompute across renders that didn't
// change the inputs.
const _ptDetMap = (() => {
  const c = ptCacheRef.current;
  const disabledRules = modal.ptDisabledRules || null;
  const customRules = modal.ptCustomRules || null;
  const ruleKey = makeDetMapRuleKey(disabledRules, customRules, piAnalystProfile);
  if (c.detMapData === data && c.detMapRuleKey === ruleKey) return c.detMap;
  const m = buildDetectionMap(data, { disabledRules, customRules, analystProfile: piAnalystProfile });
  c.detMap = m; c.detMapData = data; c.detMapRuleKey = ruleKey;
  return m;
})();

const _ptPrevalenceSummary = (() => {
  const c = ptCacheRef.current;
  if (c.prevSummaryData === data && c.prevSummaryDetMap === _ptDetMap) return c.prevSummary;
  const summary = buildPrevalenceSummary(data, _ptDetMap, 10);
  c.prevSummary = summary;
  c.prevSummaryData = data;
  c.prevSummaryDetMap = _ptDetMap;
  return summary;
})();

// Dataset severity tally for the raw-view overview strip. Cached on data + detMap
// so it isn't recomputed on every selection click (one O(n) pass otherwise).
const _ptSevCounts = (() => {
  const c = ptCacheRef.current;
  if (c.sevCountsData === data && c.sevCountsDetMap === _ptDetMap) return c.sevCounts;
  let crit = 0, high = 0, med = 0, susTotal = 0;
  const hosts = new Set(), users = new Set();
  for (const p of (data?.processes || [])) {
    const lv = (_ptDetMap.get(p.key) || { level: 0 }).level;
    if (lv >= 3) crit++; else if (lv === 2) high++; else if (lv === 1) med++;
    if (lv > 0) susTotal++;
    if (p.hostname) hosts.add(p.hostname);
    if (p.user) users.add(p.user);
  }
  const result = { total: (data?.processes || []).length, crit, high, med, susTotal, hosts: hosts.size, users: users.size };
  c.sevCounts = result; c.sevCountsData = data; c.sevCountsDetMap = _ptDetMap;
  return result;
})();

// Short-window behavioral sequence detection (second pass over _ptDetMap).
// Sequence definitions and the windowing logic now live in the pipeline module
// — this is just the cache wrapper.
const _ptSeqMap = (() => {
  const c = ptCacheRef.current;
  if (c.seqDetMap === _ptDetMap) return c.seqMap;
  const seqMap = buildSequenceMap(data, _ptDetMap);
  c.seqMap = seqMap; c.seqDetMap = _ptDetMap;
  return seqMap;
})();

// Chain cluster computation (memoized on _ptDetMap reference). All cluster
// logic — gap windows, dominant parent/child, sequence-rank annotation —
// lives in the pipeline module.
const _ptChainClusters = (() => {
  const c = ptCacheRef.current;
  if (c.clusterDetMap === _ptDetMap) return c.chainClusters;
  const allClusters = buildChainClusters(data, _ptDetMap, _ptSeqMap);
  c.chainClusters = allClusters; c.clusterDetMap = _ptDetMap;
  return allClusters;
})();
// Reverse lookup: processKey -> cluster — uses allKeys (uncapped) for full coverage
const _ptNodeClusterMap = (() => {
  const c = ptCacheRef.current;
  if (c.nodeClusterDetMap === _ptDetMap) return c.nodeClusterMap;
  const m = buildNodeClusterMap(_ptChainClusters);
  c.nodeClusterMap = m; c.nodeClusterDetMap = _ptDetMap;
  return m;
})();
const ptCellVal = (node, col) => {
  // Parent Process falls back to the relinked parent node when the row carries
  // no parent image — keeps sort/filter consistent with the column display.
  if (col === "Parent Process") return node.parentProcessName || byKeyMap.get(node.parentKey)?.processName || "";
  if (col === "Process") return node.processName || "";
  if (col === "PID") return node.pid || "";
  if (col === "PPID") return node.ppid || "";
  if (col === "User") return node.user || "";
  if (col === "Timestamp") return node.ts || "";
  if (col === "Command Line") return node.cmdLine || "";
  if (col === "Provider") return node.provider || "";
	  if (col === "Event ID") return node.eventId || "";
	  if (col === "Integrity") return _integrityShort(node.integrity);
	  if (col === "Detection") return (_ptDetMap.get(node.key) || {}).reason || "";
	  if (col === "Prevalence") return (_ptDetMap.get(node.key) || {}).prevalence?.rarity || "";
	  return "";
	};
	const ptLinkMeta = (node) => {
	  const link = node?.link || {
	    source: node?.linkSource || "",
	    confidence: node?.linkConfidence || "",
	    reason: node?.linkReason || "",
	    warnings: node?.linkWarnings || [],
	  };
	  const source = link.source || "";
	  const confidence = link.confidence || "";
	  const labelMap = {
	    guid: "GUID",
	    "pid-logon": "PID+Logon",
	    "pid-session": "PID+Session",
	    "pid-host": "PID Host",
	    resolved: "Resolved",
	    unresolved: "Unresolved",
	    root: "Root",
	  };
	  const colorMap = {
	    high: th.success,
	    medium: th.sev.med,
	    low: th.sev.high,
	    none: th.textMuted,
	  };
	  const warnings = Array.isArray(link.warnings) ? link.warnings : [];
	  const title = [
	    link.reason || "",
	    confidence ? `confidence: ${confidence}` : "",
	    link.parentRowId ? `parent row: ${link.parentRowId}` : "",
	    link.childRowId ? `child row: ${link.childRowId}` : "",
	    Number.isFinite(link.timeDeltaMs) ? `delta: ${Math.round(link.timeDeltaMs / 1000)}s` : "",
	    warnings.length ? `warnings: ${warnings.join(", ")}` : "",
	  ].filter(Boolean).join("\n");
	  return {
	    link,
	    source,
	    confidence,
	    label: labelMap[source] || source || "Unknown",
	    color: colorMap[confidence] || th.textMuted,
	    title,
	    warnings,
	  };
	};
	const ptSortKey = (node, col) => {
	  if (col === "PID") return parseInt(node.pid) || 0;
	  if (col === "PPID") return parseInt(node.ppid) || 0;
	  if (col === "Event ID") return parseInt(node.eventId) || 0;
	  if (col === "Detection") return (_ptDetMap.get(node.key) || {}).level || 0;
	  if (col === "Prevalence") {
	    const prev = (_ptDetMap.get(node.key) || {}).prevalence || null;
	    const rank = prev?.rarity === "rare" ? 2 : prev?.rarity === "uncommon" ? 1 : 0;
	    return rank * 1000 + (prev?.scoreBoost || 0);
	  }
	  return ptCellVal(node, col);
	};
const togglePtSort = (col) => {
  if (ptResizingRef.current) return;  // skip sort if column was just resized
  setModal((p) => {
    if ((p.ptSortCol || "Timestamp") === col) return { ...p, ptSortDir: (p.ptSortDir || "asc") === "asc" ? "desc" : "asc" };
    // Detection and Prevalence default to descending so high-signal rows float first.
    return { ...p, ptSortCol: col, ptSortDir: (col === "Detection" || col === "Prevalence") ? "desc" : "asc" };
  });
};
const onPtResizeStart = (colName, e) => {
  e.preventDefault(); e.stopPropagation();
  ptResizingRef.current = true;
  const startX = e.clientX;
  const startW = ptColWidths[colName] || ptDefWidths[colName];
  document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
  const move = (ev) => {
    const newW = Math.max(40, startW + ev.clientX - startX);
    setModal((p) => ({ ...p, ptColWidths: { ...(p.ptColWidths || ptDefWidths), [colName]: newW } }));
  };
  const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); setTimeout(() => { ptResizingRef.current = false; }, 0); };
  document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
};
const openPtFilter = (colName, e) => {
  e.stopPropagation();
  const rect = e.currentTarget.getBoundingClientRect();
  const counts = {};
  for (const p of (data?.processes || [])) { const v = ptCellVal(p, colName); counts[v] = (counts[v] || 0) + 1; }
  const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const current = ptColFilters[colName];
  const selected = new Set(current && current.length > 0 ? current : allVals);
  setModal((p) => ({ ...p, ptFilterOpen: colName, ptFilterPos: { x: rect.left, y: rect.bottom + 2 }, ptFilterVals: allVals, ptFilterCounts: counts, ptFilterSel: selected, ptFilterSearch: "" }));
};
const ptFilterOpen = modal.ptFilterOpen;
const ptFilterPos = modal.ptFilterPos || {};
const ptFilterVals = modal.ptFilterVals || [];
const ptFilterCounts = modal.ptFilterCounts || {};
const ptFilterSel = modal.ptFilterSel || new Set();
const ptFilterSearch = modal.ptFilterSearch || "";
const ptFilterDisplay = ptFilterSearch ? ptFilterVals.filter((v) => v.toLowerCase().includes(ptFilterSearch.toLowerCase())) : ptFilterVals;
const ptActiveFilterCount = Object.values(ptColFilters).filter((v) => v && v.length > 0).length;
const PT_CHK_W = 32;
const totalPtW = PT_CHK_W + ptHeaders.reduce((s, h) => s + (ptColWidths[h] || ptDefWidths[h]), 0) + 50;
const ptChecked = modal.ptChecked || new Set();
const ptCheckedCount = ptChecked.size;

// --- Process Inspector config constants ---
const PI_INTENTS = [
  { id: "low-noise", label: "Low-noise triage", desc: "High-confidence only \u2014 credential access, encoded PS, Office macros, service shells",
    disabled: new Set(["pi-8","pi-11","pi-15","pi-16","pi-17","pi-22","pi-23"]) },
  { id: "balanced", label: "Balanced", desc: "Recommended \u2014 all detection categories enabled", disabled: new Set() },
  { id: "broad", label: "Broad hunt", desc: "Maximum coverage \u2014 all chain rules + all standalone", disabled: new Set() },
];
// PI_TECHNIQUE_GROUPS and PI_SEV_COLORS are now imported from process-inspector.js.
// PI_ALL_RULES provides the canonical rule display metadata (name, sev, logic).
const PI_TELEMETRY = [
  { id: "sysmon", label: "Sysmon Process Create", eid: "1", desc: "Full parent/child with GUIDs + command line" },
  { id: "security", label: "Security Process Create", eid: "4688", desc: "PID-based linking, limited parent info" },
];
const piDisabledSet = modal.ptDisabledRules || new Set();

	const toggleTelemetry = (key) => {
  setModal(p => {
    const newTel = { ...p.ptTelemetry, [key]: !p.ptTelemetry[key] };
    const eids = []; if (newTel.sysmon) eids.push("1"); if (newTel.security) eids.push("4688");
    return { ...p, ptTelemetry: newTel, eventIdValue: eids.join(",") || null };
  });
  setTimeout(() => refreshPtPreview(), 0);
};

// --- Warning functions ---
const ptSkipWarnings = (evCounts, candidateRows, fullScopeCandidateRows, autoGenericFallback) => {
  const w = [];
  if (!(evCounts["1"] > 0) && !(evCounts["4688"] > 0)) {
    if (autoGenericFallback && candidateRows > 0)
      w.push({ level: "info", text: `No Sysmon 1 / Security 4688 found - preview using ${candidateRows.toLocaleString()} generic process rows` });
    else if (candidateRows > 0)
      w.push({ level: "warn", text: `${candidateRows.toLocaleString()} generic process rows detected, but no Sysmon 1 / Security 4688 are in the current scope` });
    else if (fullScopeCandidateRows > 0)
      w.push({ level: "info", text: `${fullScopeCandidateRows.toLocaleString()} generic process rows exist in the full tab - current filters are excluding them here` });
    else
      w.push({ level: "error", text: "No process creation events (Sysmon 1 or Security 4688)" });
  }
  else if (!(evCounts["1"] > 0))
    w.push({ level: "info", text: "No Sysmon EID 1 \u2014 using Security 4688 only (no GUIDs, limited parent info)" });
  else if (!(evCounts["4688"] > 0))
    w.push({ level: "info", text: "No Security 4688 \u2014 Sysmon only" });
  return w;
};
const ptSanityWarnings = (colQuality, linkQuality) => {
  const w = [];
  if (!colQuality) return w;
  if (linkQuality?.guidCoverage === 0 && linkQuality?.pidCoverage === 0)
    w.push({ level: "error", text: "No PID or GUID coverage \u2014 tree reconstruction will fail" });
  else if (linkQuality?.guidCoverage === 0 && linkQuality?.pidCoverage > 0)
    w.push({ level: "warn", text: "No ProcessGuid fields \u2014 PID reuse may weaken long-range linking" });
  if ((linkQuality?.cmdLineCoverage || 0) < 30)
    w.push({ level: "warn", text: `Command line coverage ${linkQuality?.cmdLineCoverage || 0}% \u2014 standalone detections reduced` });
  if ((linkQuality?.parentImageCoverage || 0) < 30)
    w.push({ level: "warn", text: `Parent image coverage ${linkQuality?.parentImageCoverage || 0}% \u2014 chain rules may underperform` });
  for (const [key, q] of Object.entries(colQuality)) {
    if (q.mapped && q.nullRate > 70)
      w.push({ level: "info", text: `${key} column has ${q.nullRate}% null/empty values` });
  }
  return w;
};

// --- Intent + group helpers ---
const applyPiIntent = (intent) => setModal(p => ({ ...p, ptDisabledRules: new Set(intent.disabled), ptIntent: intent.id }));
const resetPiRules = () => setModal(p => ({ ...p, ptDisabledRules: new Set(), ptIntent: "balanced" }));
const piGroupState = (ruleIds, disSet) => {
  const off = ruleIds.filter(id => disSet.has(id)).length;
  return off === 0 ? "on" : off === ruleIds.length ? "off" : "partial";
};
const piCoverageInfo = (colMap) => {
  const pidLink = !!(colMap.pid && colMap.ppid);
  const guidLink = !!(colMap.guid && colMap.parentGuid);
  const required = [
    { key: "linkage", label: "PID/PPID or GUID pair", mapped: pidLink || guidLink },
    { key: "image", label: "Image / Exe", mapped: !!colMap.image },
  ];
  const recommended = [
    { key: "cmdLine", label: "Command Line", mapped: !!colMap.cmdLine },
    { key: "ts", label: "Timestamp", mapped: !!colMap.ts },
    { key: "eventId", label: "Event ID", mapped: !!colMap.eventId },
    { key: "parentImage", label: "Parent Image", mapped: !!colMap.parentImage },
    { key: "user", label: "User", mapped: !!colMap.user },
  ];
  const reqOk = required.filter((item) => item.mapped).length;
  const recOk = recommended.filter((item) => item.mapped).length;
  const level = reqOk === required.length ? (recOk >= 3 ? "high" : "medium") : "low";
  return { level, reqOk, recOk, required, recommended, pidLink, guidLink };
};
const togglePiGroup = (group) => setModal(p => {
  const s = new Set(p.ptDisabledRules || []);
  const state = piGroupState(group.ruleIds, s);
  if (state === "on") group.ruleIds.forEach(id => s.add(id));
  else group.ruleIds.forEach(id => s.delete(id));
  return { ...p, ptDisabledRules: s };
});

const applyProcessTreeResult = (payload, progInt) => {
  clearInterval(progInt);
  tle?.removeAllListeners?.("process-tree-complete");
  const result = payload?.result ?? payload;
  const error = payload?.error || result?.error || null;
  const cancelled = payload?.cancelled || /cancelled/i.test(String(error || ""));

  if (cancelled) {
    setModal((p) => p?.type === "processTree"
      ? { ...p, phase: "config", loading: false, ptProgress: 0, ptPhaseIdx: 0, _cancelled: true, _ptJobId: null }
      : p);
    return;
  }

  if (error) {
    setModal((p) => p?.type === "processTree" && !p._cancelled
      ? { ...p, phase: "config", loading: false, error, ptProgress: 0, ptPhaseIdx: 0, _ptJobId: null }
      : p);
    return;
  }

  setModal((p) => p?.type === "processTree" && !p._cancelled
    ? { ...p, ptProgress: 100, ptPhaseIdx: 5, _ptJobId: null }
    : p);
  setTimeout(() => {
    setModal((p) => p?.type === "processTree" && !p._cancelled
      ? { ...p, phase: "results", loading: false, data: result, expandedNodes: {}, searchText: "" }
      : p);
  }, 250);
};

const handleBuild = async () => {
  const t0 = Date.now();
  const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
  const progInt = setInterval(() => {
    setModal((p) => {
      if (!p || p.type !== "processTree" || p.phase !== "loading") { clearInterval(progInt); return p; }
      const el = (Date.now() - t0) / 1000;
      const prog = Math.min(92, 90 * (1 - Math.exp(-el / 6)));
      const pi = prog < 10 ? 0 : prog < 30 ? 1 : prog < 55 ? 2 : prog < 75 ? 3 : 4;
      return { ...p, ptProgress: prog, ptPhaseIdx: pi };
    });
  }, 120);
  setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, ptProgress: 0, ptPhaseIdx: 0, _cancelled: false, _ptJobId: null }));
  try {
    const af = activeFilters(ct);
    const useGenericFallback = modal.ptPreview?.autoGenericFallback === true;
    const options = {
      pidCol: cols.pid, ppidCol: cols.ppid, guidCol: cols.guid, parentGuidCol: cols.parentGuid,
      imageCol: cols.image, cmdLineCol: cols.cmdLine, userCol: cols.user, tsCol: cols.ts, eventIdCol: cols.eventId, providerCol: cols.provider,
      eventIdValue: useGenericFallback ? null : (eventIdValue || null),
      searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
      searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      maxRows: modal.maxRows || 200000,
    };

    if (tle?.startProcessTree && tle?.onProcessTreeComplete) {
      tle.removeAllListeners?.("process-tree-complete");
      tle.onProcessTreeComplete((payload = {}) => {
        const currentModal = useUIStore.getState?.().modal;
        if (currentModal?.type !== "processTree") return;
        if (currentModal._ptJobId && payload.jobId && currentModal._ptJobId !== payload.jobId) return;
        applyProcessTreeResult(payload, progInt);
      });
      const started = await tle.startProcessTree(ct.id, options);
      if (started?.result || started?.error) {
        applyProcessTreeResult(started, progInt);
        return;
      }
      if (!started?.jobId) throw new Error("Process tree job did not start");
      setModal((p) => p?.type === "processTree" ? { ...p, _ptJobId: started.jobId } : p);
    } else {
      const result = await tle.getProcessTree(ct.id, options);
      applyProcessTreeResult({ result }, progInt);
    }
  } catch (e) {
    clearInterval(progInt);
    tle?.removeAllListeners?.("process-tree-complete");
    setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, phase: "config", loading: false, error: e.message, ptProgress: 0, _ptJobId: null } : p);
  }
};

const handleCancelBuild = async () => {
  const currentModal = useUIStore.getState?.().modal;
  const jobId = currentModal?.type === "processTree" ? currentModal._ptJobId : modal._ptJobId;
  tle?.removeAllListeners?.("process-tree-complete");
  setModal((p) => p?.type === "processTree"
    ? { ...p, phase: "config", loading: false, ptProgress: 0, ptPhaseIdx: 0, _cancelled: true, _ptJobId: null }
    : p);
  if (jobId && tle?.cancelJob) {
    try { await tle.cancelJob(jobId); } catch {}
  }
};

// Cached childMap + byKey — shared across buildFlat, expand helpers, detail panel
const _cachedChildMap = (() => {
  const c = ptCacheRef.current;
  if (c.childMapData === data) return c.childMap;
  if (!data?.processes?.length) { c.childMap = new Map(); c.childMapData = data; return c.childMap; }
  const m = new Map();
  for (const p of data.processes) {
    if (!m.has(p.parentKey)) m.set(p.parentKey, []);
    m.get(p.parentKey).push(p.key);
  }
  c.childMap = m;
  c.childMapData = data;
  return m;
})();
const _cachedByKey = (() => {
  const c = ptCacheRef.current;
  if (c.byKeyData === data) return c.byKeyMap;
  if (!data?.processes?.length) { c.byKeyMap = new Map(); c.byKeyData = data; return c.byKeyMap; }
  const m = new Map(data.processes.map((p) => [p.key, p]));
  c.byKeyMap = m;
  c.byKeyData = data;
  return m;
})();

// Expose byKeyMap / childMap before buildFlat — buildFlat calls ptCellVal which
// reads byKeyMap, so the const must be initialized before the first call.
const byKeyMap = _cachedByKey;
const childMap = _cachedChildMap;

// Build flat visible list from tree data, with connector metadata
const buildFlat = () => {
  if (!data?.processes?.length) return [];
  const procs = data.processes;
  const byKey = _cachedByKey;
  const childMap = _cachedChildMap;
  const st = (searchText || "").toLowerCase();
  const susOnly = !!modal.susOnlyFilter;
  const sevFilter = Array.isArray(modal.ptSevFilter) ? modal.ptSevFilter : [];
  const clusterKeys = modal.ptClusterKeys || null;
  const hasColFilters = Object.values(ptColFilters).some((v) => v && v.length > 0);
  const siblingSort = (a, b) => {
    const av = ptSortKey(a, ptSortCol), bv = ptSortKey(b, ptSortCol);
    const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
    return ptSortDir === "asc" ? cmp : -cmp;
  };
  // Flat mode when search, column filters, suspicious-only, severity filter, cluster filter (non-context), or sorting by Detection
  const flatSort = ptSortCol === "Detection";
  const clusterContext = !!(clusterKeys && modal.ptClusterContext);
  if (st || hasColFilters || susOnly || sevFilter.length || (clusterKeys && !clusterContext) || flatSort) {
    let filtered = [...procs];
    if (clusterKeys && !clusterContext) {
      filtered = filtered.filter((p) => clusterKeys.has(p.key));
    }
    if (hasColFilters) {
      filtered = filtered.filter((p) => {
        for (const [col, vals] of Object.entries(ptColFilters)) {
          if (!vals || vals.length === 0) continue;
          if (!vals.includes(ptCellVal(p, col))) return false;
        }
        return true;
      });
    }
    if (st) {
      filtered = filtered.filter((p) =>
        (p.processName || "").toLowerCase().includes(st) ||
        (p.pid || "").toLowerCase().includes(st) ||
        (p.cmdLine || "").toLowerCase().includes(st) ||
        (p.user || "").toLowerCase().includes(st)
      );
    }
    if (susOnly) {
      filtered = filtered.filter((p) => (_ptDetMap.get(p.key) || { level: 0 }).level > 0);
    }
    if (sevFilter.length) {
      filtered = filtered.filter((p) => sevFilter.includes((_ptDetMap.get(p.key) || { level: 0 }).level));
    }
    filtered.sort(siblingSort);
    return filtered.map((p) => ({ ...p, depth: 0, connectors: [], isLast: false }));
  }
  // When clusterContext is active, auto-expand ancestors of cluster members
  const ctxExpanded = clusterContext ? (() => {
    const expanded = { ...expandedNodes };
    for (const ck of clusterKeys) {
      let cur = byKey.get(ck);
      while (cur) {
        // Stop at a PID-reuse mislinked edge (shared guard) so we expand only the member's
        // real ancestors, not an unrelated branch reached through a bad link.
        const pk = consistentParentKey(cur, byKey);
        if (!pk || !byKey.has(pk)) break;
        expanded[pk] = true;
        cur = byKey.get(pk);
      }
    }
    return expanded;
  })() : expandedNodes;
  const roots = procs.filter((p) => !byKey.has(p.parentKey));
  const flat = [];
  const activeLines = {};
  const visited = new Set();
  const MAX_DEPTH = 100;
  const dfs = (keys, depth) => {
    if (depth > MAX_DEPTH) return;
    const sorted = keys.map((k) => byKey.get(k)).filter(Boolean);
    sorted.sort(siblingSort);
    for (let si = 0; si < sorted.length; si++) {
      const node = sorted[si];
      if (visited.has(node.key)) continue;
      visited.add(node.key);
      const isLast = si === sorted.length - 1;
      const connectors = [];
      for (let d = 0; d < depth; d++) connectors.push(!!activeLines[d]);
      flat.push({ ...node, depth, connectors, isLast: depth > 0 && isLast });
      if (ctxExpanded[node.key]) {
        activeLines[depth] = !isLast;
        dfs(childMap.get(node.key) || [], depth + 1);
        delete activeLines[depth];
      }
    }
  };
  dfs(roots.map((r) => r.key), 0);
  return flat;
};

// Cached flat list + byKeyMap — only recompute when deps actually change (not on selectedKey click)
const flatNodes = (() => {
  if (phase !== "results") return [];
  const c = ptCacheRef.current;
  const susOnly = !!modal.susOnlyFilter;
  const sevFilter = modal.ptSevFilter || null; // reference-stable cache key (don't allocate a fresh [])
  const clusterKeys = modal.ptClusterKeys || null;
  const clusterCtx = !!modal.ptClusterContext;
  if (c.data === data && c.expandedNodes === expandedNodes && c.searchText === searchText &&
      c.ptColFilters === ptColFilters && c.ptSortCol === ptSortCol && c.ptSortDir === ptSortDir && c.susOnly === susOnly && c.sevFilter === sevFilter && c.clusterKeys === clusterKeys && c.clusterCtx === clusterCtx) {
    return c.flatNodes;
  }
  const result = buildFlat();
  Object.assign(c, { flatNodes: result, data, expandedNodes, searchText, ptColFilters, ptSortCol, ptSortDir, susOnly, sevFilter, clusterKeys, clusterCtx });
  return result;
})();
// Findings minimap: bucket the (ordered) flat list into severity bands so the rail
// beside the tree shows where the high-severity rows are. Cached on (flatNodes, detMap)
// so it never recomputes on scroll/selection — only when the visible list itself changes.
const _ptRail = (() => {
  const c = ptCacheRef.current;
  if (c.railFlat === flatNodes && c.railDetMap === _ptDetMap) return c.rail;
  const N = flatNodes.length;
  let rail = null;
  if (N > 0) {
    const B = Math.min(N, 240);
    const buckets = new Array(B).fill(0);
    for (let i = 0; i < N; i++) {
      const lv = (_ptDetMap.get(flatNodes[i].key) || { level: 0 }).level;
      if (lv > 0) { const b = Math.floor((i / N) * B); if (lv > buckets[b]) buckets[b] = lv; }
    }
    rail = buckets;
  }
  c.rail = rail; c.railFlat = flatNodes; c.railDetMap = _ptDetMap;
  return rail;
})();
// Incident-story synthesis. The grouping/anchor/finalize logic lives in the
// pipeline module — this wrapper is just the existing memoization layer.
const _ptIncidentStories = (() => {
  const c = ptCacheRef.current;
  if (c.storyData === data && c.storyDetMap === _ptDetMap && c.storySeqMap === _ptSeqMap) return c.storyList || [];
  const stories = buildIncidentStories(data, byKeyMap, _cachedChildMap, _ptDetMap, _ptSeqMap, _ptNodeClusterMap);
  c.storyList = stories;
  c.storyData = data;
  c.storyDetMap = _ptDetMap;
  c.storySeqMap = _ptSeqMap;
  return stories;
})();
const _ptNodeStoryMap = (() => {
  const c = ptCacheRef.current;
  if (c.storyNodeData === data && c.storyNodeStories === _ptIncidentStories) return c.storyNodeMap || new Map();
  const m = buildNodeStoryMap(_ptIncidentStories);
  c.storyNodeMap = m;
  c.storyNodeData = data;
  c.storyNodeStories = _ptIncidentStories;
  return m;
})();

// Chain highlight: walk from selected node to root (cycle-safe)
const selectedKey = modal.selectedKey || null;
// Refresh the keyboard handler's view of the current render (see the keydown useEffect above).
ptNavRef.current = { flatNodes, selectedKey, expandedNodes, byKeyMap, childMap, setModal, ptScrollRef, rowH: modal.ptDensity === "compact" ? 26 : 34 };
const chainKeys = new Set();
if (selectedKey && byKeyMap.size > 0) {
  let cur = selectedKey;
  while (cur && !chainKeys.has(cur)) {
    chainKeys.add(cur);
    const node = byKeyMap.get(cur);
    if (!node) break;
    // Highlight only the real execution chain — stop at a PID-reuse mislinked edge.
    const pk = consistentParentKey(node, byKeyMap);
    if (!pk || !byKeyMap.has(pk)) break;
    cur = pk;
  }
}
const expandAll = () => {
  const en = {};
  for (const p of (data?.processes || [])) { if (p.childCount > 0) en[p.key] = true; }
  setModal((p) => p ? { ...p, expandedNodes: en } : p);
};
const collapseAll = () => setModal((p) => p ? { ...p, expandedNodes: {} } : p);
const expandToDepth = (maxD) => {
  const en = {};
  for (const p of (data?.processes || [])) { if (p.childCount > 0 && p.depth < maxD) en[p.key] = true; }
  setModal((p) => p ? { ...p, expandedNodes: en } : p);
};

const selStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 6, padding: "4px 8px", fontSize: 12, fontFamily: "monospace" };

return (
  <DraggableResizableModal
    defaultWidth={Math.round(window.innerWidth * 0.92)}
    defaultHeight={Math.round(window.innerHeight * 0.88)}
    minWidth={480}
    minHeight={300}
    onClose={() => setModal(null)}
  >
    {({ startDrag, width: pw }) => (<>
      {/* Header — draggable, gradient glass */}
      <div onMouseDown={startDrag} style={{ padding: "14px 20px 10px", borderBottom: `1px solid ${th.border}66`, cursor: "move", flexShrink: 0, userSelect: "none", background: `linear-gradient(180deg, ${th.headerBg}ee 0%, ${th.modalBg}cc 100%)`, backdropFilter: "blur(20px) saturate(1.4)", WebkitBackdropFilter: "blur(20px) saturate(1.4)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent} 0%, ${th.accentHover || th.accent} 100%)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, color: "#fff", boxShadow: `0 2px 8px ${th.accent}44`, flexShrink: 0 }}>{"\u25B3"}</div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>
                <span style={{ color: th.accent }}>IRFlow</span> {"\u2014"} Process Inspector
              </h3>
              {phase === "results" && data?.stats && (() => {
                // Hostname display: show real hostnames only, never fall back to a
                // user's domain (was the same Finding #4 bug). If the dataset spans
                // multiple hosts show a count; if all rows are missing a hostname
                // show nothing rather than a fabricated label.
                const hostname = (() => {
                  const procs = data?.processes || [];
                  const hosts = new Set();
                  for (const p of procs) {
                    const h = (p.hostname || "").trim();
                    if (h) hosts.add(h);
                  }
                  if (hosts.size === 0) return "";
                  if (hosts.size === 1) return [...hosts][0];
                  return `${hosts.size} hosts`;
                })();
                const providers = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
                const eids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
                // Date range: walk processes once tracking min/max via canonical
                // epoch ms. Pin the display strings to whichever raw rows produced
                // the actual chronological extremes — never lex-sort the strings.
                const dateRange = (() => {
                  const procs = data?.processes || [];
                  let minMs = Number.POSITIVE_INFINITY;
                  let maxMs = Number.NEGATIVE_INFINITY;
                  let minStr = "";
                  let maxStr = "";
                  for (const p of procs) {
                    if (!p.ts) continue;
                    const t = normalizeTimestamp(p.ts);
                    if (!Number.isFinite(t)) continue;
                    if (t < minMs) { minMs = t; minStr = p.ts; }
                    if (t > maxMs) { maxMs = t; maxStr = p.ts; }
                  }
                  if (!minStr) return "";
                  // Trim "YYYY-MM-DD HH:MM:SS..." down to the date portion for header brevity.
                  // Falls back to the full string if the trim regex doesn't match a date.
                  const datePart = (s) => {
                    const m = String(s).match(/(\d{4}-\d{2}-\d{2})/);
                    if (m) return m[1];
                    const us = String(s).match(/(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})/);
                    return us ? us[1] : String(s).split(/[\sT]/)[0];
                  };
                  const first = datePart(minStr);
                  const last = datePart(maxStr);
                  return first === last ? first : `${first} \u2192 ${last}`;
                })();
                return (
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginTop: 2, display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {hostname && <span style={{ color: th.text, fontWeight: 500 }}>{hostname}</span>}
                    {hostname && providers && <span>{"\u00B7"}</span>}
                    {providers && <span>{providers}</span>}
                    {eids && <span>{"\u00B7"} EID {eids}</span>}
                    <span>{"\u00B7"} {data.stats.totalProcesses.toLocaleString()} events</span>
                    {dateRange && <span>{"\u00B7"} {dateRange}</span>}
                    {data.useGuid && <span style={{ color: th.success }}>{"\u00B7"} GUID-linked</span>}
                    {data.stats.truncated && <span style={{ color: th.danger }}>{"\u00B7"} Truncated at {(data.stats.totalProcesses || 0).toLocaleString()} {"\u2014"} increase limit</span>}
                  </div>
                );
              })()}
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 18, cursor: "pointer", padding: "0 4px", lineHeight: 1 }}>{"\u00D7"}</button>
        </div>
      </div>

      {/* Config phase */}
      {phase === "config" && (() => {
        const prev = modal.ptPreview;
        const prevLoading = modal.ptPreviewLoading;
        const evCounts = prev?.eventCounts || {};
        const fullEvCounts = prev?.fullScopeEventCounts || {};
        const colQuality = prev?.columnQuality || {};
        const linkQuality = prev?.linkingQuality || {};
        const linkMode = prev?.linkingMode || "unknown";
        const providerMix = prev?.providerMix || {};
        const isEvtxECmd = prev?.isEvtxECmd || false;
        const trackedEvents = prev?.trackedEvents || 0;
        const candidateRows = prev?.candidateRows || 0;
        const fullScopeCandidateRows = prev?.fullScopeCandidateRows || 0;
        const previewMode = prev?.previewMode || "empty";
        const autoGenericFallback = prev?.autoGenericFallback === true;
        const usingGenericRows = autoGenericFallback && previewMode === "candidate-rows";
        const buildableRows = usingGenericRows ? candidateRows : trackedEvents;
        const providerFallback = prev?.providerFallback || false;
        const eidNormalized = prev?.eidNormalized || false;
        const skipW = ptSkipWarnings(evCounts, candidateRows, fullScopeCandidateRows, autoGenericFallback);
        const sanityW = ptSanityWarnings(colQuality, linkQuality);
        const allWarnings = [...skipW, ...sanityW];
        if (providerFallback)
          allWarnings.push({ level: "warn", text: "Provider column may be mis-mapped \u2014 preview using event-ID-only fallback" });
        if (eidNormalized)
          allWarnings.push({ level: "warn", text: "Event ID column contains non-standard values \u2014 using normalized matching" });
        if (buildableRows > (modal.maxRows || 200000))
          allWarnings.push({ level: "warn", text: `${buildableRows.toLocaleString()} rows exceed limit of ${(modal.maxRows || 200000).toLocaleString()} \u2014 tree will be truncated` });
        const topValues = prev?.topValues || {};
        const dataShape = prev?.dataShape || {};
        const linkDot = { guid: th.success, "pid-only": th.sev.high, insufficient: th.danger }[linkMode] || th.textMuted;
        const sampleRows = prev?.sampleRows || [];
        const sampleHeaders = dataShape.sampleHeaders || [];
        // Readiness score + detection capability breakdown
        const _readiness = (() => {
          if (!prev || prevLoading) return { score: "unknown", label: "Scanning\u2026", color: th.textMuted, blockers: [], caps: [] };
          const blockers = [];
          if (buildableRows === 0) blockers.push(usingGenericRows ? "No generic process rows found" : "No process-creation events (EID 1/4688) found");
          if (!usingGenericRows && !cols.eventId) blockers.push("Event ID column not mapped");
          if (linkMode === "insufficient") blockers.push("No GUID or PID linkage available");
          if ((linkQuality.cmdLineCoverage || 0) < 10) blockers.push("Command line coverage < 10%");
          if ((linkQuality.parentImageCoverage || 0) < 10) blockers.push("Parent image coverage < 10%");
          if (!usingGenericRows && eidNormalized) blockers.push("Event ID values needed normalization");
          if (!usingGenericRows && providerFallback) blockers.push("Provider column may be mis-mapped");
          // Detection capability breakdown
          const guidOk = (linkQuality.guidCoverage || 0) >= 50;
          const pidOk = (linkQuality.pidCoverage || 0) >= 50;
          const cmdOk = (linkQuality.cmdLineCoverage || 0) >= 30;
          const piOk = (linkQuality.parentImageCoverage || 0) >= 30;
          const noEvents = buildableRows === 0;
          const caps = [
            { name: "Tree reconstruction", status: noEvents ? "unavailable" : guidOk ? "good" : pidOk ? "weak" : "unavailable",
              note: noEvents ? "no rows" : guidOk ? "GUID-linked" : pidOk ? "PID-only fallback" : "no linkage" },
            { name: "Chain detections", status: noEvents ? "unavailable" : (guidOk || pidOk) && piOk ? "good" : (guidOk || pidOk) ? "weak" : "unavailable",
              note: noEvents ? "no rows" : !guidOk && !pidOk ? "needs parent linkage" : !piOk ? "parent image sparse" : "parent context available" },
            { name: "Standalone detections", status: noEvents ? "unavailable" : cmdOk ? "good" : "weak",
              note: noEvents ? "no rows" : cmdOk ? `command line ${linkQuality.cmdLineCoverage || 0}%` : `command line only ${linkQuality.cmdLineCoverage || 0}%` },
            { name: "Sequence detection", status: noEvents ? "unavailable" : cmdOk && (guidOk || pidOk) ? "good" : cmdOk ? "weak" : "unavailable",
              note: noEvents ? "no rows" : !cmdOk ? "needs command line" : !(guidOk || pidOk) ? "no tree for root affinity" : "tree + command line available" },
          ];
          const crit = blockers.length > 0 && (buildableRows === 0 || linkMode === "insufficient");
          if (crit) return { score: "insufficient", label: "Insufficient for tree building", color: th.danger, blockers, caps };
          if (usingGenericRows && blockers.length > 0) return { score: "usable", label: "Usable with generic process rows", color: th.sev.high, blockers, caps };
          if (usingGenericRows) return { score: "ready", label: "Ready with generic process rows", color: th.success, blockers: [], caps };
          if (blockers.length > 0) return { score: "usable", label: "Usable with reduced confidence", color: th.sev.high, blockers, caps };
          return { score: "ready", label: "Ready", color: th.success, blockers: [], caps };
        })();
        // Mapping status language
        const _coreCols = ["pid", "ppid", "image", "cmdLine", "ts", "eventId"].filter(k => cols[k]).length;
        const _enrichCols = ["guid", "parentGuid", "parentImage", "user", "elevation", "integrity", "provider"].filter(k => cols[k]).length;
        const _mapLabel = _coreCols >= 6 ? "Core mapped" : _coreCols >= 4 ? "Core incomplete" : "Core missing";
        const _enrichLabel = _enrichCols >= 5 ? "enrichment good" : _enrichCols >= 2 ? "enrichment sparse" : "enrichment minimal";
        const warnIcon = { error: "\u26D4", warn: "\u26A0", info: "\u2139" };
        const warnColor = { error: th.danger, warn: th.sev.high, info: th.accent };
        const mappedCount = ["pid", "ppid", "guid", "parentGuid", "image", "parentImage", "cmdLine", "user", "ts", "eventId", "elevation", "integrity", "provider"].filter(k => cols[k]).length;
        // PI_ALL_RULES, PI_SEV_COLORS, PI_TECHNIQUE_GROUPS are now imported from
        // process-inspector.js — the canonical source of truth for rule metadata.
        // (local PI_RULES + PI_SEV_COLORS deleted — now imported from process-inspector.js)
        const piActiveCount = PI_ALL_RULES.length - [...piDisabledSet].filter(k => k.startsWith("pi-")).length;
        const piCustomCount = (modal.ptCustomRules || []).length;
        const piCustomRuleErrors = (modal.ptCustomRules || [])
          .map((rule, idx) => {
            const pattern = String(rule.pattern || "").trim();
            const message = customRuleErrors.get(pattern) || validateCustomRulePattern(pattern);
            return message ? { idx, rule, message } : null;
          })
          .filter(Boolean);
        const togglePiRule = (key) => setModal((p) => { const s = new Set(p.ptDisabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, ptDisabledRules: s }; });
        const togglePiExpand = (key) => setModal((p) => ({ ...p, ptExpandedRule: p.ptExpandedRule === key ? null : key }));
        const addPiCustomRule = () => {
          const nr = modal.ptNewRule || {};
          const name = String(nr.name || "").trim();
          const pattern = String(nr.pattern || "").trim();
          if (!name) {
            setModal((p) => ({ ...p, ptNewRuleError: "Rule name is required." }));
            return;
          }
          const patternError = validateCustomRulePattern(pattern);
          if (patternError) {
            setModal((p) => ({ ...p, ptNewRuleError: patternError }));
            return;
          }
          setModal((p) => ({
            ...p,
            ptCustomRules: [...(p.ptCustomRules || []), { ...nr, name, pattern }],
            ptAddingRule: false,
            ptNewRule: {},
            ptNewRuleError: "",
          }));
        };
        const deletePiCustomRule = (idx) => setModal((p) => { const arr = [...(p.ptCustomRules || [])]; arr.splice(idx, 1); return { ...p, ptCustomRules: arr }; });
        const ptCoverageTone = (pct, threshold) => pct >= threshold ? (th.success) : pct > 0 ? th.sev.high : (th.danger);
        const piCov = piCoverageInfo(cols);
        const piCovColor = { high: th.sev.clean, medium: th.sev.med, low: th.sev.critical }[piCov.level];
        const piTechniqueGridColumns = pw < 980 ? "1fr" : "1fr 1fr";

        return (
        <div style={{ padding: 20, overflowY: "auto", flex: 1, minHeight: 0 }}>
          {modal.error && <div style={{ padding: "10px 14px", marginBottom: 14, background: `${(th.danger)}15`, border: `1px solid ${(th.danger)}33`, borderRadius: 8, color: th.danger, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{modal.error}</div>}
          <div style={{ marginBottom: 12 }}>
            <div style={{ padding: "10px 14px", background: `${piCovColor}08`, border: `1px solid ${piCovColor}22`, borderRadius: 10, marginBottom: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={piCovColor} strokeWidth="2" strokeLinecap="round">
                  {piCov.level === "high" ? <><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></> : piCov.level === "medium" ? <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></> : <><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></>}
                </svg>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
                    {piCov.level === "high" ? "Tree-ready mapping detected" : piCov.level === "medium" ? "Core tree mapping detected" : "Missing required tree columns"}
                  </div>
                  <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                    {piCov.reqOk}/{piCov.required.length} required · {piCov.recOk}/{piCov.recommended.length} recommended{piCov.guidLink ? " · GUID linkage" : piCov.pidLink ? " · PID linkage" : ""}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                {!modal.ptShowMapping && <div style={{ display: "flex", gap: 3, marginRight: 4 }}>
                  {[...piCov.required, ...piCov.recommended].map((item) => (
                    <span key={item.key} title={`${item.label}: ${item.mapped ? "mapped" : "unmapped"}`} style={{ width: 6, height: 6, borderRadius: 3, background: item.mapped ? th.sev.clean : th.sev.critical + "66" }} />
                  ))}
                </div>}
                <button onClick={() => setModal((p) => ({ ...p, ptShowMapping: !p.ptShowMapping }))} style={{ ...ms.bsm, fontSize: 10, padding: "2px 8px" }}>
                  {modal.ptShowMapping ? "Hide" : "Edit"}
                </button>
              </div>
            </div>

            {modal.ptShowMapping && (
              <div style={{ padding: "10px 14px", background: `${th.panelBg}55`, border: `1px solid ${th.border}22`, borderRadius: 10, marginBottom: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
                  {[
                    ["pid", "Process ID", true], ["ppid", "Parent PID", true], ["guid", "Process GUID", true],
                    ["parentGuid", "Parent GUID", true], ["image", "Image / Exe", true], ["cmdLine", "Command Line", false],
                    ["ts", "Timestamp", false], ["eventId", "Event ID", false], ["parentImage", "Parent Image", false],
                    ["user", "User", false], ["provider", "Provider", false], ["integrity", "Integrity", false], ["elevation", "Elevation", false],
                  ].map(([key, label, req]) => (
                    <div key={key}>
                      <label style={{ fontSize: 9, color: cols[key] ? th.textDim : req ? th.sev.critical : th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.04em", display: "flex", alignItems: "center", gap: 3, marginBottom: 2 }}>
                        {cols[key] ? <span style={{ color: th.sev.clean }}>{"\u2713"}</span> : req ? <span style={{ color: th.sev.critical }}>{"\u2717"}</span> : <span style={{ color: th.textMuted }}>{"\u25CB"}</span>}
                        {label}
                      </label>
                      <select value={cols[key] || ""} onChange={(e) => { const v = e.target.value || null; setModal((p) => { const nc = { ...p.columns, [key]: v }; setTimeout(() => refreshPtPreview(nc), 0); return { ...p, columns: nc }; }); }} style={{ ...ms.sl, fontSize: 10, padding: "3px 6px" }}>
                        <option value="">-- auto --</option>
                        {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                      </select>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <div style={{ display: "flex", gap: 4 }}>
                {PI_INTENTS.map((intent) => {
                  const active = (modal.ptIntent || "balanced") === intent.id;
                  return (
                    <button key={intent.id} onClick={() => applyPiIntent(intent)} title={intent.desc}
                      style={{ padding: "4px 10px", fontSize: 10, fontWeight: active ? 600 : 400, fontFamily: "-apple-system, sans-serif", background: active ? `${th.accent}18` : "transparent", color: active ? th.accent : th.textDim, border: `1px solid ${active ? th.accent + "44" : th.border + "22"}`, borderRadius: 6, cursor: "pointer", transition: "all var(--m-base)" }}>
                      {intent.label}
                    </button>
                  );
                })}
              </div>
              <button onClick={resetPiRules} title="Reset all rules to defaults"
                style={{ padding: "3px 8px", fontSize: 9, fontFamily: "-apple-system, sans-serif", background: "transparent", color: th.textMuted, border: `1px solid ${th.border}22`, borderRadius: 4, cursor: "pointer", display: "flex", alignItems: "center", gap: 3, transition: "all var(--m-base)" }}
                onMouseEnter={(e) => { e.currentTarget.style.color = th.accent; e.currentTarget.style.borderColor = th.accent + "44"; }}
                onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; e.currentTarget.style.borderColor = th.border + "22"; }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
                Reset
              </button>
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Detection Techniques</div>
              <div style={{ display: "grid", gridTemplateColumns: piTechniqueGridColumns, gap: 8, alignItems: "start" }}>
                {PI_TECHNIQUE_GROUPS.map((group) => {
                  const state = piGroupState(group.ruleIds, piDisabledSet);
                  const activeRuleCount = group.ruleIds.filter((id) => !piDisabledSet.has(id)).length;
                  const isOn = state !== "off";
                  return (
                    <div key={group.id} style={{ padding: "10px 14px", background: isOn ? `${th.accent}08` : `${th.panelBg}33`, border: `1px solid ${isOn ? th.accent + "22" : th.border + "22"}`, borderRadius: 10, cursor: "pointer", transition: "all var(--m-base)", opacity: isOn ? 1 : 0.6, minHeight: state === "partial" ? 100 : 72 }}
                      onClick={() => togglePiGroup(group)}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                        <div style={{ minWidth: 0, paddingRight: 10 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{group.label}</div>
                          <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1, lineHeight: 1.4 }}>{group.desc}</div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                          <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{activeRuleCount}/{group.ruleIds.length}</span>
                          <div style={{ width: 32, height: 18, borderRadius: 10, background: isOn ? th.accent : th.textMuted + "33", transition: "background var(--m-base)", position: "relative" }}>
                            <div style={{ width: 14, height: 14, borderRadius: 8, background: "#fff", position: "absolute", top: 2, left: isOn ? 16 : 2, transition: "left var(--m-base)", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }} />
                          </div>
                        </div>
                      </div>
                      {state === "partial" && (
                        <div style={{ marginTop: 6, paddingTop: 6, borderTop: `1px solid ${th.border}15`, display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {group.ruleIds.map((ruleId) => {
                            const r = PI_ALL_RULES.find((x) => x.id === ruleId);
                            if (!r) return null;
                            const off = piDisabledSet.has(ruleId);
                            return (
                              <span key={ruleId} onClick={(e) => { e.stopPropagation(); togglePiRule(ruleId); }}
                                style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: off ? `${th.textMuted}11` : `${PI_SEV_COLORS[r.sev]}15`, color: off ? th.textMuted : PI_SEV_COLORS[r.sev], border: `1px solid ${off ? th.border + "22" : PI_SEV_COLORS[r.sev] + "33"}`, fontFamily: "-apple-system, sans-serif", cursor: "pointer", textDecoration: off ? "line-through" : "none", opacity: off ? 0.5 : 1, transition: "all var(--m-base)" }}>
                                {r.name}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                {PI_TELEMETRY.map((src) => {
                  const active = modal.ptTelemetry?.[src.id] !== false;
                  const srcCount = evCounts[src.eid] || 0;
                  return (
                    <label key={src.id} style={{ fontSize: 11, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                      <input type="checkbox" checked={active} onChange={() => toggleTelemetry(src.id)} style={{ accentColor: th.accent }} />
                      {src.label}
                      <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "SF Mono, monospace" }}>{srcCount.toLocaleString()}</span>
                    </label>
                  );
                })}
              </div>
              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{piActiveCount}/{PI_ALL_RULES.length} rules{piCustomCount > 0 ? ` + ${piCustomCount} custom` : ""}</span>
            </div>

            <div style={{ padding: "10px 14px", background: `${th.panelBg}44`, border: `1px solid ${th.border}22`, borderRadius: 10 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Event Availability</div>
                {prev && <span style={{ fontSize: 9, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{trackedEvents > 0 ? `${trackedEvents.toLocaleString()} tracked events` : candidateRows > 0 ? `${candidateRows.toLocaleString()} candidate rows` : "0 rows"}</span>}
              </div>
              {prevLoading ? (
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Scanning dataset...</div>
              ) : !prev ? (
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", padding: "6px 0" }}>Preview unavailable</div>
              ) : (
                <>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: allWarnings.length > 0 ? 8 : 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${_readiness.color}12`, border: `1px solid ${_readiness.color}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: _readiness.color }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{_readiness.label}</span>
                    </div>
                    {PI_TELEMETRY.map((src) => {
                      const total = evCounts[src.eid] || 0;
                      const present = total > 0;
                      return (
                        <div key={src.id} style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: present ? th.sev.clean + "10" : `${th.textMuted}08`, border: `1px solid ${present ? th.sev.clean + "22" : th.border + "15"}` }}>
                          <span style={{ width: 5, height: 5, borderRadius: 3, background: present ? th.sev.clean : th.textMuted + "44" }} />
                          <span style={{ fontSize: 9, color: present ? th.text : th.textMuted, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{src.label}</span>
                          {present && <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{total >= 1000 ? (total / 1000).toFixed(1) + "k" : total}</span>}
                        </div>
                      );
                    })}
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${linkDot}10`, border: `1px solid ${linkDot}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: linkDot }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Linking</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkMode === "guid" ? "GUID" : linkMode === "pid-only" ? "PID" : "None"}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30)}10`, border: `1px solid ${ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30)}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: ptCoverageTone(linkQuality.cmdLineCoverage || 0, 30) }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Command Line</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkQuality.cmdLineCoverage || 0}%</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${ptCoverageTone(linkQuality.parentImageCoverage || 0, 30)}10`, border: `1px solid ${ptCoverageTone(linkQuality.parentImageCoverage || 0, 30)}22` }}>
                      <span style={{ width: 5, height: 5, borderRadius: 3, background: ptCoverageTone(linkQuality.parentImageCoverage || 0, 30) }} />
                      <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Parent Image</span>
                      <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{linkQuality.parentImageCoverage || 0}%</span>
                    </div>
                    {candidateRows > 0 && trackedEvents === 0 && (
                      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${th.accent}10`, border: `1px solid ${th.accent}22` }}>
                        <span style={{ width: 5, height: 5, borderRadius: 3, background: th.accent }} />
                        <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Generic Rows</span>
                        <span style={{ fontSize: 8, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{candidateRows >= 1000 ? (candidateRows / 1000).toFixed(1) + "k" : candidateRows}</span>
                      </div>
                    )}
                    {usingGenericRows && (
                      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, background: `${th.accent}10`, border: `1px solid ${th.accent}22` }}>
                        <span style={{ width: 5, height: 5, borderRadius: 3, background: th.accent }} />
                        <span style={{ fontSize: 9, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Fallback Build Mode</span>
                      </div>
                    )}
                  </div>

                  {allWarnings.length > 0 && (
                    <div style={{ borderTop: `1px solid ${th.border}15`, paddingTop: 6 }}>
                      {allWarnings.slice(0, 4).map((warning, idx) => (
                        <div key={`${warning.level}-${idx}`} style={{ display: "flex", alignItems: "flex-start", gap: 6, padding: "2px 0" }}>
                          <span style={{ fontSize: 10, flexShrink: 0, marginTop: 1, color: warning.level === "error" ? th.sev.critical : warning.level === "warn" ? th.sev.med : th.textMuted }}>
                            {warning.level === "error" ? "\u2717" : warning.level === "warn" ? "\u26A0" : "\u25CB"}
                          </span>
                          <span style={{ fontSize: 10, color: warning.level === "error" ? th.sev.critical : warning.level === "warn" ? th.sev.med : th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>{warning.text}</span>
                        </div>
                      ))}
                      {allWarnings.length > 4 && (
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", paddingTop: 2 }}>
                          {allWarnings.length - 4} more notes in current scope.
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* 6h. Collapsible Advanced Section */}
          <button onClick={() => setModal(p => ({ ...p, ptShowAdvanced: !p.ptShowAdvanced }))}
            style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: modal.ptShowAdvanced ? "10px 10px 0 0" : 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all var(--m-base)", marginBottom: modal.ptShowAdvanced ? 0 : 0, opacity: buildableRows === 0 ? 0.5 : 1 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Advanced
            </span>
            <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
	              <span>{piActiveCount}/{PI_ALL_RULES.length} rules{piCustomCount > 0 ? `, ${piCustomCount} custom` : ""}{piCustomRuleErrors.length > 0 ? `, ${piCustomRuleErrors.length} rule error${piCustomRuleErrors.length === 1 ? "" : "s"}` : ""}</span>
              <span style={{ transform: modal.ptShowAdvanced ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", fontSize: 12 }}>{"\u25BE"}</span>
            </span>
          </button>
          {modal.ptShowAdvanced && (
            <div style={{ padding: "12px 14px", borderLeft: `1px solid ${th.border}33`, borderRight: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}33`, borderRadius: "0 0 10px 10px", background: `${th.panelBg}55` }}>
              {/* Custom EventID override + Max processes */}
              <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 110px 1fr", gap: "6px 10px", alignItems: "center", fontSize: 12, fontFamily: "-apple-system, sans-serif", marginBottom: 12 }}>
                <label style={{ color: th.textDim, textAlign: "right", fontSize: 11 }}>EventID override:</label>
                <input value={eventIdValue || ""} onChange={(e) => setModal(p => ({ ...p, eventIdValue: e.target.value }))} placeholder="1,4688 (blank = all)" style={{ ...selStyle, width: "100%" }} />
                <label style={{ color: th.textDim, textAlign: "right", fontSize: 11 }}>Max processes:</label>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <input type="number" value={modal.maxRowsInput ?? modal.maxRows ?? 200000} onChange={(e) => setModal(p => ({ ...p, maxRowsInput: e.target.value }))} onBlur={(e) => { const v = parseInt(e.target.value); setModal(p => ({ ...p, maxRows: isNaN(v) || v < 100 ? 200000 : v, maxRowsInput: undefined })); }} style={{ ...selStyle, width: 100 }} min="100" step="50000" />
                  <span style={{ fontSize: 10, color: th.textMuted }}>default: 200,000</span>
                </div>
              </div>

              {/* Individual rule toggles */}
              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                Detection Rules ({piActiveCount}/{PI_ALL_RULES.length})
              </div>
              {[...PI_ALL_RULES].sort((a, b) => { const so = { critical: 0, high: 1, medium: 2, low: 3 }; return (so[a.sev] ?? 9) - (so[b.sev] ?? 9); }).map((r) => {
                const off = piDisabledSet.has(r.id);
                const expanded = modal.ptExpandedRule === r.id;
                const groupMeta = PI_TECHNIQUE_GROUPS.find((g) => g.id === r.group);
                const groupLabel = groupMeta?.label || r.group || "";
                return (
                  <div key={r.id}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity var(--m-base)" }}>
                      <input type="checkbox" checked={!off} onChange={() => togglePiRule(r.id)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                      <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[r.sev] + "22", color: PI_SEV_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                      <span onClick={() => togglePiExpand(r.id)} style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, cursor: "pointer" }}>{groupLabel} {"\u2014"} {r.name}</span>
                      <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{r.technique}</span>
                      <span onClick={() => togglePiExpand(r.id)} style={{ fontSize: 9, color: expanded ? th.accent : th.textMuted, cursor: "pointer", padding: "0 2px", transform: expanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)", flexShrink: 0 }}>{"\u25BE"}</span>
                    </div>
                    {expanded && r.logic && (
                      <div style={{ margin: "2px 0 6px 28px", padding: "8px 12px", background: `${th.accent}06`, border: `1px solid ${th.accent}18`, borderRadius: 6 }}>
                        <div style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: "3px 10px", fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace" }}>
                          {r.logic.map((l, li) => (
                            <div key={li} style={{ display: "contents" }}>
                              <span style={{ color: th.textMuted, textTransform: "uppercase", fontSize: 9, fontWeight: 600, letterSpacing: "0.04em", paddingTop: 1 }}>{l.label}</span>
                              <span style={{ color: th.text, lineHeight: 1.5, wordBreak: "break-word" }}>{l.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Custom rules */}
	              {(modal.ptCustomRules || []).length > 0 && (
	                <div style={{ marginTop: 10 }}>
	                  <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
	                  {(modal.ptCustomRules || []).map((cr, i) => {
	                    const pattern = String(cr.pattern || "").trim();
	                    const ruleError = customRuleErrors.get(pattern) || validateCustomRulePattern(pattern);
	                    return (
	                      <div key={`custom-${i}`} style={{ padding: "3px 0" }}>
	                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
	                          <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[cr.severity || "medium"] + "22", color: PI_SEV_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
	                          <span style={{ fontSize: 11, color: ruleError ? th.danger : th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} {"\u2014"} {cr.name || "Custom Rule"}</span>
	                          {ruleError && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.danger}18`, color: th.danger, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>not active</span>}
	                          {cr.behavior && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "SF Mono, monospace", fontWeight: 600 }}>{cr.behavior}</span>}
	                          <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{cr.technique || ""}</span>
	                          <button onClick={() => deletePiCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>{"\u00D7"}</button>
	                        </div>
	                        {ruleError && (
	                          <div style={{ marginLeft: 60, marginTop: 2, fontSize: 9, color: th.danger, fontFamily: "-apple-system, sans-serif", lineHeight: 1.35 }}>
	                            Regex error: {ruleError}. This rule is skipped until fixed.
	                          </div>
	                        )}
	                      </div>
	                    );
	                  })}
	                </div>
	              )}

              {/* Add custom rule */}
              {!modal.ptAddingRule ? (
	                <button onClick={() => setModal(p => ({ ...p, ptAddingRule: true, ptNewRule: {}, ptNewRuleError: "" }))}
	                  style={{ ...ms.bsm, marginTop: 8, display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                </button>
              ) : (
                <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
	                    <input value={(modal.ptNewRule || {}).category || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, category: e.target.value }, ptNewRuleError: "" }))} placeholder="Category (e.g. Execution)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
	                    <input value={(modal.ptNewRule || {}).name || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, name: e.target.value }, ptNewRuleError: "" }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", borderColor: modal.ptNewRuleError === "Rule name is required." ? th.danger : undefined }} />
	                    <input value={(modal.ptNewRule || {}).technique || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, technique: e.target.value } }))} placeholder="MITRE Technique (e.g. T1059)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                    <select value={(modal.ptNewRule || {}).severity || "medium"} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, severity: e.target.value } }))}
                      style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
	                    <input value={(modal.ptNewRule || {}).pattern || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, pattern: e.target.value }, ptNewRuleError: "" }))} placeholder="Regex pattern for process/cmdline" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", borderColor: modal.ptNewRuleError && modal.ptNewRuleError !== "Rule name is required." ? th.danger : undefined }} />
                    <select value={(modal.ptNewRule || {}).behavior || ""} onChange={(e) => setModal(p => ({ ...p, ptNewRule: { ...p.ptNewRule, behavior: e.target.value || null } }))}
                      style={{ ...ms.sl, fontSize: 11, padding: "4px 8px", borderColor: !(modal.ptNewRule || {}).behavior ? th.sev.med : undefined }}>
                      <option value="">Behavior (recommended)</option>
                      <option value="script-exec">Script Execution</option>
                      <option value="shell-exec">Shell Execution</option>
                      <option value="lolbin-exec">LOLBin Execution</option>
                      <option value="service-exec">Service Execution</option>
                      <option value="cred">Credential Access</option>
                      <option value="evasion">Defense Evasion</option>
                      <option value="persist">Persistence</option>
                      <option value="lateral">Lateral Movement</option>
                      <option value="download">Download/Stage</option>
                      <option value="recon">Reconnaissance</option>
                      <option value="exfil">Exfiltration</option>
                      <option value="rmm">Remote Management</option>
                    </select>
	                  </div>
	                  {modal.ptNewRuleError && (
	                    <div style={{ fontSize: 10, color: th.danger, fontFamily: "-apple-system, sans-serif", marginTop: 6, padding: "6px 8px", border: `1px solid ${th.danger}33`, borderRadius: 6, background: `${th.danger}10` }}>
	                      {modal.ptNewRuleError}
	                    </div>
	                  )}
	                  {!(modal.ptNewRule || {}).behavior && (modal.ptNewRule || {}).name && (
                    <div style={{ fontSize: 9, color: th.sev.med, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                      Without a behavior tag this rule won{"'"}t participate in sequence detection.
                    </div>
	                  )}
	                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
	                    <button onClick={() => setModal(p => ({ ...p, ptAddingRule: false, ptNewRule: {}, ptNewRuleError: "" }))} style={ms.bsm}>Cancel</button>
                    <button onClick={addPiCustomRule} style={{ ...ms.bsm, background: th.primaryBtn || th.accent, color: "#fff", border: "none" }}>Add Rule</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 6i. Action Buttons */}
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
            <button onClick={() => setModal(null)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
            <button onClick={handleBuild} disabled={!hasCols} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: hasCols ? "pointer" : "not-allowed", background: hasCols ? (th.accent) : th.border, color: "#fff", border: "none", fontFamily: "-apple-system, sans-serif" }}>Build Tree</button>
          </div>
        </div>
        );
      })()}

      {/* Loading phase */}
      {phase === "loading" && (() => {
        const prog = modal.ptProgress || 0;
        const pi = modal.ptPhaseIdx || 0;
        const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
        return (
          <div style={{ padding: "50px 40px 40px", textAlign: "center", flex: 1 }}>
            <style>{`@keyframes ptPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" style={{ marginBottom: 16, animation: "ptPulse 1.5s ease-in-out infinite" }}>
              <rect x="3" y="10" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <rect x="14" y="3" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <rect x="14" y="16" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <path d="M8 12.5h3v-7h3M11 12.5v5.5h3" />
            </svg>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 4 }}>Building Process Tree</div>
              <div style={{ fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif", height: 16 }}>{ptPhases[pi]}</div>
            </div>
            <div style={{ width: 280, margin: "0 auto", height: 6, background: th.border + "33", borderRadius: 3, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, borderRadius: 3, transition: "width var(--m-slow) ease-out" }} />
            </div>
            <div style={{ fontSize: 11, color: th.textMuted, marginTop: 8, fontFamily: "SF Mono, Menlo, monospace" }}>{Math.round(prog)}%</div>
            <div style={{ marginTop: 24 }}>
              <button onClick={handleCancelBuild}
                style={{ padding: "4px 16px", fontSize: 11, background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
            </div>
          </div>
        );
      })()}

      {/* Results phase */}
      {phase === "results" && data && (() => {
        const ptViewMode = modal.ptViewMode || (_ptIncidentStories.length > 0 ? "story" : _ptChainClusters.some(c => c.level >= 3) ? "triage" : _ptChainClusters.some(c => c.level >= 2) ? "hunt" : "raw");
        const ptMode = PT_VIEW_MODES[ptViewMode] || PT_VIEW_MODES.raw;
        // Severity filter (toolbar): array of detection levels to show; empty = show all.
        const ptSevFilter = Array.isArray(modal.ptSevFilter) ? modal.ptSevFilter : [];
        const filteredClusters = (() => {
          let cls = [..._ptChainClusters];
          if (ptMode.filter === "suspicious") cls = cls.filter(c => c.level > 0);
          else if (ptMode.filter === "medium+") cls = cls.filter(c => c.level >= 2);
          if (ptSevFilter.length) cls = cls.filter(c => ptSevFilter.includes(c.level));
          const st = (searchText || "").toLowerCase();
          if (st) cls = cls.filter(c => c.reason.toLowerCase().includes(st) || c.hostname.toLowerCase().includes(st) || c.users.some(u => u.toLowerCase().includes(st)) || c.cmdVariants.some(cmd => cmd.toLowerCase().includes(st)));
          return cls;
        })();
        const filteredStories = (() => {
          let stories = [..._ptIncidentStories];
          if (ptMode.filter === "medium+") stories = stories.filter((s) => s.level >= 2);
          else if (ptMode.filter === "suspicious") stories = stories.filter((s) => s.level > 0);
          if (ptSevFilter.length) stories = stories.filter((s) => ptSevFilter.includes(s.level));
          const st = (searchText || "").toLowerCase().trim();
          if (st) stories = stories.filter((s) => s.searchBlob.includes(st));
          return stories;
        })();
        const filteredStats = {
          total: filteredClusters.length,
          critical: filteredClusters.filter(c => c.level === 3).length,
          high: filteredClusters.filter(c => c.level === 2).length,
          medium: filteredClusters.filter(c => c.level === 1).length,
          susProcesses: filteredClusters.reduce((s, c) => s + c.count, 0),
          hosts: new Set(filteredClusters.map(c => c.hostname).filter(Boolean)).size,
          users: new Set(filteredClusters.flatMap(c => c.users)).size,
        };
        const filteredStoryStats = {
          total: filteredStories.length,
          critical: filteredStories.filter((s) => s.level === 3).length,
          high: filteredStories.filter((s) => s.level === 2).length,
          medium: filteredStories.filter((s) => s.level === 1).length,
          susProcesses: filteredStories.reduce((sum, s) => sum + s.eventCount, 0),
          hosts: new Set(filteredStories.map((s) => s.hostname).filter(Boolean)).size,
          users: new Set(filteredStories.flatMap((s) => s.users)).size,
          sequences: filteredStories.reduce((sum, s) => sum + s.sequenceCount, 0),
        };
        const _ptPivotBtn = { padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 };
        const _ptSevLabel = (lv) => lv >= 3 ? "CRIT" : lv >= 2 ? "HIGH" : lv >= 1 ? "MED" : "LOW";
        const _ptSevPill = (color) => ({ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: color + "22", color, fontWeight: 600 });
        const _ptCopyStory = (story) => {
          const lines = [
            `[${_ptSevLabel(story.level)}] ${story.hostname ? `${story.hostname} — ` : ""}${story.leadReason}`,
            `Story: ${story.title}`,
            story.users.length ? `Users: ${story.users.join(", ")}` : null,
            story.firstSeen ? `Time: ${(story.firstSeen || "").slice(0, 19)}${story.lastSeen && story.lastSeen !== story.firstSeen ? ` — ${(story.lastSeen || "").slice(0, 19)}` : ""}` : null,
            `Suspicious Events: ${story.eventCount} | Context Events: ${story.contextEventCount || story.eventCount} | Chains: ${story.chainCount}${story.sequenceCount ? ` | Sequences: ${story.sequenceCount}` : ""}`,
            story.techniques.length ? `ATT&CK: ${story.techniques.join(", ")}` : null,
            `Narrative: ${story.narrative}`,
            "",
            "Storyline:",
            ...story.steps.map((step) => `  ${(step.ts || "").slice(0, 19) || "Unknown time"}  ${step.parent} -> ${step.child} — ${step.reason}${step.isContext ? " [context]" : ""}`),
          ].filter(Boolean);
          navigator.clipboard?.writeText?.(lines.join("\n"));
        };
        return (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
          {/* Toolbar: mode toggle + search + controls */}
          <div style={{ padding: "8px 20px", borderBottom: `1px solid ${th.border}55`, flexShrink: 0, display: "flex", alignItems: "center", gap: 8, background: `${th.headerBg}88`, backdropFilter: "blur(12px) saturate(1.3)", WebkitBackdropFilter: "blur(12px) saturate(1.3)" }}>
            {/* View mode toggle */}
            {Object.entries(PT_VIEW_MODES).map(([k, m]) => (
              <button key={k} onClick={() => setModal(p => ({ ...p, ptViewMode: k, _ptExpandedCluster: null, _ptExpandedIncident: null, ptClusterKeys: m.clustered ? null : p.ptClusterKeys, ptClusterContext: m.clustered ? false : p.ptClusterContext }))} title={m.incident ? `${m.label}: grouped into investigation stories` : m.clustered ? `${m.label}: clustered by chain` : `${m.label}: full tree view`}
                style={{ padding: "4px 10px", fontSize: 10, fontWeight: ptViewMode === k ? 700 : 500, background: ptViewMode === k ? th.accent : `${th.accent}15`, color: ptViewMode === k ? "#fff" : th.accent, border: `1px solid ${ptViewMode === k ? th.accent : th.accent + "33"}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>{m.label}</button>
            ))}
            <div style={{ width: 1, height: 16, background: th.border, flexShrink: 0 }} />
            <input value={searchText || ""} onChange={(e) => setModal((p) => ({ ...p, searchText: e.target.value }))} placeholder={ptMode.incident ? "Search stories by host, user, ATT&CK, process, or reason..." : ptMode.clustered ? "Search chains by name, host, user, command..." : "Search by process name, PID, command line, or user..."} style={{ flex: 1, background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 6, padding: "6px 10px", fontSize: 12, fontFamily: "monospace", outline: "none", boxSizing: "border-box" }} />
            {!ptMode.clustered && <button onClick={expandAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Expand all nodes">Expand All</button>}
            {!ptMode.clustered && <button onClick={collapseAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Collapse all nodes">Collapse</button>}
            {!ptMode.clustered && <button onClick={() => setModal((p) => p ? { ...p, ptDensity: p.ptDensity === "compact" ? undefined : "compact" } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.ptDensity === "compact" ? (th.accent) + "22" : th.btnBg, color: modal.ptDensity === "compact" ? th.accent : th.textDim, border: `1px solid ${modal.ptDensity === "compact" ? (th.accent) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.ptDensity === "compact" ? 600 : 400 }} title="Toggle compact row height">{modal.ptDensity === "compact" ? "Compact" : "Comfortable"}</button>}
            {!ptMode.clustered && <select onChange={(e) => { if (e.target.value) expandToDepth(parseInt(e.target.value)); }} value="" style={{ padding: "4px 4px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.bgInput, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>
              <option value="">Depth...</option>
              {[1, 2, 3, 4, 5].filter((d) => d <= (data.stats.maxDepth || 5)).map((d) => <option key={d} value={d}>Depth {d}</option>)}
            </select>}
            {!ptMode.clustered && <button onClick={() => setModal((p) => p ? { ...p, susOnlyFilter: !p.susOnlyFilter } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.susOnlyFilter ? (th.danger) + "22" : th.btnBg, color: modal.susOnlyFilter ? (th.danger) : th.textDim, border: `1px solid ${modal.susOnlyFilter ? (th.danger) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.susOnlyFilter ? 600 : 400 }} title="Show only suspicious processes">{modal.susOnlyFilter ? "\u26A0 Suspicious Only" : "Suspicious Only"}</button>}
            <div style={{ display: "flex", gap: 2, alignItems: "center", flexShrink: 0 }} title="Filter by detection severity (toggle; none selected = show all)">
              <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginRight: 1 }}>Sev</span>
              {[{ v: 3, l: "Crit" }, { v: 2, l: "High" }, { v: 1, l: "Med" }].map(({ v, l }) => {
                const on = ptSevFilter.includes(v);
                const col = SUS_COLORS[v] || th.danger;
                return <button key={v} onClick={() => setModal((p) => { const cur = Array.isArray(p.ptSevFilter) ? p.ptSevFilter : []; const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]; return { ...p, ptSevFilter: next.length ? next : undefined }; })} style={{ padding: "4px 7px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: on ? col + "22" : th.btnBg, color: on ? col : th.textDim, border: `1px solid ${on ? col + "66" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: on ? 700 : 400 }}>{l}</button>;
              })}
            </div>
            {!ptMode.clustered && selectedKey && <button onClick={() => setModal((p) => p ? { ...p, selectedKey: null } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${(th.accent)}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Clear Chain</button>}
            {!ptMode.clustered && modal.ptClusterKeys && <button onClick={() => setModal((p) => p ? { ...p, ptClusterKeys: null, ptClusterContext: false } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${(th.accent)}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: 600 }}>{"\u2716"} Cluster ({modal.ptClusterKeys.size})</button>}
            {!ptMode.clustered && modal.ptClusterKeys && <button onClick={() => setModal((p) => p ? { ...p, ptClusterContext: !p.ptClusterContext } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.ptClusterContext ? (th.accent) + "22" : th.btnBg, color: modal.ptClusterContext ? (th.accent) : th.textDim, border: `1px solid ${modal.ptClusterContext ? (th.accent) + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.ptClusterContext ? 600 : 400 }}>{modal.ptClusterContext ? "Tree Context" : "Flat View"}</button>}
            {/* Separator */}
            <div style={{ width: 1, height: 16, background: th.border, flexShrink: 0 }} />
            {/* Raw mode: Copy Chain / Tree / CSV / Selected */}
            {!ptMode.clustered && selectedKey && <button onClick={() => {
              const lines = [];
              const chain = [];
              let cur = selectedKey;
              // Walk real ancestors via the shared guard so Copy Chain never splices an
              // unrelated process onto the chain through a PID-reuse mislinked edge.
              while (cur && byKeyMap.has(cur)) { const n = byKeyMap.get(cur); chain.unshift(n); cur = consistentParentKey(n, byKeyMap); }
              chain.forEach((n, i) => {
                const indent = "  ".repeat(i);
                const prefix = i === 0 ? "" : "\u2514\u2500 ";
                lines.push(`${indent}${prefix}${n.processName} (PID: ${n.pid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                if (n.cmdLine) lines.push(`${indent}   ${n.cmdLine}`);
              });
              navigator.clipboard?.writeText?.(lines.join("\n"));
            }} title="Copy ancestry chain to clipboard" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.accent, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Chain</button>}
            {!ptMode.clustered && <button onClick={() => {
              const lines = [];
              flatNodes.forEach((n) => {
                const indent = "  ".repeat(n.depth);
                const connector = n.depth > 0 ? (n.isLast ? "\u2514\u2500 " : "\u251C\u2500 ") : "";
                lines.push(`${indent}${connector}${n.processName} (PID: ${n.pid}, PPID: ${n.ppid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                if (n.cmdLine) lines.push(`${indent}${n.depth > 0 ? "   " : ""}  ${n.cmdLine}`);
              });
              navigator.clipboard?.writeText?.(lines.join("\n"));
            }} title="Copy visible tree as text" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Tree</button>}
            {!ptMode.clustered && <button onClick={() => {
              // Resolve parent name/path via the relinked tree when the row carries no
              // ParentImage — Security 4688 has none, EvtxECmd lacks a clean column.
              const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
              const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	              const header = ["Hostname", "LinkSource", "LinkConfidence", "LinkReason", "ParentProcessName", "ParentImagePath", "ProcessName", "PID", "PPID", "User", "Timestamp", "ImagePath", "CommandLine", "Provider", "EventID", "Elevation", "Integrity", "Depth"].join("\t");
	              const rows = flatNodes.map((n) => [
	                n.hostname || "", ptLinkMeta(n).source, ptLinkMeta(n).confidence, ptLinkMeta(n).link.reason || "", _parentNameFor(n), _parentImageFor(n), n.processName, n.pid, n.ppid, n.user || "", n.ts || "", n.image || "", n.cmdLine || "",
	                n.provider || "", n.eventId || "", n.elevation || "", n.integrity || "", n.depth
	              ].join("\t"));
	              navigator.clipboard?.writeText?.([header, ...rows].join("\n"));
	            }} title="Copy as tab-separated CSV" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy CSV</button>}
	            {!ptMode.clustered && ptCheckedCount > 0 && <button onClick={() => {
	              const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
	              const header = ["Timestamp", "Detection", "LinkSource", "LinkConfidence", "LinkReason", "Provider", "EventID", "ParentProcess", "Process", "PID", "PPID", "User", "CommandLine", "ImagePath", "Integrity"].join("\t");
	              const rows = flatNodes.filter((n) => ptChecked.has(n.key)).map((n) => {
	                const det = (_ptDetMap.get(n.key) || {}).reason || "";
	                const lm = ptLinkMeta(n);
	                return [n.ts || "", det, lm.source, lm.confidence, lm.link.reason || "", _providerShort(n.provider), n.eventId || "", _parentNameFor(n), n.processName, n.pid, n.ppid, n.user || "", n.cmdLine || "", n.image || "", _integrityShort(n.integrity)].join("\t");
	              });
	              navigator.clipboard?.writeText?.([header, ...rows].join("\n"));
	            }} title="Copy selected rows as tab-separated" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${th.accent}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: 600 }}>Copy Selected ({ptCheckedCount})</button>}
            {/* Download CSV / JSON */}
            {!ptMode.clustered && <>
              <div style={{ width: 1, height: 14, background: th.border, flexShrink: 0 }} />
              <button onClick={() => {
                const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
                const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	                const rows = flatNodes.map((n) => {
	                  const det = _ptDetMap.get(n.key) || {};
	                  const lm = ptLinkMeta(n);
	                  return { Timestamp: n.ts || "", Hostname: n.hostname || "", Detection: det.reason || "", Severity: det.level >= 3 ? "Critical" : det.level >= 2 ? "High" : det.level >= 1 ? "Medium" : "", TriageScore: det.triageScore || "", Prevalence: det.prevalence?.rarity || "", PrevalenceSignals: det.prevalence?.signals?.join("; ") || "", LinkSource: lm.source, LinkConfidence: lm.confidence, LinkReason: lm.link.reason || "", LinkWarnings: lm.warnings.join("; "), ParentProcess: _parentNameFor(n), ParentImagePath: _parentImageFor(n), Process: n.processName || "", PID: n.pid ?? "", PPID: n.ppid ?? "", User: n.user || "", CommandLine: n.cmdLine || "", ImagePath: n.image || "", Provider: n.provider || "", EventID: n.eventId || "", Integrity: n.integrity || "" };
	                });
	                _downloadFile(_toCSV(rows), "process-inspector.csv", "text/csv");
	              }} title="Download process tree as CSV" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>↓ CSV</button>
              <button onClick={() => {
                const _parentNameFor = (n) => n.parentProcessName || byKeyMap.get(n.parentKey)?.processName || "";
                const _parentImageFor = (n) => n.parentImage || byKeyMap.get(n.parentKey)?.image || "";
	                const rows = flatNodes.map((n) => {
	                  const det = _ptDetMap.get(n.key) || {};
	                  return { timestamp: n.ts, hostname: n.hostname, detection: det.reason || null, severity: det.level >= 3 ? "critical" : det.level >= 2 ? "high" : det.level >= 1 ? "medium" : null, triageScore: det.triageScore || 0, prevalence: det.prevalence || null, behaviors: det.behaviors || [], link: n.link || null, parentProcess: _parentNameFor(n), parentImagePath: _parentImageFor(n), process: n.processName, pid: n.pid, ppid: n.ppid, user: n.user, commandLine: n.cmdLine, imagePath: n.image, provider: n.provider, eventId: n.eventId, integrity: n.integrity };
	                });
                _downloadFile(JSON.stringify({ exportedAt: new Date().toISOString(), processes: rows }, null, 2), "process-inspector.json", "application/json");
              }} title="Download process tree as JSON" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textMuted, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>↓ JSON</button>
            </>}
            {/* Clustered mode: Copy Chains */}
            {ptMode.clustered && <button onClick={() => {
              if (ptMode.incident) {
                navigator.clipboard?.writeText?.(filteredStories.map((s) => {
                  const lines = [
                    `[${_ptSevLabel(s.level)}] ${s.hostname ? `${s.hostname} — ` : ""}${s.leadReason}`,
                    `  Story: ${s.title}`,
                    `  Users: ${s.users.join(", ") || "—"}`,
                    `  Time: ${(s.firstSeen || "").slice(0, 19)}${s.lastSeen && s.lastSeen !== s.firstSeen ? ` — ${(s.lastSeen || "").slice(0, 19)}` : ""}`,
                    `  Events: ${s.eventCount} | Chains: ${s.chainCount}${s.sequenceCount ? ` | Sequences: ${s.sequenceCount}` : ""}`,
                  ];
                  return lines.join("\n");
                }).join("\n\n"));
                return;
              }
              navigator.clipboard?.writeText?.(filteredClusters.map(c => {
                const sev = c.level >= 3 ? "CRITICAL" : c.level >= 2 ? "HIGH" : "MEDIUM";
                return `[${sev}] ${c.reason}\n  Host: ${c.hostname} | Users: ${c.users.join(", ")}\n  Time: ${(c.firstSeen||"").slice(0,19)} \u2014 ${(c.lastSeen||"").slice(0,19)} | Count: ${c.count}\n  Cmd variants: ${c.cmdVariants.length}`;
              }).join("\n\n"));
            }} title={ptMode.incident ? "Copy all visible stories" : "Copy all visible chains"} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>{ptMode.incident ? "Copy Stories" : "Copy Chains"}</button>}
          </div>

          {_ptPrevalenceSummary.items.length > 0 && (
            <div style={{ padding: "7px 20px", borderBottom: `1px solid ${th.border}44`, background: `${th.modalBg}aa`, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", flexShrink: 0 }}>
              <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700 }}>Rare Processes</span>
              <span style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>
                {_ptPrevalenceSummary.stats.rare.toLocaleString()} rare
                {_ptPrevalenceSummary.stats.uncommon ? ` · ${_ptPrevalenceSummary.stats.uncommon.toLocaleString()} uncommon` : ""}
                {_ptPrevalenceSummary.stats.rareDetected ? ` · ${_ptPrevalenceSummary.stats.rareDetected.toLocaleString()} detected` : ""}
              </span>
              {_ptPrevalenceSummary.items.slice(0, 5).map((item) => {
                const color = item.rarity === "rare" ? th.accent : th.textMuted;
                const reason = item.detectionReasons[0] || item.signals[0] || item.rarity;
                return (
                  <button key={item.key} onClick={() => setModal((p) => p ? { ...p, ptViewMode: "raw", selectedKey: item.key, ptClusterKeys: null, ptClusterContext: false } : p)}
                    title={[item.image, item.sampleCommandLine, ...item.signals].filter(Boolean).join("\n")}
                    style={{ maxWidth: 260, minWidth: 0, padding: "3px 7px", borderRadius: 4, border: `1px solid ${color}33`, background: `${color}12`, color, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.processName}</span>
                    <span style={{ opacity: 0.75, flexShrink: 0 }}>{item.rarity}</span>
                    {item.maxDetectionLevel > 0 && <span style={{ opacity: 0.8, flexShrink: 0 }}>detected</span>}
                    {reason && <span style={{ opacity: 0.65, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 500 }}>{reason}</span>}
                  </button>
                );
              })}
              <button onClick={() => setModal((p) => p ? { ...p, ptViewMode: "raw", ptClusterKeys: null, ptClusterContext: false, ptColFilters: { ...(p.ptColFilters || {}), Prevalence: ["rare"] } } : p)} style={_ptPivotBtn}>Show Rare Only</button>
            </div>
          )}

          {/* Event Timeline — interactive dots */}
          {(() => {
            const times = flatNodes.filter(n => n.ts).map(n => ({ t: normalizeTimestamp(n.ts), key: n.key })).filter(d => Number.isFinite(d.t));
            if (times.length < 2) return null;
            const tVals = times.map(d => d.t);
            const tMin = Math.min(...tVals.slice(0, 10000));
            const tMax = Math.max(...tVals.slice(0, 10000));
            if (tMin === tMax) return null;
            const range = tMax - tMin || 1;
            // Limit dots to first 500 for rendering performance
            const dotEvents = times.slice(0, 500);
            return (
              <div style={{ padding: "8px 20px 4px", borderBottom: `1px solid ${th.border}44`, background: `${th.modalBg}99`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "'SF Mono', Menlo, monospace" }}>Event Timeline</div>
                <div style={{ position: "relative", height: 40, background: `${th.bgInput}99`, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}55` }}>
                  {/* Time axis labels */}
                  {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
                    const t = new Date(tMin + range * pct);
                    return <span key={pct} style={{ position: "absolute", bottom: 2, left: `${pct * 100}%`, transform: "translateX(-50%)", fontSize: 8, color: th.textMuted + "88", fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "nowrap" }}>{t.toISOString().substr(11, 8)}</span>;
                  })}
                  {/* Event dots */}
                  {dotEvents.map((d) => {
                    const left = ((d.t - tMin) / range) * 100;
                    const nd = byKeyMap.get(d.key);
                    const pnd = nd ? byKeyMap.get(nd.parentKey) : null;
                    const isSus = nd ? (_ptDetMap.get(nd.key) || {level:0}).level > 0 : false;
                    const isSel = d.key === selectedKey;
                    return <div key={d.key} onClick={(e) => { e.stopPropagation(); setModal((p) => p ? { ...p, selectedKey: d.key } : p); }}
                      title={nd ? `${nd.processName} (PID: ${nd.pid}) \u2014 ${nd.ts}` : ""}
                      style={{ position: "absolute", left: `${left}%`, top: "38%", transform: "translate(-50%, -50%)", width: isSel ? 12 : 8, height: isSel ? 12 : 8, borderRadius: "50%", background: isSus ? (th.danger) : isSel ? (th.accent) : (th.success), border: isSel ? "2px solid #fff" : `1px solid rgba(255,255,255,0.2)`, cursor: "pointer", transition: "all var(--m-base) ease", boxShadow: isSus ? `0 0 8px ${th.danger}66` : isSel ? `0 0 8px ${th.accent}55` : "none", zIndex: isSel ? 10 : isSus ? 5 : 1 }} />;
                  })}
                </div>
              </div>
            );
          })()}

          {/* Overview strip (raw view): at-a-glance counts; severity chips toggle the severity filter */}
          {!ptMode.clustered && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 14px", borderTop: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}66`, fontSize: 10, fontFamily: "-apple-system, sans-serif", flexShrink: 0, flexWrap: "wrap" }}>
              <span style={{ color: th.textMuted, fontWeight: 600 }}>{_ptSevCounts.total.toLocaleString()} processes</span>
              {[{ v: 3, l: "critical", n: _ptSevCounts.crit }, { v: 2, l: "high", n: _ptSevCounts.high }, { v: 1, l: "medium", n: _ptSevCounts.med }].map(({ v, l, n }) => {
                if (!n) return null;
                const col = SUS_COLORS[v] || th.danger;
                const on = ptSevFilter.includes(v);
                return (
                  <span key={v} onClick={() => setModal((p) => { const cur = Array.isArray(p.ptSevFilter) ? p.ptSevFilter : []; const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]; return { ...p, ptSevFilter: next.length ? next : undefined }; })}
                    title={`Click to ${on ? "clear" : "show only"} ${l}`}
                    style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 10, cursor: "pointer", background: on ? col + "2a" : col + "12", color: col, border: `1px solid ${col}${on ? "88" : "33"}`, fontWeight: on ? 700 : 500, transition: "all var(--m-base)" }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: col }} />{n.toLocaleString()} {l}
                  </span>
                );
              })}
              <span style={{ color: th.textMuted, marginLeft: "auto", fontFamily: "'SF Mono', Menlo, monospace", fontSize: 9 }}>{_ptSevCounts.susTotal.toLocaleString()} suspicious · {_ptSevCounts.hosts} host{_ptSevCounts.hosts !== 1 ? "s" : ""} · {_ptSevCounts.users} user{_ptSevCounts.users !== 1 ? "s" : ""}</span>
            </div>
          )}

          {/* Main content: clustered card view OR tree + detail panel */}
          {ptMode.clustered ? (
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
            {/* Scrollable card list */}
            <div style={{ flex: 1, overflowY: "auto", padding: "8px 20px" }}>
              {ptMode.incident ? (
                <>
                  <div style={{ padding: "8px 14px", marginBottom: 8, background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ fontWeight: 700, color: th.text }}>{filteredStories.length} stor{filteredStories.length !== 1 ? "ies" : "y"}</span>
                    {filteredStoryStats.critical > 0 && <span style={_ptSevPill(th.sev.critical)}>{filteredStoryStats.critical} critical</span>}
                    {filteredStoryStats.high > 0 && <span style={_ptSevPill(th.sev.high)}>{filteredStoryStats.high} high</span>}
                    {filteredStoryStats.medium > 0 && <span style={_ptSevPill(th.sev.med)}>{filteredStoryStats.medium} medium</span>}
                    <span style={{ color: th.textMuted }}>|</span>
                    <span style={{ color: th.textDim }}>{filteredStoryStats.susProcesses} suspicious events</span>
                    {filteredStoryStats.sequences > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.sequences} sequence hits</span>}
                    {filteredStoryStats.hosts > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.hosts} host{filteredStoryStats.hosts !== 1 ? "s" : ""}</span>}
                    {filteredStoryStats.users > 0 && <span style={{ color: th.textDim }}>{filteredStoryStats.users} user{filteredStoryStats.users !== 1 ? "s" : ""}</span>}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {filteredStories.map((story) => {
                      const isExp = modal._ptExpandedIncident === story.id;
                      const susColor = SUS_COLORS[story.level] || th.textMuted;
                      return (
                        <div key={story.id} style={{ borderRadius: 8, border: `1px solid ${susColor}${isExp ? "44" : "22"}`, background: `${susColor}${isExp ? "0c" : "04"}`, cursor: "pointer", transition: "border-color var(--m-base)" }}
                          onClick={() => setModal((p) => ({ ...p, _ptExpandedIncident: isExp ? null : story.id, selectedKey: story.anchorKey || p.selectedKey }))}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 10px", minHeight: 34, flexWrap: "wrap" }}>
                            <span style={{ padding: "1px 6px", background: susColor + "22", color: susColor, borderRadius: 3, fontSize: 8, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{_ptSevLabel(story.level)}</span>
                            <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{story.title}</span>
                            <span style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={story.narrative}>{story.leadReason}</span>
                            {story.hostname && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{story.hostname}</span>}
	                            {story.users.length > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{story.users[0]}{story.users.length > 1 ? ` +${story.users.length - 1}` : ""}</span>}
	                            {story.prevalenceSignals?.length > 0 && <span title={story.prevalenceSignals.join("\n")} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.accent + "18", color: th.accent, fontWeight: 600, flexShrink: 0 }}>rare</span>}
	                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0 }}>{story.eventCount} suspicious</span>
                            {story.contextOnlyCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontWeight: 500, flexShrink: 0 }}>{story.contextEventCount} with context</span>}
                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{story.chainCount} chains{story.sequenceCount ? ` · ${story.sequenceCount} seq` : ""}</span>
                            {story.durationLabel && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{story.durationLabel}</span>}
                            <span style={{ fontSize: 8, color: th.textMuted, flexShrink: 0 }}>{isExp ? "\u25BC" : "\u25B6"}</span>
                          </div>
                          {isExp && (
                            <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${susColor}22` }} onClick={(e) => e.stopPropagation()}>
                              <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                                <span>{story.hostname}{story.users.length ? ` (${story.users.join(", ")})` : ""}</span>
                                <span>{(story.firstSeen || "").slice(0, 19)}{story.lastSeen && story.lastSeen !== story.firstSeen ? ` \u2014 ${(story.lastSeen || "").slice(0, 19)}` : ""}</span>
                                <span>{story.eventCount} suspicious event{story.eventCount !== 1 ? "s" : ""}</span>
                                {story.contextOnlyCount > 0 && <span>{story.contextEventCount} total in context</span>}
	                                {story.rootNames.length > 0 && <span>Roots: {story.rootNames.slice(0, 2).join(", ")}{story.rootNames.length > 2 ? ` +${story.rootNames.length - 2}` : ""}</span>}
	                                {story.prevalenceSignals?.length > 0 && <span>Prevalence: {story.prevalenceSignals.slice(0, 2).join(", ")}{story.prevalenceSignals.length > 2 ? ` +${story.prevalenceSignals.length - 2}` : ""}</span>}
	                              </div>
                              <div style={{ marginBottom: 8, fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                                {story.narrative}
                              </div>
                              {story.steps.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Storyline</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                                    {story.steps.map((step) => (
                                      <div key={step.key} onClick={() => setModal((p) => ({ ...p, selectedKey: step.key }))}
                                        style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", color: th.textDim, padding: "3px 5px", borderRadius: 4, background: step.key === selectedKey ? `${th.accent}15` : `${th.border}10`, cursor: "pointer", border: step.key === selectedKey ? `1px solid ${th.accent}33` : `1px solid ${th.border}11` }}>
                                        <span style={{ minWidth: 126, color: th.textMuted, flexShrink: 0 }}>{(step.ts || "").slice(0, 19) || "Unknown time"}</span>
                                        <span style={{ color: th.text, flexShrink: 0 }}>{step.parent} {"\u2192"} {step.child}</span>
                                        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{step.reason}</span>
                                        {step.isContext && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontWeight: 600, flexShrink: 0 }}>CTX</span>}
                                        {step.sequences?.length > 0 && <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontWeight: 600, flexShrink: 0 }}>{step.sequences[0]}</span>}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {story.sequences.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Behavioral Sequences</div>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {story.sequences.map((seq) => (
                                      <span key={seq.seqId} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${seq.confidence === "high" ? th.sev.critical : th.sev.high}18`, color: seq.confidence === "high" ? th.sev.critical : th.sev.high, border: `1px solid ${seq.confidence === "high" ? th.sev.critical : th.sev.high}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                        {seq.name} {seq.count > 1 ? `(${seq.count})` : ""}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {story.techniques.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>ATT&CK</div>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {story.techniques.map((tid) => ptMitreBadge(tid))}
                                  </div>
                                </div>
                              )}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(story.allKeys), ptClusterContext: false, selectedKey: story.anchorKey || p.selectedKey }))} style={_ptPivotBtn}>View Flat</button>
                                <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(story.contextKeys || story.allKeys), ptClusterContext: true, selectedKey: story.anchorKey || p.selectedKey }))} style={_ptPivotBtn}>View in Context</button>
                                <button onClick={() => _ptCopyStory(story)} style={_ptPivotBtn}>Copy Story</button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {filteredStories.length === 0 && (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12 }}>
                        No investigation stories built from current detections
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <>
                  {/* Summary strip */}
                  <div style={{ padding: "8px 14px", marginBottom: 8, background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ fontWeight: 700, color: th.text }}>{filteredClusters.length} chain{filteredClusters.length !== 1 ? "s" : ""}</span>
                    {filteredStats.critical > 0 && <span style={_ptSevPill(th.sev.critical)}>{filteredStats.critical} critical</span>}
                    {filteredStats.high > 0 && <span style={_ptSevPill(th.sev.high)}>{filteredStats.high} high</span>}
                    {filteredStats.medium > 0 && <span style={_ptSevPill(th.sev.med)}>{filteredStats.medium} medium</span>}
                    <span style={{ color: th.textMuted }}>|</span>
                    <span style={{ color: th.textDim }}>{filteredStats.susProcesses} suspicious events</span>
                    {filteredStats.hosts > 0 && <span style={{ color: th.textDim }}>{filteredStats.hosts} host{filteredStats.hosts !== 1 ? "s" : ""}</span>}
                    {filteredStats.users > 0 && <span style={{ color: th.textDim }}>{filteredStats.users} user{filteredStats.users !== 1 ? "s" : ""}</span>}
                  </div>
                  {/* Cluster cards */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {filteredClusters.map(cl => {
                      const isExp = modal._ptExpandedCluster === cl.id;
                      const susColor = SUS_COLORS[cl.level] || th.textMuted;
                      return (
                        <div key={cl.id} style={{ borderRadius: 6, border: `1px solid ${susColor}${isExp ? "44" : "22"}`, background: `${susColor}${isExp ? "0a" : "04"}`, cursor: "pointer", transition: "border-color var(--m-base)" }}
                          onClick={() => setModal(p => ({ ...p, _ptExpandedCluster: isExp ? null : cl.id, selectedKey: cl.members[0]?.key || p.selectedKey }))}>
                          {/* Collapsed summary row */}
                          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", minHeight: 28, flexWrap: "wrap" }}>
                            <span style={{ padding: "1px 6px", background: susColor + "22", color: susColor, borderRadius: 3, fontSize: 8, fontWeight: 700, textTransform: "uppercase", fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{_ptSevLabel(cl.level)}</span>
                            {cl.mitreId && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 600, fontFamily: "SF Mono, monospace", flexShrink: 0 }}>{cl.mitreId}</span>}
                            <span style={{ fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>{cl.displayParent} {"\u2192"} {cl.displayChild}</span>
                            <span style={{ fontSize: 11, fontWeight: 500, color: th.textDim, fontFamily: "-apple-system, sans-serif", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cl.displayReason}>{cl.displayReason}</span>
                            {cl.cmdTemplate && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }} title={cl.cmdTemplate}>{cl.cmdTemplate}</span>}
                            {cl.hostname && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{cl.hostname}</span>}
	                            {cl.count > 1 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0 }}>{cl.count}x</span>}
	                            {(cl.rareCount > 0 || cl.uncommonCount > 0) && <span title={(cl.prevalenceSignals || []).join("\n")} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.accent + "18", color: th.accent, fontWeight: 600, flexShrink: 0 }}>{cl.rareCount > 0 ? `${cl.rareCount} rare` : `${cl.uncommonCount} uncommon`}</span>}
	                            {cl.users.length > 1 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontWeight: 500, flexShrink: 0 }}>{cl.users.length} users</span>}
                            <span style={{ fontSize: 8, color: th.textMuted, flexShrink: 0 }}>{isExp ? "\u25BC" : "\u25B6"}</span>
                          </div>
                          {/* Expanded detail */}
                          {isExp && (
                            <div style={{ padding: "8px 10px 10px", borderTop: `1px solid ${susColor}22` }} onClick={e => e.stopPropagation()}>
                              {/* Meta row */}
                              <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
                                <span>{cl.hostname}{cl.users.length > 0 ? ` (${cl.users.join(", ")})` : ""}</span>
	                                <span>{(cl.firstSeen || "").slice(0, 19)}{cl.lastSeen && cl.lastSeen !== cl.firstSeen ? ` \u2014 ${cl.lastSeen.slice(0, 19)}` : ""}</span>
	                                <span>{cl.count} occurrence{cl.count !== 1 ? "s" : ""}</span>
	                                {cl.prevalenceSignals?.length > 0 && <span>Prevalence: {cl.prevalenceSignals.slice(0, 2).join(", ")}{cl.prevalenceSignals.length > 2 ? ` +${cl.prevalenceSignals.length - 2}` : ""}</span>}
	                              </div>
                              {/* Command variants */}
                              {cl.cmdVariants.length > 0 && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>Command Variants ({cl.cmdVariants.length})</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 100, overflowY: "auto" }}>
                                    {cl.cmdVariants.map((cmd, ci) => (
                                      <div key={ci} style={{ fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: th.danger, padding: "2px 4px", borderRadius: 3, background: `${th.accent}08`, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cmd}>{cmd}</div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {/* All occurrences */}
                              {cl.count > 1 && (() => {
                                const showLimit = modal._ptClusterShowAll === cl.id ? cl.members.length : 50;
                                const visible = cl.members.slice(0, showLimit);
                                const hasMore = cl.members.length > showLimit;
                                const hasHidden = cl.count > cl.members.length;
                                return (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "-apple-system, sans-serif" }}>All Occurrences{cl.count > visible.length ? ` (showing ${visible.length} of ${cl.count})` : ""}</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 1, maxHeight: modal._ptClusterShowAll === cl.id ? 400 : 150, overflowY: "auto" }}>
                                    {visible.map((m, mi) => (
                                      <div key={m.key} onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, selectedKey: m.key })); }}
                                        style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: th.textDim, padding: "2px 4px", borderRadius: 3, background: m.key === selectedKey ? `${th.accent}15` : mi % 2 === 0 ? "transparent" : `${th.border}11`, cursor: "pointer", border: m.key === selectedKey ? `1px solid ${th.accent}33` : "1px solid transparent" }}>
                                        <span style={{ minWidth: 130, color: th.textMuted, flexShrink: 0 }}>{(m.ts || "").slice(0, 19)}</span>
                                        <span style={{ minWidth: 70, flexShrink: 0 }}>{m.user || ""}</span>
                                        <span style={{ color: th.text, flexShrink: 0 }}>{m.parentProcessName} {"\u2192"} {m.processName}</span>
                                        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textMuted }}>{m.cmdLine || ""}</span>
                                      </div>
                                    ))}
                                  </div>
                                  {(hasMore || hasHidden) && (
                                    <div style={{ display: "flex", gap: 4, marginTop: 4 }}>
                                      {hasMore && <button onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, _ptClusterShowAll: cl.id })); }} style={_ptPivotBtn}>Show All ({cl.members.length})</button>}
                                      {hasHidden && <button onClick={e => { e.stopPropagation(); setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: true, selectedKey: cl.members[0]?.key || p.selectedKey })); }} style={_ptPivotBtn}>View All {cl.count} in Context</button>}
                                    </div>
                                  )}
                                </div>
                                );
                              })()}
                              {/* Pivot buttons */}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={() => setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: false, selectedKey: cl.members[0]?.key || p.selectedKey }))} style={_ptPivotBtn}>View Flat</button>
                                <button onClick={() => setModal(p => ({ ...p, ptViewMode: "raw", searchText: "", susOnlyFilter: false, ptColFilters: {}, ptClusterKeys: new Set(cl.allKeys), ptClusterContext: true, selectedKey: cl.members[0]?.key || p.selectedKey }))} style={_ptPivotBtn}>View in Context</button>
                                <button onClick={() => {
                                  const sev = cl.level >= 3 ? "CRITICAL" : cl.level >= 2 ? "HIGH" : "MEDIUM";
                                  const lines = [`[${sev}] ${cl.reason}`, `Host: ${cl.hostname}`, `Users: ${cl.users.join(", ")}`, `Time: ${(cl.firstSeen || "").slice(0, 19)} \u2014 ${(cl.lastSeen || "").slice(0, 19)}`, `Occurrences: ${cl.count}`, "", "Command Variants:", ...cl.cmdVariants.map(c => `  ${c}`)];
                                  navigator.clipboard?.writeText?.(lines.join("\n"));
                                }} style={_ptPivotBtn}>Copy IOC</button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {filteredClusters.length === 0 && (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12 }}>
                        No suspicious chains found{ptViewMode === "triage" ? " \u2014 try Hunt or Raw mode" : ""}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
            {/* Right detail panel — reused for selected member node */}
            {(() => {
              const detailW = modal.ptDetailW || 380;
              const selNode = selectedKey ? byKeyMap.get(selectedKey) : null;
              if (!selNode) return (
                <div style={{ width: detailW, borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, flexShrink: 0, display: "flex", flexDirection: "column" }}>
                  <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}88`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace" }}>Event Details</div>
                  <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12 }}>Click an occurrence to view details</div>
                </div>
              );
	              const parentNode = byKeyMap.get(selNode.parentKey);
	              const selSusInfo = _ptDetMap.get(selectedKey) || { level: 0, reason: null };
	              const selSusColor = SUS_COLORS[selSusInfo.level];
	              const selLink = ptLinkMeta(selNode);
	              const selPrev = selSusInfo.prevalence || null;
	              const nodeCluster = _ptNodeClusterMap.get(selectedKey);
              const gLbl = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 };
              const gVal = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12, color: th.text, wordBreak: "break-all", lineHeight: 1.5 };
              const fields = [
                ["Timestamp", selNode.ts ? selNode.ts.replace("T", " ").substring(0, 19) : ""],
                ["Process", selNode.processName], ["Full Path", selNode.image],
	                ["PID", selNode.pid], ["PPID", selNode.ppid],
	                ["Parent", parentNode ? parentNode.processName : ""],
	                ["Parent Link", `${selLink.label}${selLink.confidence ? ` (${selLink.confidence})` : ""}`],
	                ["Link Reason", selLink.link.reason],
	                ["Link Warnings", selLink.warnings.join(", ")],
	                ["Prevalence", selPrev ? `${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : ""],
	                ["Prevalence Signals", selPrev?.signals?.join(", ")],
	                ["User", selNode.user], ["Command Line", selNode.cmdLine],
                ["Provider", _providerShort(selNode.provider)], ["Event ID", selNode.eventId],
              ].filter(([, v]) => v);
              return (
                <div style={{ width: detailW, borderLeft: selSusInfo.level >= 2 ? `3px solid ${selSusColor}` : `1px solid ${th.border}44`, background: `${th.modalBg}cc`, flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                  <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}aa`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>Event Details</div>
                  <div style={{ padding: "12px 16px 8px", borderBottom: `1px solid ${th.border}33`, flexShrink: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
	                      {ptIcon(selNode.processName)}
	                      <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, fontSize: 15, color: selSusColor || th.text }}>{selNode.processName}</span>
	                      <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: th.textMuted }}> PID {selNode.pid}</span>
	                      <span title={selLink.title} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selLink.color}18`, color: selLink.color, border: `1px solid ${selLink.color}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selLink.label}</span>
	                      {selPrev?.signals?.length > 0 && <span title={selPrev.signals.join("\n")} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selPrev.rarity}</span>}
	                    </div>
                    {selSusInfo.reason && <div style={{ marginBottom: 6 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: `${selSusColor}22`, color: selSusColor, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusColor}44` }}>{"\u26A0"} {selSusInfo.reason}</span>
                        {selSusInfo.confidence && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: selSusInfo.confidence === "confirmed" ? th.sev.critical + "22" : selSusInfo.confidence === "likely" ? th.sev.high + "22" : th.sev.low + "22", color: selSusInfo.confidence === "confirmed" ? th.sev.critical : selSusInfo.confidence === "likely" ? th.sev.high : th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusInfo.confidence === "confirmed" ? th.sev.critical + "44" : selSusInfo.confidence === "likely" ? th.sev.high + "44" : th.sev.low + "44"}`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{selSusInfo.confidence}</span>}{selSusInfo.triageScore > 0 && <span title={`Triage score ${selSusInfo.triageScore} — composite priority: severity×100 + confidence + prevalence/lifetime/trust boosts. Higher = investigate first.`} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selSusColor}1a`, color: selSusColor, border: `1px solid ${selSusColor}44`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.04em" }}>SCORE {selSusInfo.triageScore}</span>}
                        {selSusInfo.sanctioned && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.clean + "18", color: th.sev.clean, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.clean}33`, letterSpacing: "0.03em" }}>SANCTIONED {selSusInfo.sanctioned.cat.toUpperCase()}</span>}
                        {(() => { const seqs = _ptSeqMap.get(selectedKey); if (!seqs?.length) return null; const best = seqs.reduce((a, b) => a.confidence === "high" ? a : b); const sc = best.confidence === "high" ? th.sev.critical : th.sev.high; return <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${sc}aa`, color: "#fff", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.03em" }}>SEQ {best.confidence === "high" ? "\u2191" : "\u2193"}</span>; })()}
                        {(() => { const ev = selSusInfo.evidence; if (!ev || ev.length <= 1) return null; const pc = ev.filter(e => e.cat !== "context").length - 1; const cc = ev.filter(e => e.cat === "context").length; const parts = []; if (pc > 0) parts.push(`${pc} primary`); if (cc > 0) parts.push(`${cc} context`); return parts.length ? <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>+{parts.join(" + ")}</span> : null; })()}
                      </div>
                      {selSusInfo.evidence?.length > 1 && (() => {
                        const rest = selSusInfo.evidence.filter(e => e.reason !== selSusInfo.reason);
                        const prim = rest.filter(e => e.cat !== "context");
                        const ctxs = rest.filter(e => e.cat === "context");
                        return <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "center" }}>
                          {prim.map((e, i) => { const eColor = SUS_COLORS[e.level] || th.sev.low; return <span key={`p${i}`} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}14`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}22` }}>{e.cat === "chain" ? "chain: " : ""}{e.reason}{e.tid?.length ? ` [${e.tid.join(", ")}]` : ""}</span>; })}
                          {prim.length > 0 && ctxs.length > 0 && <span style={{ color: th.border, fontSize: 10, margin: "0 2px" }}>{"\u00B7"}</span>}
                          {ctxs.map((e, i) => { const eColor = e.dampen ? th.textDim : th.sev.low; return <span key={`c${i}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${eColor}0a`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}18`, fontStyle: "italic" }}>{e.dampen ? "\u25BC " : ""}{e.reason}</span>; })}
                        </div>;
                      })()}
                      {selSusInfo.techniques?.length > 0 && <div style={{ marginTop: 3, display: "flex", gap: 3, flexWrap: "wrap" }}>
                        {selSusInfo.techniques.map((t) => ptMitreBadge(t))}
                      </div>}
                    </div>}
                  </div>
                  <div style={{ overflow: "auto", flex: 1, padding: 16 }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      {fields.map(([label, value]) => (
                        <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                          <span style={gLbl}>{label}</span>
                          <span style={{ ...gVal, color: label === "Command Line" ? (th.danger) : th.text, background: label === "Command Line" ? `${th.accent}08` : "transparent", padding: label === "Command Line" ? "4px 6px" : "0", borderRadius: label === "Command Line" ? 3 : 0 }}>{label === "Command Line" ? ptHighlightCmd(value) : (value || "\u2014")}</span>
                        </div>
                      ))}
                    </div>
                    {ptDecodePanel(selNode.cmdLine, gLbl)}
                    {/* Behavioral Sequence */}
                    {(() => {
                      const seqs = _ptSeqMap.get(selectedKey);
                      if (!seqs?.length) return null;
                      const seqConfColor = { high: th.sev.critical, medium: th.sev.high };
                      return (
                        <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.critical + "12", borderRadius: 6, border: `1px solid ${th.sev.critical}22` }}>
                          <div style={{ ...gLbl, marginBottom: 4, color: th.sev.critical }}>Behavioral Sequence</div>
                          {seqs.map((s, i) => {
                            const sc = seqConfColor[s.confidence] || th.sev.low;
                            return (
                            <div key={i} style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: i < seqs.length - 1 ? 6 : 0 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                                <span style={{ color: sc, fontWeight: 600 }}>{s.seqName}</span>
                                <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33` }}>{s.stageName}</span>
                                <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33`, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.confidence}</span>
                              </div>
                              <div style={{ marginTop: 2, fontSize: 9, color: th.textMuted }}>{s.confidence === "high" ? "same tree" : "same host/user"} \u2014 {s.peers.length} processes {s.tid?.length ? `\u2014 ${s.tid.join(", ")}` : ""}</div>
                            </div>
                          ); })}
                        </div>
                      );
                    })()}
                    {(() => {
                      const nodeStory = _ptNodeStoryMap.get(selectedKey);
                      if (!nodeStory) return null;
                      return (
                        <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                          <div style={{ ...gLbl, marginBottom: 4 }}>Investigation Story</div>
                          <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, marginBottom: 6 }}>
                            {nodeStory.narrative}
                          </div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.eventCount} events</span>
                            <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.chainCount} chains</span>
                            {nodeStory.sequenceCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.sequenceCount} seq</span>}
                          </div>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "story", _ptExpandedIncident: nodeStory.id, selectedKey: nodeStory.anchorKey || selectedKey }))} style={_ptPivotBtn}>View Story</button>
                            <button onClick={() => _ptCopyStory(nodeStory)} style={_ptPivotBtn}>Copy Story</button>
                          </div>
                        </div>
                      );
                    })()}
                    {/* Chain Context */}
                    {nodeCluster && nodeCluster.count > 1 && (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Chain Context</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", display: "flex", flexDirection: "column", gap: 3 }}>
                          <div>Repeated <strong style={{ color: th.accent }}>{nodeCluster.count}x</strong> across {nodeCluster.users.length} user{nodeCluster.users.length !== 1 ? "s" : ""}</div>
                          <div>First: {(nodeCluster.firstSeen || "").slice(0, 19)} {"\u2014"} Last: {(nodeCluster.lastSeen || "").slice(0, 19)}</div>
                          <div>{nodeCluster.cmdVariants.length} command variant{nodeCluster.cmdVariants.length !== 1 ? "s" : ""}</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
          ) : (
          <div style={{ display: "flex", flex: 1, minHeight: 0 }}>

          {/* Column headers + Tree — virtualized */}
          {(() => {
            const PT_ROW_H = modal.ptDensity === "compact" ? 26 : 34, OVERSCAN = 8;
            const ptST = ptScroll.top;
            const ptCH = ptScroll.h;
            const totalRows = flatNodes.length;
            const totalH = totalRows * PT_ROW_H;
            const startIdx = Math.max(0, Math.floor(ptST / PT_ROW_H) - OVERSCAN);
            const endIdx = Math.min(totalRows, Math.ceil((ptST + ptCH) / PT_ROW_H) + OVERSCAN);
            const visibleSlice = flatNodes.slice(startIdx, endIdx);

            return (
              <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, minWidth: 0, overflow: "hidden" }}>
                {/* Fixed column header — OUTSIDE scroll container to prevent overlap */}
                <div ref={ptHeaderRef} style={{ flexShrink: 0, overflowX: "hidden", backgroundColor: th.modalBg, backgroundImage: `linear-gradient(180deg, ${th.accent}22 0%, transparent 100%)`, borderBottom: `2px solid ${th.accent}55`, boxShadow: `0 2px 8px ${th.accent}18` }}>
                  {/* Filter active indicator */}
                  {ptActiveFilterCount > 0 && (
                    <div style={{ padding: "4px 12px", display: "flex", alignItems: "center", gap: 8, borderBottom: `1px solid ${th.border}33`, borderLeft: `3px solid ${th.accent}`, minWidth: totalPtW }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>Filter active ({ptActiveFilterCount} column{ptActiveFilterCount > 1 ? "s" : ""})</span>
                      <span style={{ fontSize: 10, color: th.textDim }}>{"\u2014"} {flatNodes.length} of {data.stats.totalProcesses} processes</span>
                      <button onClick={() => setModal((p) => ({ ...p, ptColFilters: {} }))} style={{ padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Clear All</button>
                    </div>
                  )}
                  {/* Column header row */}
                  <div style={{ display: "flex", minWidth: totalPtW }}>
                    {/* Select-all checkbox */}
                    <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                      <input type="checkbox" checked={flatNodes.length > 0 && ptCheckedCount === flatNodes.length} ref={(el) => { if (el) el.indeterminate = ptCheckedCount > 0 && ptCheckedCount < flatNodes.length; }}
                        onChange={() => { setModal((p) => { if (!p) return p; const cur = p.ptChecked || new Set(); if (cur.size === flatNodes.length) return { ...p, ptChecked: new Set() }; return { ...p, ptChecked: new Set(flatNodes.map((n) => n.key)) }; }); }}
                        style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} title="Select all" />
                    </div>
                    {ptHeaders.map((h) => (
                      <div key={h} onClick={() => togglePtSort(h)} style={{ width: ptColWidths[h] || ptDefWidths[h], flexShrink: 0, padding: "9px 8px", fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, color: (ptSortCol || "Timestamp") === h ? th.accent : `${th.accent}99`, textTransform: "uppercase", letterSpacing: "0.08em", whiteSpace: "nowrap", overflow: "hidden", userSelect: "none", position: "relative", boxSizing: "border-box", cursor: "pointer" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 3 }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                          {(ptSortCol || "Timestamp") === h && <span style={{ fontSize: 7, color: th.accent }}>{(ptSortDir || "asc") === "asc" ? "\u25B2" : "\u25BC"}</span>}
                          <span onClick={(e) => { e.stopPropagation(); openPtFilter(h, e); }} style={{ cursor: "pointer", fontSize: 7, color: ptColFilters[h] ? (th.accent) : (th.textDim) + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                          <div onMouseDown={(e) => { e.stopPropagation(); onPtResizeStart(h, e); }} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                            <div style={{ position: "absolute", right: 2, top: 4, bottom: 4, width: 1, background: `${th.accent}44` }} />
                          </div>
                        </div>
                      </div>
                    ))}
                    <div style={{ width: 50, flexShrink: 0, padding: "6px 4px", fontSize: 9, fontFamily: "-apple-system, sans-serif", color: th.textDim, userSelect: "none" }} />
                  </div>
                </div>
                {/* Scrollable rows (+ findings minimap rail) — header stays fixed above */}
                <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
                <div ref={ptScrollRef} onScroll={(e) => {
                  const el = e.currentTarget;
                  const st = el.scrollTop;
                  const ch = el.clientHeight;
                  if (ptHeaderRef.current) ptHeaderRef.current.scrollLeft = el.scrollLeft;
                  if (ptRafRef.current) cancelAnimationFrame(ptRafRef.current);
                  ptRafRef.current = requestAnimationFrame(() => {
                    setPtScroll((p) => {
                      const oldStart = Math.floor(p.top / PT_ROW_H);
                      const newStart = Math.floor(st / PT_ROW_H);
                      if (newStart === oldStart && p.h === ch) return p;
                      return { top: st, h: ch };
                    });
                  });
                }} style={{ flex: 1, overflowY: "auto", overflowX: "auto", minHeight: 0, contain: "strict", willChange: "transform" }}>
                {/* Virtualized tree rows */}
                {flatNodes.length === 0 && (
                  <div style={{ padding: 20, textAlign: "center", color: th.textDim, fontSize: 12 }}>{searchText ? "No matching processes" : "No process creation events found"}</div>
                )}
                {flatNodes.length > 0 && (
                  <div style={{ height: totalH, position: "relative", minWidth: totalPtW, contain: "layout size" }}>
                    <div style={{ position: "absolute", top: startIdx * PT_ROW_H, left: 0, right: 0 }}>
                      {visibleSlice.map((node, vi) => {
                        const i = startIdx + vi;
                        const susInfo = _ptDetMap.get(node.key) || { level: 0, reason: null };
                        const sus = susInfo.level;
                        const susColor = SUS_COLORS[sus];
                        const hasChildren = node.childCount > 0;
                        const isExpanded = !!expandedNodes[node.key];
                        const tsDisplay = (node.ts || "").replace("T", " ").substring(0, 19);
                        const inChain = chainKeys.has(node.key);
                        const isSelected = node.key === selectedKey;
                        const lineColor = th.textMuted || th.textDim;
                        const chainColor = th.accent;
                        const INDENT = 20, LEFT_PAD = 16;

                        return (
                          <div key={node.key + ":" + i}
                            onClick={() => setModal((p) => p ? { ...p, selectedKey: p.selectedKey === node.key ? null : node.key } : p)}
                            className={isSelected ? "pt-row pt-sel" : "pt-row"}
                            style={{ display: "flex", height: PT_ROW_H, fontSize: 13, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer", background: isSelected ? (th.accent) + "10" : susColor && !inChain ? susColor + "06" : "transparent", borderBottom: `1px solid ${th.border}18`, borderLeft: isSelected ? `2px solid ${chainColor}` : susColor ? `2px solid ${susColor}55` : "2px solid transparent", alignItems: "center", minHeight: PT_ROW_H, contain: "layout style" }}>

                            {/* Row checkbox */}
                            <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                              <input type="checkbox" checked={ptChecked.has(node.key)}
                                onClick={(e) => e.stopPropagation()}
                                onChange={() => { setModal((p) => { if (!p) return p; const s = new Set(p.ptChecked || []); if (s.has(node.key)) s.delete(node.key); else s.add(node.key); return { ...p, ptChecked: s }; }); }}
                                style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                            </div>

                            {/* Timestamp column */}
                            <div style={{ width: ptColWidths.Timestamp || ptDefWidths.Timestamp, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 13, whiteSpace: "nowrap" }}>{tsDisplay}</span>
                            </div>

                            {/* Detection column — severity dot + reason + confidence + MITRE chips */}
	                            <div style={{ width: ptColWidths.Detection || ptDefWidths.Detection, flexShrink: 0, display: "flex", alignItems: "center", gap: 3, padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
	                              {sus > 0 && <span title={sus >= 3 ? "Critical" : sus >= 2 ? "High" : "Medium"} style={{ width: 6, height: 6, borderRadius: "50%", background: susColor, flexShrink: 0 }} />}
	                              {susInfo.reason && <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 4, background: susColor + "22", color: susColor, border: `1px solid ${susColor}44`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flexShrink: 1, minWidth: 0 }} title={susInfo.reason}>{susInfo.reason}</span>}
	                              {susInfo.confidence && susInfo.confidence !== "context" && <span title={`Confidence: ${susInfo.confidence}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, fontWeight: 700, flexShrink: 0, fontFamily: "'SF Mono', Menlo, monospace", background: (susInfo.confidence === "confirmed" ? th.sev.critical : susInfo.confidence === "likely" ? th.sev.high : th.sev.low) + "22", color: susInfo.confidence === "confirmed" ? th.sev.critical : susInfo.confidence === "likely" ? th.sev.high : th.sev.low }}>{susInfo.confidence === "confirmed" ? "✓✓" : susInfo.confidence === "likely" ? "✓" : "~"}</span>}
	                              {susInfo.techniques?.slice(0, 2).map((tid) => ptMitreBadge(tid, `dc-${node.key}-${tid}`))}
	                              {(() => { const cl = _ptNodeClusterMap.get(node.key); if (!cl || cl.count <= 1) return null; return <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontWeight: 600, flexShrink: 0, fontFamily: "SF Mono, monospace" }}>{cl.count}x</span>; })()}
	                              {(() => { const cl = _ptNodeClusterMap.get(node.key); if (!cl || cl.users.length <= 1) return null; return <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: th.sev.med + "15", color: th.sev.med, fontWeight: 500, flexShrink: 0, fontFamily: "SF Mono, monospace" }}>{cl.users.length}u</span>; })()}
	                            </div>

	                            {/* Trust column */}
	                            <div style={{ width: ptColWidths.Prevalence || ptDefWidths.Prevalence, flexShrink: 0, display: "flex", alignItems: "center", gap: 4, padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
	                              {(() => {
	                                const prev = susInfo.prevalence || null;
	                                if (!prev || prev.rarity === "common" || !prev.signals?.length) return null;
	                                const color = prev.rarity === "rare" ? th.accent : th.textMuted;
	                                return (
	                                  <span title={prev.signals.join("\n")} style={{ display: "inline-flex", alignItems: "center", gap: 4, maxWidth: "100%", fontSize: 10, padding: "1px 6px", borderRadius: 4, background: `${color}18`, color, border: `1px solid ${color}33`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontFamily: "SF Mono, monospace", fontWeight: 700 }}>
	                                    <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{prev.rarity}</span>
	                                    {prev.scoreBoost > 0 && <span style={{ opacity: 0.8, flexShrink: 0 }}>+{prev.scoreBoost}</span>}
	                                  </span>
	                                );
	                              })()}
	                            </div>

	                            {/* Parent Process column.
                                Falls back to the relinked parent node's processName when the row itself
                                has no parent image — this handles Security 4688 (no ParentImage field at
                                all), EvtxECmd, and any dataset where parent linkage exists via PID/GUID
                                but the parent's executable name lives on a different row. */}
                            <div style={{ width: ptColWidths["Parent Process"] || ptDefWidths["Parent Process"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              {(() => {
                                const linked = byKeyMap.get(node.parentKey);
                                const display = node.parentProcessName || linked?.processName || "";
                                const titleAttr = node.parentImage || linked?.image || "";
                                return <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={titleAttr}>{display}</span>;
                              })()}
                            </div>

                            {/* Process column */}
                            <div style={{ width: ptColWidths.Process || ptDefWidths.Process, flexShrink: 0, position: "relative", display: "flex", alignItems: "center", gap: 4, overflow: "hidden", boxSizing: "border-box" }}>
                              {node.depth > 0 && (node.connectors || []).map((active, d) => (
                                active ? <div key={`vl${d}`} style={{ position: "absolute", left: LEFT_PAD + d * INDENT + INDENT / 2, top: 0, bottom: 0, width: 1, background: inChain && d >= 0 ? chainColor + "66" : lineColor + "44" }} /> : null
                              ))}
                              {node.depth > 0 && (
                                <>
                                  <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: 0, height: node.isLast ? PT_ROW_H / 2 : PT_ROW_H, width: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                  <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: PT_ROW_H / 2, width: INDENT / 2 + 2, height: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                </>
                              )}
                              <div style={{ width: LEFT_PAD + node.depth * INDENT, minWidth: LEFT_PAD + node.depth * INDENT, flexShrink: 0 }} />
                              <span onClick={(e) => { e.stopPropagation(); if (hasChildren) setModal((p) => { const en = { ...p.expandedNodes }; if (en[node.key]) delete en[node.key]; else en[node.key] = true; return { ...p, expandedNodes: en }; }); }}
                                style={{ width: 14, textAlign: "center", color: hasChildren ? (inChain ? chainColor : th.textDim) : "transparent", fontSize: 11, flexShrink: 0, userSelect: "none" }}>
                                {hasChildren ? (isExpanded ? "\u25BC" : "\u25B6") : "\u00B7"}
                              </span>
                              {inChain && <div style={{ width: 6, height: 6, borderRadius: "50%", background: chainColor, flexShrink: 0 }} />}
                              {ptIcon(node.processName)}
                              <span style={{ fontWeight: 600, color: isSelected ? chainColor : susColor || th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }} title={node.image}>{node.processName}</span>
                              {node.childCount > 0 && <span style={{ fontSize: 11, color: th.accent, flexShrink: 0, paddingRight: 4 }}>({node.childCount})</span>}
                            </div>

                            {/* Command Line column */}
                            <div style={{ width: ptColWidths["Command Line"] || ptDefWidths["Command Line"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.cmdLine}>{node.cmdLine}</span>
                            </div>

                            {/* PID column */}
                            <div style={{ width: ptColWidths.PID || ptDefWidths.PID, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ fontFamily: "monospace", color: inChain ? chainColor + "cc" : th.textDim, fontSize: 13, whiteSpace: "nowrap" }}>{node.pid}</span>
                            </div>

                            {/* PPID column */}
                            <div style={{ width: ptColWidths.PPID || ptDefWidths.PPID, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 13, whiteSpace: "nowrap" }}>{node.ppid || ""}</span>
                            </div>

                            {/* User column */}
                            <div style={{ width: ptColWidths.User || ptDefWidths.User, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.user || ""}</span>
                            </div>

                            {/* Provider column */}
                            <div style={{ width: ptColWidths.Provider || ptDefWidths.Provider, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ fontSize: 12, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{_providerShort(node.provider)}</span>
                            </div>

                            {/* Event ID column */}
                            <div style={{ width: ptColWidths["Event ID"] || ptDefWidths["Event ID"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 12, whiteSpace: "nowrap" }}>{node.eventId || ""}</span>
                            </div>

                            {/* Integrity column */}
                            <div style={{ width: ptColWidths.Integrity || ptDefWidths.Integrity, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                              {(() => { const il = _integrityShort(node.integrity); const ic = INT_COLOR[il]; return il ? <span style={{ fontSize: 11, padding: "2px 6px", borderRadius: 3, background: (ic || th.textDim) + "18", color: ic || th.textDim, fontWeight: 500, whiteSpace: "nowrap" }}>{il}</span> : null; })()}
                            </div>

                            {/* Filter grid button */}
                            <div style={{ width: 50, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <button onClick={(e) => {
                                e.stopPropagation();
                                if (cols.pid && node.pid) {
                                  const cbf = { ...(ct.checkboxFilters || {}) };
                                  cbf[cols.pid] = [node.pid];
                                  if (cols.eventId) delete cbf[cols.eventId];
                                  up("checkboxFilters", cbf);
                                }
                                setModal(null);
                              }} title="Filter grid to this process" style={{ background: "none", border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, fontSize: 10, padding: "2px 6px", cursor: "pointer" }}>Filter</button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
              {flatNodes.length > 40 && _ptRail && (
                <div
                  onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); const frac = Math.max(0, Math.min(1, (e.clientY - r.top) / r.height)); if (ptScrollRef.current) ptScrollRef.current.scrollTop = frac * Math.max(0, totalH - ptCH); }}
                  title="Findings overview — click to jump to that position"
                  style={{ width: 11, flexShrink: 0, position: "relative", cursor: "pointer", background: `${th.border}14`, borderLeft: `1px solid ${th.border}33` }}>
                  {_ptRail.map((lv, b) => lv > 0 ? (
                    <div key={b} style={{ position: "absolute", left: 1, right: 1, top: `${(b / _ptRail.length) * 100}%`, height: `${Math.max(100 / _ptRail.length, 0.6)}%`, minHeight: 2, background: SUS_COLORS[lv], opacity: lv >= 3 ? 1 : lv === 2 ? 0.8 : 0.55, borderRadius: 1 }} />
                  ) : null)}
                  {totalH > ptCH && (
                    <div style={{ position: "absolute", left: 0, right: 0, top: `${(ptST / totalH) * 100}%`, height: `${Math.min(100, (ptCH / totalH) * 100)}%`, background: `${th.accent}1f`, border: `1px solid ${th.accent}55`, borderRadius: 2, pointerEvents: "none", boxSizing: "border-box" }} />
                  )}
                </div>
              )}
              </div>
              </div>
            );
          })()}

          {/* Column filter dropdown popup */}
          {ptFilterOpen && (
            <>
              <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} />
              <div style={{ position: "fixed", left: modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340), top: modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440), width: modal.ptFilterW || 320, height: modal.ptFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    const startX = e.clientX, startY = e.clientY;
                    const startLeft = modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340);
                    const startTop = modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440);
                    document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                    const onMove = (ev) => setModal((p) => ({ ...p, ptFilterX: startLeft + ev.clientX - startX, ptFilterY: startTop + ev.clientY - startY }));
                    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                  }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {(ptFilterOpen || "").toUpperCase()}</span>
                  <span style={{ cursor: "pointer", color: th.textDim, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))}>{"\u00D7"}</span>
                </div>
                <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                  <input type="text" placeholder="Search values..." value={ptFilterSearch} onChange={(e) => setModal((p) => ({ ...p, ptFilterSearch: e.target.value }))}
                    style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                    autoFocus />
                </div>
                <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set(ptFilterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                  <span style={{ fontSize: 9, color: th.textDim, marginLeft: "auto" }}>{ptFilterSel.size} of {ptFilterVals.length}</span>
                </div>
                <div style={{ flex: 1, overflowY: "auto", minHeight: 0, padding: "0 4px" }}>
                  {ptFilterDisplay.map((val) => (
                    <label key={val} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 6px", cursor: "pointer", fontSize: 11, fontFamily: "SF Mono, Menlo, monospace", color: th.text, borderRadius: 3 }}
                      onMouseEnter={(e) => e.currentTarget.style.background = th.bgHover || th.border + "22"}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                      <input type="checkbox" checked={ptFilterSel.has(val)} onChange={() => setModal((p) => {
                        const s = new Set(p.ptFilterSel || []);
                        if (s.has(val)) s.delete(val); else s.add(val);
                        return { ...p, ptFilterSel: s };
                      })} style={{ width: 13, height: 13, accentColor: th.accent }} />
                      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val || "(empty)"}</span>
                      <span style={{ fontSize: 9, color: th.textDim, flexShrink: 0 }}>{ptFilterCounts[val] || 0}</span>
                    </label>
                  ))}
                </div>
                <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                  <button onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} style={{ padding: "4px 12px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Cancel</button>
                  <button onClick={() => {
                    const selected = [...ptFilterSel];
                    const all = ptFilterVals;
                    setModal((p) => {
                      const filters = { ...(p.ptColFilters || {}) };
                      if (selected.length === 0 || selected.length === all.length) { delete filters[ptFilterOpen]; }
                      else { filters[ptFilterOpen] = selected; }
                      return { ...p, ptColFilters: filters, ptFilterOpen: null };
                    });
                  }} style={{ padding: "4px 12px", fontSize: 10, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Apply</button>
                  <button onClick={() => {
                    setModal((p) => {
                      const filters = { ...(p.ptColFilters || {}) };
                      delete filters[ptFilterOpen];
                      return { ...p, ptColFilters: filters, ptFilterOpen: null };
                    });
                  }} style={{ padding: "4px 12px", fontSize: 10, background: "transparent", border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Reset</button>
                </div>
                {/* Resize grip */}
                <div onMouseDown={(e) => {
                  e.preventDefault(); e.stopPropagation();
                  const startX = e.clientX, startY = e.clientY;
                  const startW = modal.ptFilterW || 320, startH = modal.ptFilterH || 420;
                  document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                  const onMove = (ev) => setModal((p) => ({ ...p, ptFilterW: Math.max(200, startW + ev.clientX - startX), ptFilterH: Math.max(200, startH + ev.clientY - startY) }));
                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize" }}>
                  <svg width="16" height="16" viewBox="0 0 16 16" style={{ position: "absolute", right: 2, bottom: 2 }}>
                    <line x1="12" y1="4" x2="4" y2="12" stroke={th.textDim} strokeWidth="1" />
                    <line x1="12" y1="8" x2="8" y2="12" stroke={th.textDim} strokeWidth="1" />
                  </svg>
                </div>
              </div>
            </>
          )}

          {/* Right-side Detail Panel — prototype grid layout, resizable */}
          {(() => {
            const detailW = modal.ptDetailW || 380;
            const detailResizeHandle = (
              <div onMouseDown={(e) => {
                e.preventDefault(); e.stopPropagation();
                const startX = e.clientX;
                const startW = modal.ptDetailW || 380;
                document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                const onMove = (ev) => { const newW = Math.max(240, Math.min(700, startW - (ev.clientX - startX))); setModal((p) => p ? { ...p, ptDetailW: newW } : p); };
                const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
              }} style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 }}>
                <div style={{ position: "absolute", left: 2, top: "50%", transform: "translateY(-50%)", width: 3, height: 40, borderRadius: 2, background: th.textMuted + "44", transition: "background var(--m-base)" }}
                  onMouseEnter={(e) => e.currentTarget.style.background = th.accent}
                  onMouseLeave={(e) => e.currentTarget.style.background = (th.textMuted) + "44"} />
              </div>
            );
            const selNode = selectedKey ? byKeyMap.get(selectedKey) : null;
            if (!selNode) return (
              <div style={{ width: detailW, position: "relative", borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column" }}>
                {detailResizeHandle}
                <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}88`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace" }}>Event Details</div>
                <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12 }}>Select a process node to view details</div>
              </div>
            );
	            const parentNode = byKeyMap.get(selNode.parentKey);
	            const selSusInfo = _ptDetMap.get(selectedKey) || { level: 0, reason: null };
	            const selSus = selSusInfo.level;
	            const selSusColor = SUS_COLORS[selSus];
	            const selLink = ptLinkMeta(selNode);
	            const selPrev = selSusInfo.prevalence || null;
            const children = (childMap.get(selectedKey) || []).map((k) => byKeyMap.get(k)).filter(Boolean);
            const elevMap = { "%%1936": "Full (elevated)", "%%1937": "Limited (not elevated)", "%%1938": "Default" };
            const elevLabel = elevMap[selNode.elevation] || selNode.elevation || "";
            const integrityLabel = _integrityShort(selNode.integrity);
            const intCol = INT_COLOR[integrityLabel];
            const selSuppressed = selSusInfo.suppressed || null;
            const selBaselined = selSusInfo.baselined || null;
            const sourceEvent = modal.ptSourceEvent?.rowId === selNode.rowid && (!modal.ptSourceEvent?.tabId || modal.ptSourceEvent.tabId === ct.id) ? modal.ptSourceEvent.row : null;
            const relatedCtx = modal.ptRelatedEvents?.selected?.rowid === selNode.rowid ? modal.ptRelatedEvents : null;
            const relatedTimeline = relatedCtx?.timeline || [];
            const relatedGroups = relatedCtx?.groups || [];
            const relatedChips = relatedCtx?.enrichmentChips || [];
            const crossTelemetry = relatedCtx?.crossTelemetry || null;
            const crossPivots = crossTelemetry?.pivots || [];
            const crossRefs = crossTelemetry?.evidenceRefs || [];
            const groupRefsByTab = (refs) => {
              const grouped = new Map();
              for (const ref of refs || []) {
                const rowId = Number(ref?.rowId);
                if (!Number.isInteger(rowId) || rowId <= 0) continue;
                const tabId = ref.tabId || ct.id;
                if (!grouped.has(tabId)) grouped.set(tabId, []);
                grouped.get(tabId).push(rowId);
              }
              return grouped;
            };
            const filterLinkedRows = () => {
              const ids = [...new Set(crossRefs.filter((ref) => !ref.tabId || ref.tabId === ct.id).map((ref) => Number(ref.rowId)).filter(Boolean))];
              if (!ids.length) return;
              updateActiveTab({ rowIdFilter: ids, rowIdFilterLabel: `Process linked evidence (${ids.length})` });
              setModal(null);
            };
            const bookmarkLinkedRows = async () => {
              if (!tle?.setBookmarks || !crossRefs.length) return;
              for (const [tabId, rowIds] of groupRefsByTab(crossRefs)) await tle.setBookmarks(tabId, [...new Set(rowIds)], true);
              setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedActionStatus: `Bookmarked ${crossRefs.length} linked evidence rows.` } : p);
            };
            const tagLinkedRows = async () => {
              if (!tle?.addTag || !crossRefs.length) return;
              const tag = window.prompt("Tag linked evidence rows", "PI:Linked Evidence");
              if (!tag) return;
              for (const [tabId, rowIds] of groupRefsByTab(crossRefs)) {
                for (const rowId of [...new Set(rowIds)]) await tle.addTag(tabId, rowId, tag);
              }
              setModal((p) => p?.type === "processTree" ? { ...p, ptLinkedActionStatus: `Tagged ${crossRefs.length} linked evidence rows as ${tag}.` } : p);
            };
            const exportLinkedEvidence = () => {
              if (!crossTelemetry) return;
              const payload = {
                exportedAt: new Date().toISOString(),
                selectedProcess: {
                  tabId: ct.id,
                  rowId: selNode.rowid,
                  timestamp: selNode.ts,
                  host: selNode.hostname,
                  user: selNode.user,
                  process: selNode.processName,
                  image: selNode.image,
                  commandLine: selNode.cmdLine,
                },
                crossTelemetry,
              };
              const safeProc = (selNode.processName || "process").replace(/[^a-z0-9_.-]+/gi, "_").slice(0, 40);
              _downloadFile(JSON.stringify(payload, null, 2), `process-linked-evidence-${safeProc}.json`, "application/json");
            };
            const relatedMatchLabel = {
              hostWindow: "host window",
              samePid: "same PID",
              samePpid: "same PPID",
              sameGuid: "same GUID",
              sameParentGuid: "parent GUID",
              sameUser: "same user",
              sameLogon: "same logon",
              enrichment: "enrichment",
              telemetry: "telemetry",
              sameProcessImage: "same process",
            };
            const relatedTypeColor = (type) => ({
              powershell: th.textMuted,
              service: th.sev.high,
              task: th.sev.med,
              logon: th.textMuted,
              terminate: th.sev.critical,
              network: th.sev.high,
              dns: th.textMuted,
              detection: th.sev.critical,
            }[type] || th.textMuted);
            const sourceEventFields = sourceEvent
              ? Object.entries(sourceEvent).filter(([k, v]) => k !== "__idx" && String(v || "").trim() !== "")
              : [];
            const copyDetails = () => {
              const lines = [
                `Process: ${selNode.processName}`, `PID: ${selNode.pid}`, `PPID: ${selNode.ppid}`,
                selNode.user ? `User: ${selNode.user}` : null, selNode.ts ? `Timestamp: ${selNode.ts.replace("T", " ").substring(0, 19)}` : null,
	                selNode.image ? `Image: ${selNode.image}` : null, selNode.cmdLine ? `Command Line: ${selNode.cmdLine}` : null,
	                selNode.parentImage ? `Parent Image: ${selNode.parentImage}` : null,
	                parentNode ? `Parent: ${parentNode.processName} (PID ${parentNode.pid})` : null,
	                selLink.source ? `Parent Link: ${selLink.label} (${selLink.confidence || "none"})` : null,
	                selLink.link.reason ? `Link Reason: ${selLink.link.reason}` : null,
	                selLink.warnings.length ? `Link Warnings: ${selLink.warnings.join(", ")}` : null,
	                selPrev ? `Prevalence: ${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : null,
	                selPrev?.signals?.length ? `Prevalence Signals: ${selPrev.signals.join(", ")}` : null,
	                elevLabel ? `Elevation: ${elevLabel}` : null, integrityLabel ? `Integrity: ${integrityLabel}` : null,
                selSus > 0 ? `Suspicious: ${selSusInfo.reason}` : null,
                selBaselined ? `Baselined: ${selBaselined.hostname || "global"}` : null,
                relatedCtx?.stats?.totalRelated ? `Related EVTX: ${relatedCtx.stats.totalRelated}` : null,
                crossTelemetry?.stats?.total ? `Cross-Telemetry: ${crossTelemetry.stats.total} pivots (${Object.entries(crossTelemetry.counts || {}).map(([k, v]) => `${k}:${v}`).join(", ")})` : null,
                children.length > 0 ? `Children (${children.length}): ${children.map((c) => `${c.processName} (${c.pid})`).join(", ")}` : null,
              ].filter(Boolean);
              navigator.clipboard?.writeText?.(lines.join("\n"));
            };
            const gLbl = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 };
            const gVal = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12, color: th.text, wordBreak: "break-all", lineHeight: 1.5 };
            const fields = [
              ["Timestamp", selNode.ts ? selNode.ts.replace("T", " ").substring(0, 19) : ""],
              ["Process", selNode.processName],
              ["Full Path", selNode.image],
              ["PID", selNode.pid],
	              ["PPID", selNode.ppid],
	              ["Parent", parentNode ? parentNode.processName : ""],
	              ["Parent Path", selNode.parentImage],
	              ["Parent Link", `${selLink.label}${selLink.confidence ? ` (${selLink.confidence})` : ""}`],
	              ["Link Reason", selLink.link.reason],
	              ["Link Warnings", selLink.warnings.join(", ")],
	              ["Prevalence", selPrev ? `${selPrev.rarity}${selPrev.scoreBoost ? ` (+${selPrev.scoreBoost})` : ""}` : ""],
	              ["Prevalence Signals", selPrev?.signals?.join(", ")],
	              ["User", selNode.user],
              ["Integrity", integrityLabel],
              ["Elevation", elevLabel],
              ["Command Line", selNode.cmdLine],
              ["Provider", _providerShort(selNode.provider)],
              ["Event ID", selNode.eventId],
              ["Hash", ptExtractHash(selNode.hashes)],
            ].filter(([, v]) => v);
            return (
              <div style={{ width: detailW, position: "relative", borderLeft: selSusInfo.level >= 2 ? `3px solid ${selSusColor}` : `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {detailResizeHandle}
                {/* EVENT DETAILS header bar */}
                <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}aa`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>Event Details</div>
                {/* Process header + badges */}
                <div style={{ padding: "12px 16px 8px", borderBottom: `1px solid ${th.border}33`, flexShrink: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
	                    {ptIcon(selNode.processName)}
	                    <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, fontSize: 15, color: selSusColor || th.text }}>{selNode.processName}</span>
	                    <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: th.textMuted, marginLeft: 4 }}>PID {selNode.pid}</span>
	                    <span title={selLink.title} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selLink.color}18`, color: selLink.color, border: `1px solid ${selLink.color}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selLink.label}</span>
	                    {selPrev?.signals?.length > 0 && <span title={selPrev.signals.join("\n")} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, textTransform: "uppercase" }}>{selPrev.rarity}</span>}
	                  </div>
                  {selSuppressed && (
                    <div style={{ marginBottom: 6, display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: th.sev.low + "22", color: th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.low}44`, textTransform: "uppercase", letterSpacing: "0.05em" }}>Suppressed</span>
                      <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Analyst rule hid this detection from triage views.</span>
                    </div>
                  )}
                  {selSusInfo.reason && <div style={{ marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: `${selSusColor}22`, color: selSusColor, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusColor}44`, letterSpacing: "0.02em" }}>{"\u26A0"} {selSusInfo.reason}</span>
                      {selSusInfo.confidence && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: selSusInfo.confidence === "confirmed" ? th.sev.critical + "22" : selSusInfo.confidence === "likely" ? th.sev.high + "22" : th.sev.low + "22", color: selSusInfo.confidence === "confirmed" ? th.sev.critical : selSusInfo.confidence === "likely" ? th.sev.high : th.sev.low, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusInfo.confidence === "confirmed" ? th.sev.critical + "44" : selSusInfo.confidence === "likely" ? th.sev.high + "44" : th.sev.low + "44"}`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{selSusInfo.confidence}</span>}{selSusInfo.triageScore > 0 && <span title={`Triage score ${selSusInfo.triageScore} — composite priority: severity×100 + confidence + prevalence/lifetime/trust boosts. Higher = investigate first.`} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${selSusColor}1a`, color: selSusColor, border: `1px solid ${selSusColor}44`, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.04em" }}>SCORE {selSusInfo.triageScore}</span>}
                      {selSusInfo.sanctioned && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.clean + "18", color: th.sev.clean, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.sev.clean}33`, letterSpacing: "0.03em" }}>SANCTIONED {selSusInfo.sanctioned.cat.toUpperCase()}</span>}
                      {selBaselined && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${th.textMuted}33`, letterSpacing: "0.03em" }}>BASELINED {selBaselined.hostname || "GLOBAL"}</span>}
                      {(() => { const seqs = _ptSeqMap.get(selectedKey); if (!seqs?.length) return null; const best = seqs.reduce((a, b) => a.confidence === "high" ? a : b); const sc = best.confidence === "high" ? th.sev.critical : th.sev.high; return <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${sc}aa`, color: "#fff", fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, letterSpacing: "0.03em" }}>SEQ {best.confidence === "high" ? "\u2191" : "\u2193"}</span>; })()}
                      {(() => { const ev = selSusInfo.evidence; if (!ev || ev.length <= 1) return null; const pc = ev.filter(e => e.cat !== "context").length - 1; const cc = ev.filter(e => e.cat === "context").length; const parts = []; if (pc > 0) parts.push(`${pc} primary`); if (cc > 0) parts.push(`${cc} context`); return parts.length ? <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>+{parts.join(" + ")}</span> : null; })()}
                    </div>
                    {selSusInfo.evidence?.length > 1 && (() => {
                      const rest = selSusInfo.evidence.filter(e => e.reason !== selSusInfo.reason);
                      const prim = rest.filter(e => e.cat !== "context");
                      const ctxs = rest.filter(e => e.cat === "context");
                      return <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "center" }}>
                        {prim.map((e, i) => { const eColor = SUS_COLORS[e.level] || th.sev.low; return <span key={`p${i}`} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}14`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}22` }}>{e.cat === "chain" ? "chain: " : ""}{e.reason}{e.tid?.length ? ` [${e.tid.join(", ")}]` : ""}</span>; })}
                        {prim.length > 0 && ctxs.length > 0 && <span style={{ color: th.border, fontSize: 10, margin: "0 2px" }}>{"\u00B7"}</span>}
                        {ctxs.map((e, i) => { const eColor = e.dampen ? th.textDim : th.sev.low; return <span key={`c${i}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${eColor}0a`, color: eColor, fontFamily: "'SF Mono', Menlo, monospace", border: `1px solid ${eColor}18`, fontStyle: "italic" }}>{e.dampen ? "\u25BC " : ""}{e.reason}</span>; })}
                      </div>;
                    })()}
                    {selSusInfo.techniques?.length > 0 && <div style={{ marginTop: 3, display: "flex", gap: 3, flexWrap: "wrap" }}>
                      {selSusInfo.techniques.map((t) => ptMitreBadge(t))}
                    </div>}
                  </div>}
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <button onClick={copyDetails} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Copy Details</button>
                    <button onClick={() => openPiSourceEvent(selNode.rowid)} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Source Event</button>
                    {ptExtractHash(selNode.hashes) && <button onClick={() => window.tle?.openExternal?.(`https://www.virustotal.com/gui/file/${ptExtractHash(selNode.hashes)}`)} title="Look up this file's hash on VirusTotal (opens in browser)" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.accent + "15", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>VirusTotal</button>}
                    {selSusInfo.reason && !selBaselined && <button onClick={() => {
                      const entry = makePiAnalystEntry("baselines", selNode, parentNode, selSusInfo);
                      if (entry) upsertPiAnalystEntry("baselines", entry);
                    }} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.accent + "15", color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Baseline Host</button>}
                    {selBaselined && <button onClick={() => removePiAnalystEntry("baselines", selBaselined.id)} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Remove Baseline</button>}
                    {selSusInfo.reason && !selSuppressed && <button onClick={() => {
                      const entry = makePiAnalystEntry("suppressions", selNode, parentNode, selSusInfo);
                      if (entry) upsertPiAnalystEntry("suppressions", entry);
                    }} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.sev.low + "15", color: th.sev.low, border: `1px solid ${th.sev.low}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Suppress</button>}
                  </div>
                </div>
                {/* Grid fields — matching prototype */}
                <div style={{ overflow: "auto", flex: 1, padding: 16 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {fields.map(([label, value]) => (
                      <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={gLbl}>{label}</span>
                        <span style={{ ...gVal, color: label === "Command Line" ? (th.danger) : label === "Parent" ? (th.accent) : label === "Integrity" ? (intCol || th.text) : th.text, background: label === "Command Line" ? `${th.accent}08` : "transparent", padding: label === "Command Line" ? "4px 6px" : "0", borderRadius: label === "Command Line" ? 3 : 0, cursor: label === "Parent" && parentNode ? "pointer" : "default" }}
                          onClick={label === "Parent" && parentNode ? () => {
                            const en = { ...(modal.expandedNodes || {}) };
                            let cur = consistentParentKey(parentNode, byKeyMap);
                            while (cur && byKeyMap.has(cur)) { en[cur] = true; cur = consistentParentKey(byKeyMap.get(cur), byKeyMap); }
                            setModal((p) => p ? { ...p, selectedKey: parentNode.key, expandedNodes: en } : p);
                          } : undefined}>{label === "Command Line" ? ptHighlightCmd(value) : (value || "\u2014")}</span>
                      </div>
                    ))}
                  </div>
                  {ptDecodePanel(selNode.cmdLine, gLbl)}
                  {(modal.ptSourceEventLoading || sourceEvent) && (
                    <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.panelBg}66`, borderRadius: 6, border: `1px solid ${th.border}22` }}>
                      <div style={{ ...gLbl, marginBottom: 6 }}>Source Event</div>
                      {modal.ptSourceEventLoading ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Loading raw event...</div>
                      ) : sourceEvent ? (
                        <>
                          <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: 6 }}>Row ID {sourceEvent.__idx}</div>
                          <div style={{ display: "flex", flexDirection: "column", gap: 1, maxHeight: 260, overflowY: "auto" }}>
                            {sourceEventFields.slice(0, 40).map(([label, value]) => (
                              <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "4px 0", borderBottom: `1px solid ${th.border}18` }}>
                                <span style={gLbl}>{label}</span>
                                <span style={{ ...gVal, color: th.textDim }}>{value}</span>
                              </div>
                            ))}
                          </div>
                          {sourceEventFields.length > 40 && <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{sourceEventFields.length - 40} more populated fields hidden.</div>}
                        </>
                      ) : (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Source event not available.</div>
                      )}
                    </div>
                  )}
                  {(modal.ptRelatedEventsLoading || relatedCtx || modal.ptRelatedEventsError) && (
                    <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                      <div style={{ ...gLbl, marginBottom: 6 }}>Related EVTX</div>
                      {modal.ptRelatedEventsLoading ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Loading related events...</div>
                      ) : modal.ptRelatedEventsError && !relatedCtx ? (
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{modal.ptRelatedEventsError}</div>
                      ) : relatedCtx ? (
                        <>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                            {relatedGroups.map((group) => (
                              <span key={group.id} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                {group.label} {group.count}
                              </span>
                            ))}
                          </div>
                          {relatedChips.length > 0 && (
                            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                              {relatedChips.map((chip) => {
                                const color = relatedTypeColor(chip.id);
                                return (
                                  <span key={chip.id} style={{ fontSize: 8, padding: "1px 6px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                    {chip.label} {chip.count}
                                  </span>
                                );
                              })}
                            </div>
                          )}
                          {crossTelemetry?.stats?.total > 0 && (
                            <div style={{ marginBottom: 8, padding: "7px 8px", borderRadius: 6, background: `${th.panelBg}66`, border: `1px solid ${th.border}22` }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap", marginBottom: 6 }}>
                                <span style={{ ...gLbl, paddingTop: 0, color: th.accent }}>Cross-Telemetry Pivots</span>
                                {Object.entries(crossTelemetry.counts || {}).map(([type, count]) => {
                                  const color = relatedTypeColor(type);
                                  return <span key={type} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{type} {count}</span>;
                                })}
                                <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{crossTelemetry.stats.evidenceRows} rows</span>
                              </div>
                              <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 150, overflowY: "auto", marginBottom: 7 }}>
                                {crossPivots.slice(0, 12).map((pivot) => {
                                  const color = relatedTypeColor(pivot.type);
                                  const ref = pivot.evidenceRefs?.[0] || null;
                                  return (
                                    <div key={pivot.id} style={{ padding: "4px 5px", borderRadius: 5, background: `${color}08`, border: `1px solid ${color}22` }}>
                                      <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                                        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{pivot.type}</span>
                                        <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}18`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{pivot.confidence}</span>
                                        <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{(pivot.timestamp || "").slice(0, 19)}</span>
                                        {ref?.rowId && <button onClick={() => openPiSourceEvent(ref)} style={{ marginLeft: "auto", padding: "1px 6px", borderRadius: 3, fontSize: 8, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Open</button>}
                                      </div>
                                      <div style={{ marginTop: 2, fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.35, wordBreak: "break-word" }}>
                                        <strong style={{ color: th.text }}>{pivot.label}</strong>{pivot.summary ? ` - ${pivot.summary}` : ""}
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                              {modal.ptLinkedActionStatus && <div style={{ fontSize: 9, color: th.sev.clean, fontFamily: "-apple-system, sans-serif", marginBottom: 6 }}>{modal.ptLinkedActionStatus}</div>}
                              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                <button onClick={filterLinkedRows} style={_ptPivotBtn}>Open Linked Rows</button>
                                <button onClick={bookmarkLinkedRows} style={_ptPivotBtn}>Bookmark Linked</button>
                                <button onClick={tagLinkedRows} style={_ptPivotBtn}>Tag Linked</button>
                                <button onClick={exportLinkedEvidence} style={_ptPivotBtn}>Export Evidence</button>
                              </div>
                            </div>
                          )}
                          {relatedTimeline.length > 0 ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 260, overflowY: "auto" }}>
                              {relatedTimeline.map((evt) => {
                                const eColor = relatedTypeColor(evt.enrichmentType || evt.telemetryType);
                                return (
                                  <div key={evt.rowid} style={{ padding: "5px 6px", borderRadius: 6, background: evt.isSelected ? `${th.accent}12` : `${th.panelBg}55`, border: `1px solid ${evt.isSelected ? `${th.accent}33` : `${th.border}18`}` }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap", marginBottom: 3 }}>
                                      <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{(evt.timestamp || "").slice(0, 19) || "Unknown time"}</span>
                                      <span style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}22`, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>{evt.eventId || "?"}</span>
                                      {evt.provider && <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{_providerShort(evt.provider) || evt.provider}</span>}
                                      {evt.enrichmentType && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}18`, color: eColor, border: `1px solid ${eColor}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{evt.eventLabel}</span>}
                                      {evt.telemetryType && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${eColor}18`, color: eColor, border: `1px solid ${eColor}33`, fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{evt.telemetryType}</span>}
                                      {evt.isSelected && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}18`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>anchor</span>}
                                      {(evt.matchTypes || []).filter((m) => m !== "selected").slice(0, 4).map((m) => (
                                        <span key={`${evt.rowid}-${m}`} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${th.border}18`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                          {relatedMatchLabel[m] || m}
                                        </span>
                                      ))}
                                      {!evt.isSelected && evt.rowid > 0 && (
                                        <button onClick={() => openPiSourceEvent(evt.rowid)} style={{ marginLeft: "auto", padding: "1px 6px", borderRadius: 3, fontSize: 8, cursor: "pointer", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>Open Raw</button>
                                      )}
                                    </div>
                                    <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4 }}>
                                      {evt.telemetrySummary || evt.summary || `${evt.processName || "Event"}${evt.cmdLine ? ` — ${evt.cmdLine}` : ""}`}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          ) : (
                            <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>No related EVTX pivots matched this process in the current tab.</div>
                          )}
                        </>
                      ) : null}
                    </div>
                  )}
                  {/* Behavioral Sequence */}
                  {(() => {
                    const seqs = _ptSeqMap.get(selectedKey);
                    if (!seqs?.length) return null;
                    const seqConfColor = { high: th.sev.critical, medium: th.sev.high };
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: th.sev.critical + "12", borderRadius: 6, border: `1px solid ${th.sev.critical}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4, color: th.sev.critical }}>Behavioral Sequence</div>
                        {seqs.map((s, i) => {
                          const sc = seqConfColor[s.confidence] || th.sev.low;
                          return (
                          <div key={i} style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginBottom: i < seqs.length - 1 ? 6 : 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                              <span style={{ color: sc, fontWeight: 600 }}>{s.seqName}</span>
                              <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33` }}>{s.stageName}</span>
                              <span style={{ fontSize: 8, padding: "0px 4px", borderRadius: 2, background: `${sc}18`, color: sc, border: `1px solid ${sc}33`, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.confidence}</span>
                            </div>
                            <div style={{ marginTop: 2, fontSize: 9, color: th.textMuted }}>{s.confidence === "high" ? "same tree" : "same host/user"} {"\u2014"} {s.peers.length} processes {s.tid?.length ? `\u2014 ${s.tid.join(", ")}` : ""}</div>
                          </div>
                        ); })}
                      </div>
                    );
                  })()}
                  {(() => {
                    const nodeStory = _ptNodeStoryMap.get(selectedKey);
                    if (!nodeStory) return null;
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Investigation Story</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, marginBottom: 6 }}>
                          {nodeStory.narrative}
                        </div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                          <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}15`, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.eventCount} events</span>
                          {nodeStory.contextOnlyCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.border}22`, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.contextEventCount} with context</span>}
                          <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.textMuted + "18", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.chainCount} chains</span>
                          {nodeStory.sequenceCount > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: th.sev.critical + "18", color: th.sev.critical, fontFamily: "'SF Mono', Menlo, monospace" }}>{nodeStory.sequenceCount} seq</span>}
                        </div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          <button onClick={() => setModal((p) => ({ ...p, ptViewMode: "story", _ptExpandedIncident: nodeStory.id, selectedKey: nodeStory.anchorKey || selectedKey, ptClusterKeys: null, ptClusterContext: false, searchText: "", ptColFilters: {} }))} style={_ptPivotBtn}>View Story</button>
                          <button onClick={() => _ptCopyStory(nodeStory)} style={_ptPivotBtn}>Copy Story</button>
                        </div>
                      </div>
                    );
                  })()}
                  {/* Execution Timeline — selected process + its children on a shared time axis */}
                  {(() => {
                    const items = [selNode, ...children]
                      .map((p) => ({ p, start: normalizeTimestamp(p.ts), dur: Number.isFinite(p.durationMs) ? p.durationMs : null, lvl: (_ptDetMap.get(p.key) || { level: 0 }).level }))
                      .filter((x) => Number.isFinite(x.start));
                    if (items.length < 2) return null;
                    items.sort((a, b) => a.start - b.start);
                    const minT = items[0].start;
                    let maxT = minT;
                    for (const x of items) maxT = Math.max(maxT, x.start + (x.dur || 0));
                    const span = Math.max(1, maxT - minT);
                    return (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                          <span style={{ ...gLbl, paddingTop: 0 }}>Execution Timeline</span>
                          <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{items.length} procs · {_ptFormatDuration(span)} span</span>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                          {items.slice(0, 24).map((x, i) => {
                            const isSel = x.p.key === selectedKey;
                            const col = SUS_COLORS[x.lvl] || th.textDim;
                            const leftPct = ((x.start - minT) / span) * 100;
                            const widthPct = x.dur != null ? Math.max((x.dur / span) * 100, 1.5) : null;
                            return (
                              <div key={x.p.key + ":" + i}
                                onClick={() => { const en = { ...(modal.expandedNodes || {}), [selectedKey]: true }; setModal((p) => p ? { ...p, selectedKey: x.p.key, expandedNodes: en } : p); }}
                                title={`${x.p.processName} (PID ${x.p.pid}) — ${(x.p.ts || "").replace("T", " ").slice(0, 19)}${x.dur != null ? ` · ${_ptFormatDuration(x.dur)}` : " · no termination recorded"}`}
                                style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", padding: "1px 0" }}>
                                <span style={{ width: 92, flexShrink: 0, fontSize: 9, fontFamily: "'SF Mono', Menlo, monospace", color: isSel ? th.accent : th.textDim, fontWeight: isSel ? 700 : 400, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{x.p.processName}</span>
                                <div style={{ position: "relative", flex: 1, height: 10, background: `${th.border}18`, borderRadius: 2 }}>
                                  {widthPct != null
                                    ? <div style={{ position: "absolute", left: `${leftPct}%`, width: `${Math.min(widthPct, 100 - leftPct)}%`, top: 1, bottom: 1, background: col, opacity: isSel ? 1 : 0.7, borderRadius: 2, minWidth: 2, boxShadow: isSel ? `0 0 0 1px ${th.accent}` : "none" }} />
                                    : <div style={{ position: "absolute", left: `${leftPct}%`, top: 0, width: 4, height: 10, marginLeft: -2, borderRadius: "50%", background: col, opacity: isSel ? 1 : 0.7, boxShadow: isSel ? `0 0 0 1px ${th.accent}` : "none" }} />}
                                </div>
                              </div>
                            );
                          })}
                          {items.length > 24 && <span style={{ fontSize: 9, color: th.textMuted }}>+{items.length - 24} more</span>}
                        </div>
                      </div>
                    );
                  })()}
                  {/* Children chips */}
                  {children.length > 0 && <div style={{ marginTop: 12 }}>
                    <div style={{ ...gLbl, marginBottom: 6 }}>Children ({children.length})</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {children.slice(0, 20).map((c) => {
                        const cSusInfo = _ptDetMap.get(c.key) || { level: 0, reason: null };
                        const cColor = SUS_COLORS[cSusInfo.level];
                        return <span key={c.key} onClick={() => { const en = { ...(modal.expandedNodes || {}), [selectedKey]: true }; setModal((p) => p ? { ...p, selectedKey: c.key, expandedNodes: en } : p); }}
                          style={{ padding: "2px 8px", borderRadius: 4, background: (cColor || th.accent) + "14", color: cColor || th.textDim, fontSize: 10, cursor: "pointer", border: `1px solid ${(cColor || th.border)}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{c.processName} ({c.pid})</span>;
                      })}
                      {children.length > 20 && <span style={{ fontSize: 9, color: th.textDim }}>+{children.length - 20} more</span>}
                    </div>
                  </div>}
                  {/* Chain Context — shows when this node belongs to a repeated cluster */}
                  {(() => {
                    const nodeCluster = _ptNodeClusterMap.get(selectedKey);
                    if (!nodeCluster || nodeCluster.count <= 1) return null;
                    return (
                      <div style={{ marginTop: 12, padding: "8px 10px", background: `${th.accent}08`, borderRadius: 6, border: `1px solid ${th.accent}22` }}>
                        <div style={{ ...gLbl, marginBottom: 4 }}>Chain Context</div>
                        <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", display: "flex", flexDirection: "column", gap: 3 }}>
                          <div>Repeated <strong style={{ color: th.accent }}>{nodeCluster.count}x</strong> across {nodeCluster.users.length} user{nodeCluster.users.length !== 1 ? "s" : ""}</div>
                          <div>First: {(nodeCluster.firstSeen || "").slice(0, 19)} {"\u2014"} Last: {(nodeCluster.lastSeen || "").slice(0, 19)}</div>
                          <div>{nodeCluster.cmdVariants.length} command variant{nodeCluster.cmdVariants.length !== 1 ? "s" : ""}</div>
                        </div>
                        <button onClick={() => setModal(p => ({ ...p, ptViewMode: "triage", _ptExpandedCluster: nodeCluster.id, ptClusterKeys: null, ptClusterContext: false, searchText: "", ptColFilters: {} }))} style={{ marginTop: 6, padding: "2px 8px", background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 4, fontSize: 9, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>View Cluster</button>
                      </div>
                    );
                  })()}
                </div>
              </div>
            );
          })()}
          </div>
          )}

          {/* Footer */}
          {(() => {
            const susCountFooter = flatNodes.filter(n => (_ptDetMap.get(n.key) || { level: 0 }).level > 0).length;
            let treeDepth = 0;
            for (const n of flatNodes) if ((n.depth || 0) > treeDepth) treeDepth = n.depth;
            const fProviders = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
            const fEids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
            return (
          <div style={{ padding: "8px 20px", borderTop: `1px solid ${th.border}44`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, fontSize: 10, color: th.textDim, background: `${th.headerBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", fontFamily: "'SF Mono', Menlo, monospace" }}>
            <span>
              {ptMode.incident
                ? `${filteredStories.length} stor${filteredStories.length !== 1 ? "ies" : "y"} · ${filteredStoryStats.susProcesses} suspicious of ${(data?.stats?.totalProcesses || 0).toLocaleString()} total`
                : ptMode.clustered
                ? `${filteredClusters.length} chain${filteredClusters.length !== 1 ? "s" : ""} · ${filteredStats.susProcesses} suspicious of ${(data?.stats?.totalProcesses || 0).toLocaleString()} total`
                : `${flatNodes.length.toLocaleString()} visible · ${susCountFooter} suspicious · Tree depth: ${treeDepth}`}
              {!ptMode.clustered && selectedKey && ` · Chain: ${chainKeys.size}`}
            </span>
            <span style={{ opacity: 0.7 }}>
              Data: {fProviders || "Events"} EID {fEids || "—"} {"\u2192"} ProcessEvent {"\u2192"} Tree Index by PID/PPID
            </span>
          </div>
            );
          })()}
        </div>
      );
      })()}
    </>)}
  </DraggableResizableModal>
);
}
