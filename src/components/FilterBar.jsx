import { useState, useEffect } from "react";
import useUIStore from "../store/useUIStore.js";
import { formatNumber } from "../utils/format.js";
import { Tooltip } from "./primitives/index.js";

/**
 * FilterBar — search input capsule + search options bar + regex pattern palette.
 *
 * Props:
 *   th               – theme object
 *   ct               – current tab object
 *   up               – function to update current tab field
 *   isGrouped        – whether grouping is active
 *   searchLoading    – boolean, search in progress
 *   searchMatchIdx   – current search match index
 *   hlMatchIndices   – array of highlight match indices (or null)
 *   navigateSearch   – function(direction) to navigate matches
 */
export default function FilterBar({
  th,
  ct,
  up,
  isGrouped,
  searchLoading,
  searchMatchIdx,
  hlMatchIndices,
  navigateSearch,
}) {
  const [regexPaletteOpen, setRegexPaletteOpen] = useState(false);

  // ESC closes the regex palette (parity with other popovers via App.jsx central handler).
  // Local handler so the rest of App.jsx ESC chain doesn't need to reach into local state.
  useEffect(() => {
    if (!regexPaletteOpen) return;
    const onKey = (e) => { if (e.key === "Escape") setRegexPaletteOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [regexPaletteOpen]);

  const tb = { display: "flex", alignItems: "center", gap: 5, padding: "5px 12px", background: "transparent", color: th.textDim, border: "none", borderRadius: 8, fontSize: 13, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" };

  return (
    <>
      {/* Search capsule — rendered inside the toolbar by the parent; this is the standalone search bar area */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flex: 1, maxWidth: 560, background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 10, padding: "0 10px", WebkitAppRegion: "no-drag" }}>
        {searchLoading && ct?.searchTerm ? (
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" style={{ animation: "tle-spin 0.8s linear infinite", flexShrink: 0 }}>
            <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></svg>
        ) : (
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" style={{ flexShrink: 0 }}><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
        )}
        <input id="gs" value={ct?.searchTerm || ""} onChange={(e) => up("searchTerm", e.target.value)} placeholder='Search: terms, +AND, -NOT, "phrase", Col:val'
          style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: th.text, fontSize: 12, padding: "6px 0", fontFamily: "inherit" }} />
        {(() => {
          const mode = ct?.searchMode || "mixed";
          const isDefault = mode === "mixed";
          return (
            <select value={mode} onChange={(e) => up("searchMode", e.target.value)}
              title={isDefault ? "Search mode" : `Search mode: ${mode.toUpperCase()} — non-default, results differ from Mixed`}
              style={{ background: isDefault ? th.btnBg : th.warning + "22", border: isDefault ? "none" : `1px solid ${th.warning}66`, color: isDefault ? th.textDim : th.warning, fontSize: 10, fontWeight: isDefault ? 400 : 600, padding: "2px 5px", borderRadius: 3, cursor: "pointer", outline: "none" }}>
              <option value="mixed">Mixed</option><option value="or">OR</option><option value="and">AND</option><option value="exact">Exact</option><option value="regex">Regex</option>
            </select>
          );
        })()}
        <Tooltip content={ct?.searchHighlight ? "Highlight mode — showing all rows, highlighting matches" : "Filter mode — hiding non-matching rows"}>
          <button onClick={() => ct && up("searchHighlight", !ct.searchHighlight)}
            aria-label={ct?.searchHighlight ? "Switch to filter mode" : "Switch to highlight mode"}
            style={{ background: ct?.searchHighlight ? `${th.warning}33` : "none", border: ct?.searchHighlight ? `1px solid ${th.warning}66` : "1px solid transparent", color: ct?.searchHighlight ? th.warning : th.textMuted, cursor: "pointer", fontSize: 10, padding: "1px 5px", borderRadius: 3, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
            {ct?.searchHighlight ? "HL" : "FL"}
          </button>
        </Tooltip>
        {ct?.searchTerm && !isGrouped && (
          searchLoading ? (
            <span style={{ color: th.accent, fontSize: 10, whiteSpace: "nowrap", fontStyle: "italic" }}>Searching...</span>
          ) : (
            <>
              <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>
                {ct.searchHighlight && hlMatchIndices
                  ? `${hlMatchIndices.indexOf(searchMatchIdx) >= 0 ? hlMatchIndices.indexOf(searchMatchIdx) + 1 : 0}/${hlMatchIndices.length}`
                  : (ct?.totalFiltered || 0) > 0 ? `${searchMatchIdx >= 0 ? searchMatchIdx + 1 : 0}/${formatNumber(ct.totalFiltered)}` : "0"}
              </span>
              <Tooltip content="Previous match (Shift+F3)">
                <button onClick={() => navigateSearch(-1)} aria-label="Previous match" style={{ background: "none", border: "none", color: th.textDim, cursor: "pointer", fontSize: 12, padding: "0 2px", lineHeight: 1 }}>▲</button>
              </Tooltip>
              <Tooltip content="Next match (F3)">
                <button onClick={() => navigateSearch(1)} aria-label="Next match" style={{ background: "none", border: "none", color: th.textDim, cursor: "pointer", fontSize: 12, padding: "0 2px", lineHeight: 1 }}>▼</button>
              </Tooltip>
            </>
          )
        )}
        {ct?.searchTerm && <button onClick={() => up("searchTerm", "")} aria-label="Clear search" title="Clear search" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11 }}>✕</button>}

        {/* Regex Pattern Palette */}
        <div style={{ position: "relative" }}>
          <button onClick={() => setRegexPaletteOpen((v) => !v)}
            title="Regex Pattern Palette — quick-insert common forensic patterns"
            style={{ background: regexPaletteOpen ? `${th.accent}22` : "none", border: regexPaletteOpen ? `1px solid ${th.accent}66` : "1px solid transparent", color: regexPaletteOpen ? th.accent : th.textMuted, cursor: "pointer", fontSize: 10, padding: "1px 5px", borderRadius: 3, fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 700, whiteSpace: "nowrap", lineHeight: "16px" }}>Rx</button>
          {regexPaletteOpen && (<>
            <div onClick={() => setRegexPaletteOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 149 }} />
            <div style={{ position: "absolute", top: "100%", right: 0, marginTop: 6, background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", padding: "6px 0", zIndex: 150, boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", minWidth: 260, maxHeight: "70vh", overflow: "auto", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
              <div style={{ padding: "4px 12px 6px", borderBottom: `1px solid ${th.border}`, marginBottom: 4 }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: th.textDim, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Forensic Regex Patterns</span>
              </div>
              {[
                { label: "IPv4 Address", pattern: "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", icon: "IP" },
                { label: "IPv6 Address", pattern: "\\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}\\b", icon: "v6" },
                { label: "Domain Name", pattern: "\\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+\\b", icon: "DN" },
                { label: "Email Address", pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", icon: "@" },
                { label: "sep" },
                { label: "MD5 Hash", pattern: "\\b[a-fA-F0-9]{32}\\b", icon: "M5" },
                { label: "SHA1 Hash", pattern: "\\b[a-fA-F0-9]{40}\\b", icon: "S1" },
                { label: "SHA256 Hash", pattern: "\\b[a-fA-F0-9]{64}\\b", icon: "S2" },
                { label: "sep" },
                { label: "Base64 Blob", pattern: "[A-Za-z0-9+/]{20,}={0,2}", icon: "B6" },
                { label: "Windows SID", pattern: "S-1-[0-9](-[0-9]+){1,}", icon: "SI" },
                { label: "UNC Path", pattern: "\\\\\\\\[a-zA-Z0-9._-]+\\\\[a-zA-Z0-9._$\\\\-]+", icon: "\\\\" },
                { label: "Windows File Path", pattern: "[A-Za-z]:\\\\[^\\s\"'<>|]+", icon: "C:" },
                { label: "Unix File Path", pattern: "/[a-zA-Z0-9._/-]{2,}", icon: "/" },
                { label: "sep" },
                { label: "URL (http/https)", pattern: "https?://[^\\s\"'<>]+", icon: "://" },
                { label: "Registry Key", pattern: "(HKLM|HKCU|HKU|HKCR|HKCC)\\\\[^\\s\"]+", icon: "HK" },
                { label: "MAC Address", pattern: "\\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b", icon: "MA" },
              ].map((item, i) => item.label === "sep" ? (
                <div key={i} style={{ height: 1, background: th.border, margin: "4px 0" }} />
              ) : (
                <button key={item.label} onClick={() => {
                  up("searchTerm", item.pattern);
                  up("searchMode", "regex");
                  setRegexPaletteOpen(false);
                  setTimeout(() => document.getElementById("gs")?.focus(), 50);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 22, textAlign: "center", fontSize: 9, fontWeight: 700, color: th.accent, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{item.icon}</span>
                  <span style={{ flex: 1 }}>{item.label}</span>
                  <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.pattern}>{item.pattern.length > 18 ? item.pattern.slice(0, 18) + "..." : item.pattern}</span>
                </button>
              ))}
            </div>
          </>)}
        </div>
      </div>
    </>
  );
}

/**
 * SearchOptionsBar — condition/match/behavior row shown when search is active.
 */
export function SearchOptionsBar({ th, ct, up }) {
  if (!ct || !ct.searchTerm) return null;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "3px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0 }}>
      <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Condition:</span>
      {[["contains", "Contains"], ["fuzzy", "Fuzzy"], ["startswith", "Starts with"], ["like", "Like"], ["equals", "Equals"]].map(([v, l]) => (
        <label key={v} style={{ display: "flex", alignItems: "center", gap: 3, cursor: "pointer" }}>
          <input type="radio" name="searchCondition" value={v} checked={(ct.searchCondition || "contains") === v}
            onChange={() => up("searchCondition", v)} style={{ margin: 0, accentColor: th.accent }} />
          <span style={{ color: (ct.searchCondition || "contains") === v ? th.accent : th.textDim, fontSize: 10 }}>{l}</span>
        </label>
      ))}
      <div style={{ width: 1, height: 14, background: th.border }} />
      <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Match:</span>
      <select value={ct.searchMode || "mixed"} onChange={(e) => up("searchMode", e.target.value)}
        style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "2px 5px", borderRadius: 3, cursor: "pointer", outline: "none" }}>
        <option value="mixed">Mixed</option><option value="or">OR</option><option value="and">AND</option><option value="exact">Exact</option><option value="regex">Regex</option>
      </select>
      <div style={{ width: 1, height: 14, background: th.border }} />
      <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Behavior:</span>
      <button onClick={() => up("searchHighlight", false)}
        style={{ fontSize: 10, color: !ct.searchHighlight ? th.accent : th.textDim, background: !ct.searchHighlight ? `${th.accent}22` : "none", border: `1px solid ${!ct.searchHighlight ? th.accent + "4D" : "transparent"}`, borderRadius: 3, padding: "1px 6px", cursor: "pointer" }}>Filter</button>
      <button onClick={() => up("searchHighlight", true)}
        style={{ fontSize: 10, color: ct.searchHighlight ? th.warning : th.textDim, background: ct.searchHighlight ? `${th.warning}22` : "none", border: `1px solid ${ct.searchHighlight ? th.warning + "4D" : "transparent"}`, borderRadius: 3, padding: "1px 6px", cursor: "pointer" }}>Highlight</button>
    </div>
  );
}
