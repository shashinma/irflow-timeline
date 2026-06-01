import { useRef } from "react";
import useTabStore from "../store/useTabStore.js";
import { formatNumber } from "../utils/format.js";

/**
 * TabBar — horizontal tab strip with per-tab scroll position tracking.
 *
 * Props:
 *   th             – theme object
 *   scrollTop      – current scroll position (saved per tab on switch)
 *   selectedRows   – current selected rows Set
 *   lastClickedRow – last clicked row index
 *   setScrollTop   – setter for scroll position
 *   setSelectedRows – setter for selected rows
 *   setLastClickedRow – setter for last clicked row
 *   setProximityFilter – setter for proximity filter
 *   scrollRef      – ref to scroll container (to restore scroll position)
 *   closeTab       – function to close a tab by id
 */
export default function TabBar({
  th,
  scrollTop,
  selectedRows,
  lastClickedRow,
  setScrollTop,
  setSelectedRows,
  setLastClickedRow,
  setProximityFilter,
  scrollRef,
  closeTab,
}) {
  const tabs = useTabStore((s) => s.tabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const tabFilter = useTabStore((s) => s.tabFilter);
  const setTabFilter = useTabStore((s) => s.setTabFilter);

  const tabScrollPos = useRef({}); // Per-tab scroll/selection state

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "4px 12px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderBottom: `1px solid ${th.glassBorder}`, overflowX: "auto", flexShrink: 0 }}>
      {tabs.filter((t) => !tabFilter || t.name.toLowerCase().includes(tabFilter.toLowerCase())).map((t) => (
        <div className="tle-tab" key={t.id} onClick={() => {
          if (activeTab) tabScrollPos.current[activeTab] = { scrollTop, selectedRows, lastClickedRow };
          const saved = tabScrollPos.current[t.id];
          setActiveTab(t.id);
          setScrollTop(saved?.scrollTop || 0);
          setSelectedRows(saved?.selectedRows || new Set());
          setLastClickedRow(saved?.lastClickedRow ?? null);
          setProximityFilter(null);
          if (saved?.scrollTop && scrollRef.current) {
            requestAnimationFrame(() => { if (scrollRef.current) scrollRef.current.scrollTop = saved.scrollTop; });
          }
        }}
          style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 14px", cursor: "pointer", color: t.id === activeTab ? th.text : th.textDim, fontSize: 11, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", background: t.id === activeTab ? th.glassBg : "transparent", border: t.id === activeTab ? `1px solid ${th.glassBorder}` : "1px solid transparent", borderRadius: 8, boxShadow: t.id === activeTab ? `0 1px 3px rgba(0,0,0,0.15), inset 0 1px 0 ${th.glassBorder}` : "none" }}>
          {t.importing && <span style={{ color: th.warning }}>⏳</span>}
          {t.id === activeTab && <span style={{ width: 6, height: 6, borderRadius: 3, background: th.accent, flexShrink: 0 }} />}
          <span style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</span>
          <span style={{ color: th.textMuted, fontSize: 10 }}>({formatNumber(t.totalRows || 0)})</span>
          <button onClick={(e) => { e.stopPropagation(); closeTab(t.id); }} aria-label={`Close tab ${t.name}`} title={`Close ${t.name}`}
            onMouseEnter={(e) => { e.currentTarget.style.color = th.danger; e.currentTarget.style.background = th.danger + "1f"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; e.currentTarget.style.background = "none"; }}
            style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, padding: "0 4px", borderRadius: 4, transition: "background var(--m-fast) var(--ease-out), color var(--m-fast) var(--ease-out)" }}>✕</button>
        </div>
      ))}
      {tabs.length >= 3 && (
        <div style={{ display: "flex", alignItems: "center", marginLeft: "auto", flexShrink: 0, padding: "0 4px" }}>
          <input value={tabFilter} onChange={(e) => setTabFilter(e.target.value)}
            placeholder="Filter tabs..."
            style={{ width: 110, padding: "2px 6px", background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 6, color: th.text, fontSize: 10, outline: "none", fontFamily: "-apple-system, sans-serif" }} />
          {tabFilter && <button onClick={() => setTabFilter("")} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, padding: "0 3px", marginLeft: 2 }}>✕</button>}
        </div>
      )}
    </div>
  );
}
