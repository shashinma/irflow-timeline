export const THEMES = {
  dark: {
    bg: "#0f1114", bgAlt: "#181b20", bgInput: "#12151a", border: "#2a2d33", borderAccent: "#E85D2A",
    text: "#e0ddd8", textDim: "#9a9590", textMuted: "#7a7470", accent: "#E85D2A", accentHover: "#F47B50",
    rowOdd: "#141720", rowEven: "#0f1114", headerBg: "#181b20", headerText: "#E85D2A",
    selection: "rgba(232,93,42,0.14)", bookmark: "rgba(232,93,42,0.06)",
    modalBg: "#181b20", modalBorder: "#333639", overlay: "rgba(5,5,8,0.85)",
    success: "#4ade80", warning: "#F5A623", danger: "#f85149",
    btnBg: "#22252a", btnBorder: "#333639",
    // Unit 42 extended palette
    panelBg: "#0b0d10", cellBorder: "#12151a", accentSubtle: "rgba(232,93,42,0.12)",
    histBar: "#E85D2A", histBarHover: "#F47B50", histGrid: "#1e2028",
    primaryBtn: "#E85D2A", primaryBtnHover: "#C44D1E",
    toolbarBg: "rgba(24,27,32,0.82)", glassBg: "rgba(255,255,255,0.05)", glassBorder: "rgba(255,255,255,0.08)", glassHover: "rgba(255,255,255,0.10)",
    // Severity palette — used by SUS_COLORS, INT_COLOR, PI_SEV_COLORS, IOC verdicts.
    // Distinct from brand `accent` (which is #E85D2A): severity needs cooler reds, deeper amber, etc.
    sev: { critical: "#f85149", high: "#f0883e", med: "#d29922", low: "#8b949e", custom: "#a371f7", clean: "#3fb950", info: "#58a6ff" },
  },
  light: {
    bg: "#ffffff", bgAlt: "#f7f5f3", bgInput: "#ffffff", border: "#e0dbd6", borderAccent: "#E85D2A",
    text: "#1c1917", textDim: "#6b6560", textMuted: "#a09a94", accent: "#E85D2A", accentHover: "#C44D1E",
    rowOdd: "#faf8f6", rowEven: "#ffffff", headerBg: "#f7f5f3", headerText: "#E85D2A",
    selection: "rgba(232,93,42,0.10)", bookmark: "rgba(232,93,42,0.06)",
    modalBg: "#ffffff", modalBorder: "#e0dbd6", overlay: "rgba(28,25,23,0.5)",
    success: "#16a34a", warning: "#B86E00", danger: "#dc2626",
    btnBg: "#f0ebe6", btnBorder: "#e0dbd6",
    // Unit 42 extended palette
    panelBg: "#f0ebe6", cellBorder: "#ebe6e0", accentSubtle: "rgba(232,93,42,0.08)",
    histBar: "#E85D2A", histBarHover: "#C44D1E", histGrid: "#e0dbd6",
    primaryBtn: "#E85D2A", primaryBtnHover: "#C44D1E",
    toolbarBg: "rgba(247,245,243,0.82)", glassBg: "rgba(0,0,0,0.03)", glassBorder: "rgba(0,0,0,0.06)", glassHover: "rgba(0,0,0,0.08)",
    sev: { critical: "#dc2626", high: "#cc4400", med: "#a16207", low: "#6b6560", custom: "#7c3aed", clean: "#16a34a", info: "#3b82f6" },
  },
};
