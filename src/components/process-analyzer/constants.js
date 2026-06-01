export const PT_ICON_STYLE = { width: 14, height: 14, verticalAlign: "middle", flexShrink: 0 };

export const PT_VIEW_MODES = {
  story:  { label: "Story",  filter: "suspicious", clustered: true, incident: true },
  triage: { label: "Triage", filter: "suspicious", clustered: true },
  hunt:   { label: "Hunt",   filter: "medium+",    clustered: true },
  raw:    { label: "Raw",    filter: "all",         clustered: false },
};

export const PI_ANALYST_PROFILE_DEFAULT = { version: 1, suppressions: [], baselines: [] };
