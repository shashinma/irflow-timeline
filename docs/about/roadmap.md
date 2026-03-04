# Roadmap

This page outlines the planned direction for IRFlow Timeline. Priorities may shift based on community feedback and real-world investigation needs. Have a feature request? [Open an issue](https://github.com/r3nzsec/irflow-timeline/issues) on GitHub.

---

## In Progress

### Enhanced Detection Rules
- Expand the detection rules library beyond the current ones
- Community-contributed rule packs with shared rule repositories

### MFT & $J File Support
- Native `.mft` `.$J` file parsing without requiring pre-processing through MFTECmd
- Direct ingestion of raw $MFT $J files from forensic images
- Ransomware analytics based on $MFT data

---

## Planned

### Cross-Platform Support
- **Windows** and **Linux** builds to make IRFlow Timeline available beyond macOS
- Platform-specific packaging (MSI/EXE for Windows, AppImage/deb for Linux)

### Sigma Rule Integration
- Import and match Sigma detection rules against event log timelines
- Map Sigma rule hits to MITRE ATT&CK techniques alongside existing detections
- Support for custom Sigma rule collections

### Timeline Diffing
- Compare two timelines or sessions side by side
- Highlight events present in one timeline but not the other
- Useful for comparing baseline vs. compromised host activity

### Collaborative Sessions
- Share `.tle` session files with annotations via a link
- Real-time collaborative analysis for team-based investigations

---

## Under Consideration

### AI-Assisted Analysis
- LLM-powered summarization of tagged findings for report drafting
- Natural language queries against timeline data ("show me all lateral movement after 3 AM")
- Anomaly detection suggestions based on statistical patterns

### Plugin System
- Extensible architecture for community-developed analysis modules
- Custom parsers for proprietary log formats

### Cloud Evidence Formats
- Native parsing of Azure AD sign-in logs, AWS CloudTrail, GCP audit logs
- Unified authentication timeline across on-prem and cloud environments

### Network Traffic Integration
- Zeek/Bro log ingestion for network-level correlation
- Merge network and host timelines for full-stack visibility

### Auto-Update
- In-app update notifications and one-click updates
- Delta updates to minimize download size

---

## Recently Completed

See the [Changelog](/about/changelog) for detailed release notes on everything shipped so far. Highlights from recent releases:

- **v1.0.3-beta** — Lateral Movement attack pattern detection, RDP session grouping, menu bar redesign, row checkbox selection, Find Duplicates, Persistence Analyzer custom rules
- **v1.0.2-beta** — 342 detection rules library, import queue system, IOC matching expansion (17+ types), Process Tree overhaul, Lateral Movement expansion with RDP correlation
- **v1.0.0-beta** — Persistence Analyzer (30+ techniques), lateral movement outlier detection, background indexing pipeline, phase-tuned SQLite performance
