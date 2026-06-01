---
description: IRFlow Timeline architecture — React renderer, Electron main process, a worker-thread pool, the SQLite data engine, forensic analyzers, and streaming parsers.
---

# Architecture

Technical overview of IRFlow Timeline's architecture for developers and contributors.

> **v1.0.6 is a modular refactor.** What was once a ~20K-line `App.jsx` and a monolithic `electron/parser.js` / `electron/db.js` is now decomposed into ~150 focused modules across the renderer and main process. The file references below reflect that layout.

## System Architecture

![IRFlow Timeline layered architecture: React renderer, preload bridge, Electron main-process services, worker-thread pool, SQLite data engine with forensic analyzers, and streaming parsers, connected by IPC and with side connectors for evidence, external tools, network, local state, and outputs](/dfir-tips/Architecture-Diagram.svg)

The diagram uses a **semantic color system** — color maps to function, not just layer:

| Color | Meaning |
|-------|---------|
| 🟠 Orange | UI / output surface |
| 🟣 Violet | Secure IPC bridge |
| 🔵 Blue | Orchestration & network |
| 🟡 Amber | Ingestion & compute |
| 🟢 Green | Data & persistence |
| 🔴 Red | Forensic detection |

## Layer Responsibilities

### Renderer Process (React)

**Entry:** `src/main.jsx` (~60 lines) → **Coordinator:** `src/App.jsx` (~3,800 lines)

The renderer runs in a sandboxed browser context with no direct Node.js access — all system operations go through the IPC bridge. `App.jsx` is now a thin top-level coordinator; responsibility is distributed across focused trees:

- **`components/`** — `VirtualGrid`, `MenuBar`, `FilterBar`, `TabBar`, `StatusBar`; `primitives/` (Modal, Button, Toast, ConfirmDialog, …); `modals/` (one file per analysis modal — Sigma, Lateral Movement, Persistence, Ransomware, USN, ADS, Timestomping, RDP bitmap cache, …); `process-analyzer/` (process-tree UI subsystem)
- **`store/`** — Zustand stores: `useTabStore`, `useUIStore`, `useGridInteractionStore`, `useConfirmStore`, `useToastStore`
- **`hooks/`**, **`modals/modalRegistry.js`** (namespaced modal state), **`constants/`** (`themes.js`, `presets.js`, `kape-profiles.js`, …), **`utils/`** (`ipc-result.js`, `datetime.js`, a mirror of `forensic-normalize`, …)
- **`detection-rules.js`** (~400 lines) + **`detection-rules/`** (`tool-aliases.js` — the canonical RMM/tunnel/exfil tool catalog), mapped to MITRE ATT&CK and consumed by the process analyzer

Responsibilities: grid rendering with virtual scrolling, user-interaction handling, Zustand state management, visualization (histogram, process inspector, lateral-movement graphs, NTFS analysis panels), KAPE profile auto-detection, VirusTotal verdict display, and theme management (dark default + light).

### Preload Bridge

**File:** `electron/preload.js` (~240 lines)

The preload script creates a secure bridge between renderer and main using Electron's `contextBridge`. It exposes a **whitelisted `window.tle` API** with `contextIsolation` enabled and `nodeIntegration` disabled. All renderer↔main calls go through here as invoke-only channels; listener registrations return unsubscribe functions. Channels cover file ops, queries, tag/bookmark ops, IOC/VirusTotal enrichment, analysis (NTFS, lateral movement, Sigma, RDP bitmap cache), jobs, session persistence, filter presets, and auto-update.

### Main Process (Electron)

**Files:** `main.js` (~520 lines) · `import.js` (~240) · `menu.js` (~290) · `updater.js` (~545) · `logger.js` (~50) · `ipc/` (13 modules)

The main process runs with full Node.js access and acts as the orchestrator:

- **`main.js`** — creates the `BrowserWindow`, wires crash guards, defines the `safeHandle` / `safeSend` IPC primitives, owns the serialized import queue and the deferred index/FTS build queue, and delegates IPC registration to `ipc/index.js`, menus to `menu.js`, and updates to `updater.js`. Raises the V8 heap to **16 GB** for large imports.
- **`import.js`** — import pipeline: validation, XLSX sheet selection, large-file warnings, USN↔MFT path resolution, and index scheduling.
- **`ipc/`** — one registration module per domain (`query-`, `tag-`, `analysis-`, `export-`, `session-`, `vt-`, `sigma-`, `job-`, `rdp-bitmap-cache-`), all registered by `ipc/index.js`. **159 handlers** total, each wrapped by `safeHandle()`.
- **`updater.js`** — auto-update lifecycle (check → download → install) via `electron-updater`.
- **`logger.js`** — shared singleton debug logger with ~5 MB rotation and a write buffer (`~/tle-debug.log`); `dbg(scope, message, data?)`.

`safeHandle`/`safeSend` wrap every handler to log and catch errors; on failure they return `{ __ipcError: true, message }`, which the renderer must check via `isIpcError()` — a resolved value is not necessarily success.

### Worker Threads

**Files:** `electron/jobs/job-manager.js` + `import-worker.js` · `index-worker.js` · `analyzer-worker.js` · `sigma-worker.js`

CPU-heavy work runs off the main thread in `worker_threads`, coordinated by `job-manager.js`:

- **`import-worker`** — streams a source file through `parsers/index.js` into a temp SQLite DB
- **`index-worker`** — builds column indexes, then the FTS5 index, in the background
- **`analyzer-worker`** — runs forensic detectors
- **`sigma-worker`** — runs Sigma / Hayabusa scans

Workers parse/scan into their own temp SQLite files that the main process then **adopts** (`db.adoptTabFromFile()`). Progress streams over IPC; cancellation is `postMessage('cancel')` → 250 ms grace → `terminate()`.

### Data Engine (SQLite)

**Files:** `electron/db.js` facade (~1,435 lines) + `electron/db/` submodules (~1,850 lines)

The `TimelineDB` facade wraps `better-sqlite3`. Each tab gets its own temp SQLite DB in `os.tmpdir()`. Logic is split into submodules:

- **`query-store.js`** — filter / sort / paginate / search
- **`tag-store.js`** — tags / bookmarks / bulk ops
- **`timeline-analytics.js`** — histogram / gap / burst / stacking / log-source coverage
- **`runtime-functions.js`** — custom SQLite UDFs

**Schema per tab** (columns sanitized to `c0..cN` at creation, mapped back via `colMap`):
```sql
CREATE TABLE data (rowid INTEGER PRIMARY KEY, c0 TEXT, c1 TEXT, ...);
CREATE VIRTUAL TABLE data_fts USING fts5(c0, c1, ..., content=data);
CREATE TABLE bookmarks (rowid INTEGER PRIMARY KEY);
CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY(rowid, tag));
CREATE TABLE color_rules (id, col_name, condition, value, bg_color, fg_color);
```

**Custom SQL functions (5):** `REGEXP`, `FUZZY_MATCH`, `EXTRACT_DATE`, `EXTRACT_DATETIME_MINUTE`, `SORT_DATETIME` (the last also backs sortable expression indexes).

**Performance tuning (phase-dependent):**
- Import: `journal_mode=OFF`, large cache, mmap disabled (write-only)
- Index/FTS build: deferred until the import queue drains, yielding to the event loop
- Query: WAL mode, 256 MB cache, mmap enabled; passive `wal_checkpoint` every 5 min
- Column indexes (then FTS5) built asynchronously after import

### Forensic Analyzers & Detection

**Directory:** `electron/analyzers/` — **10 domains**

The renderer never touches SQLite directly; the main process owns the `db` facade and delegates specialized detection to analyzer modules, each querying the tab DB and returning findings with severity / MITRE mapping:

- Standalone modules: `ransomware.js`, `timestomping.js`, `ads.js`, `file-activity.js`, `usn-journal.js`
- Subsystems: `lateral-movement/`, `persistence/`, `process-tree/`, `rdp-bitmap-cache/`, `sigma/`

**Dual Sigma / Hayabusa detection engine** (`analyzers/sigma/`, ~26 modules):
1. **In-app JS Sigma engine** — `condition-compiler.js` compiles Sigma detection YAML to a JS predicate; `field-mapper.js` resolves fields across formats (raw EVTX / EvtxECmd / Hayabusa / Chainsaw); `logsource-mapper.js` pre-filters candidate rows; `rule-cache`/`rule-parser`/`rule-compatibility`/`rule-suppression`/`rule-diff` manage rules; `result-store.js` persists findings.
2. **Hayabusa binary engine** — `analyzers/sigma/evtx-scanner/`: `binary-manager.js` (discover/verify the bundled binary), `command-builder.js`, `scan-process.js` (subprocess lifecycle + cancellation), `scan-runner.js`, `progress-parser.js`, `output-parser.js`.

**RDP bitmap cache** (`analyzers/rdp-bitmap-cache/`) wraps the bundled **bmc-tools** to recover bitmap tiles from `bcache*.bmc` / `cache????.bin`, records source/output hashes, and exports an evidence package.

External-tool and scan inputs are validated through `utils/path-authorizer.js` scopes.

### Parser Layer

**Directory:** `electron/parsers/` — dispatched by `parsers/index.js` (extension + magic-byte detection)

Streaming parsers convert source files into batched SQLite inserts:

- **`csv.js`** — RFC 4180, delimiter auto-detect, quote-aware; raw chunk processing with adaptive batches (up to 100,000 rows, ~100 MB target per batch)
- **`xlsx.js`** — ExcelJS streaming `WorkbookReader` with spill-to-SQLite shared strings (`.xls` falls back to SheetJS)
- **`evtx.js`** — `@ts-evtx/core` binary parsing with dynamic schema discovery
- **`plaso.js`** — Plaso SQLite databases via ATTACH + zlib
- **`mft.js`** — two-pass raw `$MFT` parser (pass 1 builds directory + FN attribute maps, pass 2 reconstructs full paths); outputs **34 columns** matching MFTECmd, with SI-vs-FN timestamp comparison and resident-data detection
- **`usn.js`** — raw `$UsnJrnl:$J` parser with reason-flag decoding and file-reference extraction

## Data Flow

### Import Pipeline

```
open → main.enqueueImport() → import-worker (parsers/index.js, streaming)
     → temp SQLite DB → main.adoptTabFromFile() → renderer (row window + metadata)
     → after queue drains: index-worker (column indexes → FTS5)
```

1. A file is opened (dialog / drag-drop / `open-file`) and added to the serialized import queue.
2. XLSX with multiple sheets → the renderer shows a sheet picker first.
3. `import-worker` streams the file into a temp SQLite DB; progress via `import-progress`.
4. On completion the main process adopts the worker's DB; the initial row window + metadata go to the renderer.
5. After the queue drains, `index-worker` builds column indexes, then the FTS5 index, in the background (`index-progress` / `fts-progress`).

### Query Pipeline

```
UI action → IPC → db.queryRows() → SQL (filters/sort) → LIMIT/OFFSET window → IPC → grid
              ↓
         debounce (search/filter)
```

1. The user scrolls, searches, or filters.
2. The request is debounced.
3. SQL is built with active filters, sort, and pagination.
4. A bounded result window is returned via IPC.
5. The grid renders the visible rows from the cached window (the renderer holds ~5K rows; SQL `LIMIT/OFFSET` windows fetch more as the user scrolls).

## Technology Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| **Electron** | ^33.2.1 | Native app container |
| **React** | ^18.3.1 | UI framework |
| **Zustand** | ^5.0.12 | Renderer state stores |
| **Vite** | ^6.0.7 | Build tooling |
| **better-sqlite3** | ^11.7.0 | SQLite bindings (zero-copy) |
| **ExcelJS** | ^4.4.0 | XLSX streaming |
| **SheetJS (xlsx)** | ^0.18.5 | Legacy XLS parsing |
| **@ts-evtx/core** | ^1.1.1 | EVTX binary parsing |
| **csv-parser** | ^3.0.0 | CSV parsing |
| **js-yaml** | ^4.1.1 | Sigma rule parsing |
| **electron-updater** | ^6.6.7 | Auto-update framework |
| **electron-builder** | ^25.1.8 | App packaging |

External binaries bundled as `extraResources`: **Hayabusa** (Sigma over raw EVTX) and **bmc-tools** (RDP bitmap cache).

## Build Targets

| Target | Command | Output |
|--------|---------|--------|
| **Development** | `npm run dev` | Vite + Electron hot reload |
| **Quick start** | `npm run start` | Build + run |
| **Bundle tools** | `npm run bundle:tools` | Download Hayabusa + bmc-tools |
| **DMG** | `npm run dist:dmg` | macOS installer |
| **Universal** | `npm run dist:universal` | Intel + Apple Silicon |
| **Smoke build** | `npm run dist:smoke` | Unsigned local build (`SKIP_NOTARIZE=1`) |
| **Tests** | `npm test` | `node --test tests/*.test.js` |

`npm run dist*` runs `bundle:tools` first. After `npm install`, run `npm run rebuild` to rebuild `better-sqlite3` against Electron's ABI.

## Security Model

- **Context isolation** enabled — the renderer has no Node.js access
- **Preload bridge** exposes only a whitelisted `window.tle` surface (invoke-only channels)
- **Offline-first** — all forensic processing runs locally; no remote content is loaded
- **Minimal network access** — only opt-in VirusTotal lookups (user-provided API key) and auto-update checks
- **Path authorization** — external-tool and scan inputs are validated through `utils/path-authorizer.js` scopes
- **Hardened runtime** + notarization for macOS distribution
- **VirusTotal API key** stored locally in `userData`, transmitted only to VirusTotal's API endpoint
