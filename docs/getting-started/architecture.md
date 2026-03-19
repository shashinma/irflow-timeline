---
description: IRFlow Timeline architecture — React UI, Electron main process, SQLite data engine, and streaming parsers.
---

# Architecture

Technical overview of IRFlow Timeline's architecture for developers and contributors.

## System Architecture

![IRFlow Timeline four-layer architecture: React UI Layer, Electron Main Process, SQLite Data Engine, and Parser Layer connected via IPC and streaming I/O](/dfir-tips/Architecture-Diagram.svg)

## Layer Responsibilities

### Renderer Process (React)

**File:** `src/App.jsx` (~19,900 lines) + `src/detection-rules.js` (~383 lines)

The renderer runs in a sandboxed browser context with no direct Node.js access. All system operations go through the IPC bridge.

Responsibilities:
- Grid rendering with virtual scrolling
- User interaction handling
- State management (React hooks)
- Visualization rendering (histogram, process inspector, lateral movement graphs, NTFS analysis panels)
- 24 KAPE profile auto-detection with optimized column layouts
- VirusTotal verdict display and enrichment UI
- Theme management (dark/light)

### Preload Bridge

**File:** `preload.js` (~137 lines)

The preload script creates a secure bridge between the renderer and main process using Electron's `contextBridge` API. It exposes ~112 methods and event listeners as `window.tle`, covering file ops, data queries, tag/bookmark ops, IOC matching, VirusTotal enrichment, NTFS analysis, analyst profiles, auto-updates, session persistence, and filter presets.

### Main Process (Electron)

**Files:** `main.js` (~2,050 lines) + `updater.js` (~544 lines) + `logger.js` (~46 lines)

The main process runs with full Node.js access and manages:
- Window lifecycle and native menus
- IPC handler registration (72 handlers via `safeHandle()`)
- File dialog management
- Export orchestration (CSV, TSV, XLSX, XLS, HTML, PDF)
- Session save/load coordination
- VirusTotal API integration with persistent SQLite cache (`vt-cache.db`)
- Auto-update lifecycle (check → download → install) via `electron-updater`
- Shared debug logger with 5MB rotation and 50-line write buffer (`~/tle-debug.log`)
- macOS integration (vibrancy, dark mode, traffic lights)

### Data Engine (SQLite)

**File:** `db.js` (~14,100 lines)

The `TimelineDB` class wraps `better-sqlite3` with forensic-analysis-specific operations:

**Schema per tab:**
```sql
CREATE TABLE data (rowid INTEGER PRIMARY KEY, c0 TEXT, c1 TEXT, ...);
CREATE VIRTUAL TABLE data_fts USING fts5(c0, c1, ..., content=data);
CREATE TABLE bookmarks (rowid INTEGER PRIMARY KEY);
CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY(rowid, tag));
CREATE TABLE color_rules (id, col_name, condition, value, bg_color, fg_color);
```

**Custom SQL functions (5):**
- `REGEXP(pattern, value)` — deterministic regex matching
- `FUZZY_MATCH(text, term)` — n-gram similarity for typo tolerance
- `EXTRACT_DATE(value)` — normalize any timestamp to `yyyy-MM-dd`
- `EXTRACT_DATETIME_MINUTE(value)` — normalize to `yyyy-MM-dd HH:mm`
- `SORT_DATETIME(value)` — normalize any timestamp to sortable ISO string (also used for expression indexes)

**NTFS analysis modules:**
- Ransomware analysis — extension scanning, ransom note detection, USN cross-reference, timing evidence
- Timestomping detection — SI vs FN timestamp comparison with severity scoring
- File activity heatmap — hourly/daily buckets and 7×24 day-of-week matrix
- ADS analyzer — Zone.Identifier parsing, suspicious stream detection
- USN Journal analysis — 11 forensic categories (renames, deletions, creations, exfiltration, execution, persistence, suspicious paths, security changes, data overwrite, stream changes, close patterns)
- USN path resolution — parent reference chain-walking with MFT cross-reference

**Performance tuning (phase-dependent):**
- Import: `journal_mode=OFF`, 1GB cache, 64KB pages, `threads=4`
- Index/FTS build: `journal_mode=OFF`, 1GB cache, `threads=8`
- Query: WAL mode, 256MB cache, 512MB MMAP
- Exclusive locking throughout (single-user optimization)
- All columns indexed asynchronously after import

### Parser Layer

**File:** `parser.js` (~2,600 lines)

Streaming parsers convert source files into SQLite batch inserts:

- **CSV:** 128MB chunk reader, RFC 4180 compliant, auto-delimiter detection
- **XLSX:** ExcelJS `WorkbookReader` for memory-efficient streaming
- **XLS:** SheetJS in-memory reader for legacy binary Excel format
- **EVTX:** `@ts-evtx` binary parsing with dynamic schema discovery
- **Plaso:** Direct SQLite query via `better-sqlite3`
- **$MFT:** Two-pass binary parser — pass 1 builds directory map + FN attribute map, pass 2 reconstructs full paths. Outputs 22 columns matching MFTECmd format. Includes SI vs FN timestamp comparison and resident data detection
- **$J (USN Journal):** Binary parser for raw `$UsnJrnl:$J` files with reason flag decoding and file reference extraction

## Data Flow

### Import Pipeline

```
File → Parser (streaming chunks) → Batch Arrays → SQLite INSERT
                                    (100K rows)    (prepared statements)
```

1. Parser reads file in chunks (128MB for CSV)
2. Rows are accumulated into adaptive batches (up to 100,000 rows, tuned by column count)
3. Batches are inserted using pre-built multi-row INSERT statements with pre-allocated parameter arrays
4. Progress callbacks update the UI every 200ms (time-based)
5. After import: type detection, then async background builds (column indexes → FTS5 index)

### Query Pipeline

```
UI Action → IPC → db.queryRows() → SQL Query → Result Set → IPC → Grid Render
              ↓                        ↓
         Debounce (500ms)       LIMIT/OFFSET
                                 (pagination)
```

1. User scrolls, searches, or filters
2. Request is debounced (500ms for search/filter)
3. SQL query is built with active filters, sort, and pagination
4. Results (up to 10,000 rows) returned via IPC
5. Grid renders visible rows from the cached window

## Technology Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| **Electron** | ^33.2.1 | Native app container |
| **React** | ^18.3.1 | UI framework |
| **Vite** | ^6.0.7 | Build tooling |
| **better-sqlite3** | ^11.7.0 | SQLite bindings (zero-copy) |
| **ExcelJS** | ^4.4.0 | XLSX streaming |
| **SheetJS (xlsx)** | ^0.18.5 | Legacy XLS parsing |
| **@ts-evtx** | ^1.1.1 | EVTX binary parsing |
| **csv-parser** | ^3.0.0 | CSV parsing |
| **electron-updater** | ^6.6.7 | Auto-update framework |
| **electron-builder** | ^25.1.8 | App packaging |

## Build Targets

| Target | Command | Output |
|--------|---------|--------|
| **Development** | `npm run dev` | Vite + Electron hot reload |
| **Quick start** | `npm run start` | Build + run |
| **DMG** | `npm run dist:dmg` | macOS installer |
| **Universal** | `npm run dist:universal` | Intel + Apple Silicon |

## Security Model

- **Context isolation** enabled — renderer has no Node.js access
- **Preload bridge** exposes only whitelisted IPC methods (~112 entries)
- **No remote content** — purely local data processing
- **Hardened runtime** enabled for macOS distribution
- **Minimal network access** — only VirusTotal API lookups (opt-in, requires user-provided API key) and auto-update checks. All forensic processing is fully offline
- **VirusTotal API key** stored locally in `userData/vt-settings.json`, never transmitted except to VirusTotal's API endpoint
