import { create } from "zustand";

/**
 * useGridInteractionStore — Grid interaction state.
 *
 * Selection, context menus, cell popups, column resize, and drag state.
 * These are transient UI states that are not per-tab — they reset on
 * tab switch and are consumed by VirtualGrid, MenuBar, StatusBar.
 *
 * Moving these to a store eliminates prop drilling through 4+ components.
 */
const useGridInteractionStore = create((set) => ({
  // ── Selection ──────────────────────────────────────────────────────
  selectedRows: new Set(),
  lastClickedRow: null,

  setSelectedRows: (v) => set((s) => ({ selectedRows: typeof v === "function" ? v(s.selectedRows) : v })),
  setLastClickedRow: (v) => set({ lastClickedRow: v }),

  // Spreadsheet-style whole-column selection: the display name of the column the user
  // has selected (header highlights, ⌘C copies just that column's values). null = none.
  selectedColumn: null,
  setSelectedColumn: (v) => set({ selectedColumn: v }),

  // ── Context Menus ──────────────────────────────────────────────────
  contextMenu: null,        // column header right-click: { x, y, colName }
  rowContextMenu: null,     // row right-click: { x, y, rowId, rowIndex, currentTags, row, cellColumn, cellValue }
  cellContextMenu: null,    // cmd+click cell: { x, y, colName, cellValue }

  setContextMenu: (v) => set({ contextMenu: v }),
  setRowContextMenu: (v) => set({ rowContextMenu: v }),
  setCellContextMenu: (v) => set({ cellContextMenu: v }),

  // ── Cell Detail Popup ──────────────────────────────────────────────
  cellPopup: null,          // { column, value } — shows timestamp converter, base64 decode, etc.

  setCellPopup: (v) => set({ cellPopup: v }),

  // ── Column Resize ──────────────────────────────────────────────────
  resizingCol: null,
  resizeX: 0,
  resizeW: 0,

  setResizingCol: (v) => set({ resizingCol: v }),
  setResizeX: (v) => set({ resizeX: v }),
  setResizeW: (v) => set({ resizeW: v }),

  // ── Drag State ─────────────────────────────────────────────────────
  headerDragOver: null,     // column header being dragged over (for reorder)

  setHeaderDragOver: (v) => set({ headerDragOver: v }),

  // ── Tag Column ─────────────────────────────────────────────────────
  tagColWidth: 60,
  setTagColWidth: (v) => set({ tagColWidth: v }),

  // ── Copied Message Toast ───────────────────────────────────────────
  copiedMsg: false,
  setCopiedMsg: (v) => set({ copiedMsg: v }),

  // ── Search Loading ─────────────────────────────────────────────────
  searchLoading: false,
  setSearchLoading: (v) => set({ searchLoading: v }),

  // ── Dismiss all transient state (on tab switch) ────────────────────
  resetTransient: () => set({
    selectedRows: new Set(),
    lastClickedRow: null,
    selectedColumn: null,
    contextMenu: null,
    rowContextMenu: null,
    cellContextMenu: null,
    cellPopup: null,
    resizingCol: null,
  }),
}));

export default useGridInteractionStore;
