import { create } from "zustand";

/**
 * Global toast / notification queue. Replaces the OS-native alert() calls and
 * the inline `copiedMsg` flash state.
 *
 * Usage from anywhere:
 *
 *   import { toast } from "../store/useToastStore.js";
 *   toast.success("Copied to clipboard");
 *   toast.error("Import failed", { detail: error.message });
 *   toast.info("Loading...", { ttl: 0 });   // ttl=0 means no auto-dismiss
 *
 * The <ToastContainer /> primitive must be mounted once at the app root for
 * toasts to render — see App.jsx alongside the other portal-style components.
 *
 * Defaults:
 *   info / success  — auto-dismiss after 3500ms
 *   warning         — auto-dismiss after 6000ms
 *   error           — does NOT auto-dismiss (requires user action)
 */
let nextId = 1;

const DEFAULT_TTL = { info: 3500, success: 3500, warning: 6000, error: 0 };

const useToastStore = create((set, get) => ({
  toasts: [],

  push: ({ kind = "info", message, detail, ttl, actionLabel, onAction }) => {
    const id = nextId++;
    const effectiveTtl = ttl !== undefined ? ttl : DEFAULT_TTL[kind] ?? 3500;
    set((s) => ({ toasts: [...s.toasts, { id, kind, message, detail, ttl: effectiveTtl, actionLabel, onAction }] }));
    if (effectiveTtl > 0) {
      setTimeout(() => get().dismiss(id), effectiveTtl);
    }
    return id;
  },

  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  clear: () => set({ toasts: [] }),
}));

export default useToastStore;

// Convenience API — drop-in replacements for alert() / inline message flashes.
export const toast = {
  info:    (message, opts = {}) => useToastStore.getState().push({ kind: "info",    message, ...opts }),
  success: (message, opts = {}) => useToastStore.getState().push({ kind: "success", message, ...opts }),
  warning: (message, opts = {}) => useToastStore.getState().push({ kind: "warning", message, ...opts }),
  error:   (message, opts = {}) => useToastStore.getState().push({ kind: "error",   message, ...opts }),
};
