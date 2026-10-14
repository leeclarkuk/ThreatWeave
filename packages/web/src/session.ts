import { useSyncExternalStore } from 'react';
import { type Model, type Issue } from '@threatweave/core';
import { api, ApiError } from './api';

export type SaveState = 'saved' | 'dirty' | 'saving' | 'error' | 'reloaded';
type Op = { label: string; fn: (m: Model) => Model };

/**
 * Holds one open project. Edits are pure functions over the model (the same functions the CLI and MCP use),
 * applied locally, validated server-side on save. Undo/redo is a bounded snapshot stack.
 * If the file changed underneath us (for example an analysis run finished), pending edits are
 * replayed on top of the fresh copy rather than overwritten or silently lost.
 */
export class Session {
  model: Model;
  etag: string;
  issues: Issue[] = [];
  saveState: SaveState = 'saved';
  message: string | null = null;
  past: Model[] = [];
  future: Model[] = [];
  private pending: Op[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private saving: Promise<void> | undefined;
  private listeners = new Set<() => void>();
  version = 0;

  constructor(public id: string, model: Model, etag: string, issues: Issue[]) { this.model = model; this.etag = etag; this.issues = issues; }

  subscribe = (fn: () => void) => { this.listeners.add(fn); return () => this.listeners.delete(fn); };
  getVersion = () => this.version;
  private emit() { this.version++; this.listeners.forEach((l) => l()); }

  /** Apply an edit. Returns false (and surfaces the reason) if the domain rules refuse it. */
  mutate(label: string, fn: (m: Model) => Model, opts: { history?: boolean; immediate?: boolean } = {}): boolean {
    let next: Model;
    try { next = fn(this.model); } catch (e) { this.message = (e as Error).message; this.emit(); return false; }
    if (opts.history !== false) { this.past.push(this.model); if (this.past.length > 100) this.past.shift(); this.future = []; }
    this.model = next;
    this.pending.push({ label, fn });
    this.message = null;
    this.saveState = 'dirty';
    this.emit();
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.flush(), opts.immediate ? 0 : 450);
    return true;
  }

  undo() { const p = this.past.pop(); if (!p) return; this.future.push(this.model); this.model = p; this.touch('Undo'); }
  redo() { const n = this.future.pop(); if (!n) return; this.past.push(this.model); this.model = n; this.touch('Redo'); }
  private touch(label: string) {
    // History moves replace the whole model: save the exact result instead of replaying ops.
    this.pending = [{ label, fn: () => this.model }];
    this.saveState = 'dirty'; this.emit();
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.flush(), 300);
  }
  get canUndo() { return this.past.length > 0; }
  get canRedo() { return this.future.length > 0; }

  async flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    if (this.saving) { await this.saving; }
    if (!this.pending.length) return;
    this.saving = this.doSave().finally(() => { this.saving = undefined; });
    await this.saving;
  }

  private async doSave(): Promise<void> {
    this.saveState = 'saving'; this.emit();
    const ops = this.pending;
    this.pending = [];
    try {
      const r = await api.save(this.id, this.model, this.etag);
      this.etag = r.etag; this.issues = r.issues;
      this.saveState = this.pending.length ? 'dirty' : 'saved';
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        try {
          const fresh = await api.load(this.id);
          let m = fresh.model;
          for (const op of ops) m = op.fn(m);
          this.model = m; this.etag = fresh.etag;
          const r = await api.save(this.id, m, fresh.etag);
          this.etag = r.etag; this.issues = r.issues; this.saveState = 'reloaded';
          this.message = 'The project changed on disk (for example a finished analysis run). Your edits were applied on top of the newer copy.';
        } catch (e2) {
          this.pending = ops.concat(this.pending);
          this.saveState = 'error'; this.message = `Could not merge with the newer copy: ${(e2 as Error).message}`;
        }
      } else {
        this.pending = ops.concat(this.pending);
        this.saveState = 'error';
        this.message = e instanceof ApiError && e.status === 422 ? `The server refused the change: ${(e.body?.issues?.[0]?.message ?? e.message)}` : `Save failed: ${(e as Error).message}. Your edits are kept; they will retry.`;
      }
    }
    this.emit();
  }

  /** Pick up changes made by the server (analysis finished, source synced). Pending edits are flushed first. */
  async reload() {
    await this.flush();
    const fresh = await api.load(this.id);
    this.model = fresh.model; this.etag = fresh.etag; this.issues = fresh.issues;
    this.past = []; this.future = []; this.saveState = 'saved'; this.emit();
  }
  dismissMessage() { this.message = null; this.emit(); }
}

export function useSession(s: Session | null): Model | null {
  useSyncExternalStore(s ? s.subscribe : () => () => {}, s ? s.getVersion : () => 0);
  return s?.model ?? null;
}
