import { addIngested, finishRun, newEventId, startRun, buildSource, refreshEvidence, type Model } from '@threatweave/core';
import { runAnalysis, type AnalysisFile } from '@threatweave/ai';
import { UserError, type Store } from './store.js';
import type { SettingsStore } from './settings.js';
import { loadSelected, scanDirectory, snapshotRevision, type ScanResult } from './ingest.js';
import { redactSecrets } from '@threatweave/core';

interface Live { controller: AbortController; log: string[] }

export class Runs {
  private live = new Map<string, Live>();
  constructor(private store: Store, private settings: SettingsStore, private allowedRoots: string[]) {}

  liveLog(runId: string): string[] | undefined { return this.live.get(runId)?.log; }

  /** What would be sent, and where. Shown to the user before any provider call. */
  async disclosure(scan: ScanResult, selected?: string[]) {
    const adapter = await this.settings.adapter();
    const pick = scan.files.filter((f) => !selected || selected.includes(f.path));
    const { redactions } = await loadSelected(scan, pick.map((f) => f.path));
    return {
      adapter: adapter.id, model: adapter.modelId, host: adapter.endpointHost, capabilities: adapter.capabilities(),
      files: pick.map((f) => ({ path: f.path, bytes: f.bytes, role: f.role })), totalBytes: pick.reduce((n, f) => n + f.bytes, 0),
      redactions, note: 'File text is sent as shown. Values of secret-looking keys and credentials in URLs are replaced with [REDACTED] first. The project model (component, flow and threat names) is also sent as context.',
    };
  }

  /** Start a run. Returns immediately; the run record is persisted and updated as it finishes. */
  async start(projectId: string, a: { path: string; files?: string[] | undefined; focus?: string | undefined; expectHost: string; confirmSend: boolean }): Promise<{ runId: string }> {
    if (!a.confirmSend) throw new UserError('Explicit confirmation is required before sending project data to a provider');
    const adapter = await this.settings.adapter();
    if (a.expectHost !== adapter.endpointHost) throw new UserError(`The configured provider host changed (${adapter.endpointHost}). Review what will be sent and confirm again.`);
    const scan = await scanDirectory(a.path, { allowedRoots: this.allowedRoots });
    const sel = a.files ?? scan.files.map((f) => f.path);
    const { inputs, changed } = await loadSelected(scan, sel);
    if (changed.length) throw new UserError(`Files changed since you reviewed them: ${changed.join(', ')}. Re-scan and confirm again.`);
    if (!inputs.length) throw new UserError('No files selected');
    const files: AnalysisFile[] = inputs.map((f) => ({ path: f.path, text: redactSecrets(f.content).text, hash: f.hash }));
    const revision = snapshotRevision(inputs);
    const source = buildSource(inputs, { label: scan.label, revision, vcsRevision: scan.vcsRevision });
    const runId = newEventId('run');
    const budgets = await this.settings.budgets();
    const t = await this.store.update(projectId, (m) => {
      let next: Model = m;
      if (!next.sources.some((s) => s.id === source.id)) next = { ...next, sources: [...next.sources, source] };
      next = refreshEvidence(next, inputs, source.id).model; // capturing a newer revision for analysis also invalidates evidence it contradicts
      return startRun(next, { id: runId, kind: 'ai-analysis', adapter: adapter.id, modelId: adapter.modelId, promptVersion: 'tw-analysis-1', sourceId: source.id, inputManifest: source.files.filter((f) => inputs.some((i) => i.path === f.path)), usage: { inputTokens: null, outputTokens: null, costUsd: null, note: '' }, proposalIds: [], notes: [] }).model;
    });
    const live: Live = { controller: new AbortController(), log: [] };
    this.live.set(runId, live);
    void this.execute(projectId, runId, t.model, adapter, files, source.id, a.focus, budgets, live);
    return { runId };
  }

  private async execute(projectId: string, runId: string, snapshot: Model, adapter: Awaited<ReturnType<SettingsStore['adapter']>>, files: AnalysisFile[], sourceId: string, focus: string | undefined, budgets: Awaited<ReturnType<SettingsStore['budgets']>>, live: Live) {
    try {
      const out = await runAnalysis({ adapter, model: snapshot, runId, sourceId, files, focus, budgets, signal: live.controller.signal, onLog: (l) => live.log.push(l) });
      await this.store.update(projectId, (m) => {
        let next = m;
        const notes = [...out.log];
        let ids: string[] = [];
        if (out.ingest) {
          const added = addIngested(next, out.ingest);
          next = added.model;
          ids = added.added.map((p) => p.id);
          for (const d of out.ingest.discarded) notes.push(`Discarded: ${d.reason}`);
          for (const s of added.skipped) notes.push(`Skipped "${s.title}": ${s.reason}`);
          if (out.ingest.summary) notes.push(`Model summary (unverified): ${out.ingest.summary.slice(0, 400)}`);
        }
        return finishRun(next, runId, { status: out.status, usage: out.usage, proposalIds: ids, notes: notes.slice(0, 60).map((n) => n.slice(0, 480)), ...(out.error ? { error: out.error.slice(0, 900) } : {}) });
      });
    } catch (e) {
      await this.store.update(projectId, (m) => finishRun(m, runId, { status: 'failed', error: `Internal error: ${(e as Error).message}`.slice(0, 900) })).catch(() => undefined);
    } finally {
      this.live.delete(runId);
    }
  }

  cancel(runId: string): boolean {
    const l = this.live.get(runId);
    if (!l) return false;
    l.controller.abort();
    return true;
  }

  /** Connectivity test: tiny request, explicit user action, sends no project data. */
  async testConnection() {
    const adapter = await this.settings.adapter();
    const started = Date.now();
    try {
      const r = await adapter.complete({ system: 'Reply with the JSON object {"ok": true}.', user: 'ping', jsonSchema: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'], additionalProperties: false }, schemaName: 'ping', maxOutputTokens: 200 }, AbortSignal.timeout(30000));
      return { ok: true, host: adapter.endpointHost, model: adapter.modelId, ms: Date.now() - started, usage: r.usage, servedModel: r.model };
    } catch (e) {
      return { ok: false, host: adapter.endpointHost, model: adapter.modelId, error: (e as Error).message, kind: (e as { kind?: string }).kind ?? 'unknown' };
    }
  }
}
