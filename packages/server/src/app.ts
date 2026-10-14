import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { Hono, type Context } from 'hono';
import {
  ModelValidationError, emptyModel, exportThreatComposer, importThreatComposer, renderMarkdownReport, serialiseModel, syncSource,
  validateModel, type Model, PRODUCT_NAME, SCHEMA_VERSION,
} from '@threatweave/core';
import { Conflict, NotFound, Store, PROJECT_ID, UserError } from './store.js';
import { SettingsStore, type Settings } from './settings.js';
import { Runs } from './runs.js';
import { IngestError, loadSelected, scanDirectory, snapshotRevision } from './ingest.js';

export interface AppOptions {
  dataDir: string;
  webDir?: string | undefined;
  examplesDir?: string | undefined;
  allowedRoots?: string[];
  /** Hostnames accepted in the Host header (DNS rebinding defence). */
  allowedHosts?: string[];
}

const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json' };

export async function createApp(o: AppOptions) {
  const store = new Store(o.dataDir);
  await store.init();
  await store.recoverInterruptedRuns();
  const settings = new SettingsStore(o.dataDir);
  const runs = new Runs(store, settings, o.allowedRoots ?? []);
  const app = new Hono();
  const hosts = new Set((o.allowedHosts ?? []).concat(['localhost', '127.0.0.1', '[::1]']));

  // A local tool still gets web-borne attacks: reject foreign Host headers (DNS rebinding) and cross-site writes.
  app.use('*', async (c, next) => {
    const host = (c.req.header('host') ?? '').replace(/:\d+$/, '');
    if (!hosts.has(host)) return c.json({ error: 'Host not allowed' }, 403);
    if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
      if (c.req.header('x-threatweave') !== '1') return c.json({ error: 'Missing X-ThreatWeave header' }, 403);
      const origin = c.req.header('origin');
      if (origin && new URL(origin).host !== c.req.header('host')) return c.json({ error: 'Cross-origin request refused' }, 403);
    }
    c.header('x-content-type-options', 'nosniff');
    c.header('referrer-policy', 'no-referrer');
    c.header('cache-control', 'no-store');
    await next();
  });

  app.onError((e, c) => {
    if (e instanceof NotFound) return c.json({ error: e.message }, 404);
    if (e instanceof Conflict) return c.json({ error: e.message, code: 'conflict' }, 409);
    if (e instanceof ModelValidationError) return c.json({ error: e.message, issues: e.issues }, 422);
    if (e instanceof IngestError || e instanceof UserError) return c.json({ error: e.message }, 400);
    if (e instanceof SyntaxError) return c.json({ error: 'Request body is not valid JSON' }, 400);
    console.error('[error]', c.req.method, new URL(c.req.url).pathname, (e as Error).message); // never log bodies
    return c.json({ error: 'Internal error' }, 500);
  });

  const body = async (c: Context) => (await c.req.json()) as Record<string, any>;
  const ensureId = async (base: string) => {
    let id = base, n = 2;
    const existing = new Set((await store.list()).map((p) => p.id));
    while (existing.has(id)) id = `${base.slice(0, 55)}-${n++}`;
    return id;
  };

  app.get('/api/health', (c) => c.json({ ok: true, product: PRODUCT_NAME, schemaVersion: SCHEMA_VERSION }));

  /* ---------------- projects ---------------- */
  app.get('/api/projects', async (c) => c.json(await store.list()));

  app.post('/api/projects', async (c) => {
    const b = await body(c);
    let model: Model;
    let warnings: unknown[] = [];
    if (b.example) {
      if (!o.examplesDir) throw new NotFound('Examples are not installed');
      const name = String(b.example).replace(/[^a-z0-9-]/g, '');
      model = JSON.parse(await readFile(join(o.examplesDir, `${name}.threatweave.json`), 'utf8').catch(() => { throw new NotFound('Unknown example'); }));
      model.id = await ensureId(model.id);
    } else if (b.tc) {
      const r = importThreatComposer(b.tc, { modelId: await ensureId(String(b.name ?? b.tc?.applicationInfo?.name ?? 'imported').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50) || 'imported'), importedBy: String(b.actor ?? '') || undefined });
      model = r.model; warnings = r.warnings;
    } else if (b.model) {
      const v = validateModel(b.model);
      if (!v.ok || !v.model) throw new ModelValidationError('Imported model failed validation', v.issues);
      model = v.model;
      model.id = await ensureId(model.id);
    } else {
      const name = String(b.name ?? '').trim();
      if (!name) return c.json({ error: 'A name is required' }, 400);
      model = emptyModel(name, String(b.description ?? ''));
      model.id = await ensureId(model.id);
    }
    const saved = await store.save(model, { create: true });
    return c.json({ id: saved.model.id, etag: saved.etag, warnings }, 201);
  });

  app.get('/api/projects/:id', async (c) => {
    const { model, etag, issues } = await store.load(c.req.param('id'));
    return c.json({ model, etag, issues });
  });

  app.put('/api/projects/:id', async (c) => {
    const id = c.req.param('id');
    const b = await body(c);
    if (b.model?.id !== id) return c.json({ error: 'Model id does not match the URL' }, 400);
    const ifMatch = c.req.header('if-match');
    if (!ifMatch) return c.json({ error: 'If-Match header with the etag you loaded is required' }, 428);
    const r = await store.save(b.model, { ifMatch });
    return c.json({ etag: r.etag, issues: r.issues });
  });

  app.post('/api/projects/:id/restore', async (c) => {
    try { await store.restoreBackup(c.req.param('id')); } catch (e) { return c.json({ error: (e as Error).message }, 409); }
    return c.json({ ok: true });
  });

  app.delete('/api/projects/:id', async (c) => { await store.load(c.req.param('id')); await store.delete(c.req.param('id')); return c.json({ ok: true }); });

  /* ---------------- export / import ---------------- */
  app.get('/api/projects/:id/export', async (c) => {
    const { model } = await store.load(c.req.param('id'));
    const fmt = c.req.query('format') ?? 'json';
    const safe = model.id;
    const send = (text: string, type: string, ext: string, extra?: unknown) => {
      c.header('content-type', type);
      c.header('content-disposition', `attachment; filename="${safe}${ext}"`);
      if (extra) c.header('x-conversion-warnings', encodeURIComponent(JSON.stringify(extra)));
      return c.body(text);
    };
    if (fmt === 'json') return send(serialiseModel(model), 'application/json', '.threatweave.json');
    if (fmt === 'markdown') return send(renderMarkdownReport(model, { generatedAt: new Date().toISOString().slice(0, 10) }), 'text/markdown; charset=utf-8', '.md');
    if (fmt === 'tc') {
      const r = exportThreatComposer(model);
      return send(JSON.stringify(r.json, null, 2) + '\n', 'application/json', '.tc.json', r.warnings);
    }
    return c.json({ error: 'format must be json, markdown or tc' }, 400);
  });

  app.post('/api/import/preview', async (c) => {
    const b = await body(c);
    if (b.kind === 'tc') {
      try {
        const r = importThreatComposer(b.data);
        const v = validateModel(r.model);
        return c.json({ ok: v.ok, name: r.model.name, stats: r.stats, warnings: r.warnings, issues: v.issues });
      } catch (e) { return c.json({ ok: false, error: (e as Error).message }, 200); }
    }
    const v = validateModel(b.data);
    return c.json({ ok: v.ok, name: v.model?.name, stats: v.model ? { threats: v.model.threats.length, mitigations: v.model.mitigations.length, elements: v.model.elements.length } : undefined, warnings: [], issues: v.issues });
  });

  /* ---------------- revisions ---------------- */
  app.get('/api/projects/:id/revisions', async (c) => c.json(await store.revisions(c.req.param('id'))));
  app.post('/api/projects/:id/revisions', async (c) => c.json(await store.snapshot(c.req.param('id'), String((await body(c)).label ?? 'snapshot').slice(0, 60))));
  app.get('/api/projects/:id/revisions/:rid', async (c) => c.json({ model: await store.revision(c.req.param('id'), c.req.param('rid')) }));

  /* ---------------- source analysis ---------------- */
  app.post('/api/projects/:id/source/scan', async (c) => {
    await store.load(c.req.param('id'));
    const b = await body(c);
    const scan = await scanDirectory(String(b.path ?? ''), { allowedRoots: o.allowedRoots ?? [] });
    const disclosure = await runs.disclosure(scan).catch(() => null);
    return c.json({ scan: { ...scan, root: scan.root }, disclosure });
  });

  /** Deterministic: extract topology, merge, diff, derive review items. No model provider is contacted. */
  app.post('/api/projects/:id/source/sync', async (c) => {
    const id = c.req.param('id');
    const b = await body(c);
    const scan = await scanDirectory(String(b.path ?? ''), { allowedRoots: o.allowedRoots ?? [] });
    const { inputs, changed } = await loadSelected(scan);
    if (changed.length) return c.json({ error: `Files changed during the scan: ${changed.join(', ')}. Try again.` }, 409);
    if (!inputs.length) return c.json({ error: 'No supported files found in that directory' }, 400);
    const actor = (await settings.get()).actor;
    await store.snapshot(id, 'before-sync');
    let summary: unknown;
    const r = await store.update(id, (m) => {
      const res = syncSource(m, inputs, { label: scan.label, revision: snapshotRevision(inputs), ...(scan.vcsRevision ? { vcsRevision: scan.vcsRevision } : {}), actor });
      summary = { changes: res.changes, reviewItems: res.reviewItems.length, proposals: res.proposals.length, notes: res.notes, stats: res.stats };
      return res.model;
    });
    await store.snapshot(id, 'after-sync');
    return c.json({ summary, etag: r.etag });
  });

  app.post('/api/projects/:id/source/analyze', async (c) => {
    await store.load(c.req.param('id'));
    const b = await body(c);
    const r = await runs.start(c.req.param('id'), { path: String(b.path ?? ''), files: Array.isArray(b.files) ? b.files.map(String) : undefined, focus: typeof b.focus === 'string' ? b.focus.slice(0, 4000) : undefined, expectHost: String(b.expectHost ?? ''), confirmSend: b.confirmSend === true });
    return c.json(r, 202);
  });
  app.get('/api/projects/:id/runs/:rid', async (c) => {
    const { model } = await store.load(c.req.param('id'));
    const run = model.runs.find((r) => r.id === c.req.param('rid'));
    if (!run) throw new NotFound('Run not found');
    return c.json({ run, log: runs.liveLog(run.id) ?? [] });
  });
  app.post('/api/projects/:id/runs/:rid/cancel', async (c) => {
    const ok = runs.cancel(c.req.param('rid'));
    return c.json({ ok, note: ok ? 'Cancellation requested.' : 'That run is not active.' });
  });

  /* ---------------- settings ---------------- */
  app.get('/api/settings', async (c) => {
    const adapter = await settings.adapter();
    return c.json({ settings: await settings.get(), secrets: await settings.secretStatus(), active: { id: adapter.id, model: adapter.modelId, host: adapter.endpointHost, capabilities: adapter.capabilities() } });
  });
  app.put('/api/settings', async (c) => c.json({ settings: await settings.put((await body(c)).settings as Settings) }));
  app.put('/api/settings/secret', async (c) => {
    const b = await body(c);
    if (b.name !== 'anthropic' && b.name !== 'openaiCompatible') return c.json({ error: 'unknown credential' }, 400);
    await settings.setSecret(b.name, typeof b.value === 'string' && b.value ? b.value : null);
    return c.json({ secrets: await settings.secretStatus() });
  });
  app.post('/api/ai/test', async (c) => c.json(await runs.testConnection()));

  /* ---------------- examples ---------------- */
  app.get('/api/examples', async (c) => {
    if (!o.examplesDir) return c.json({ models: [], repos: [] });
    const exists = async (p: string) => stat(p).then(() => true, () => false);
    const repos = [] as Array<{ id: string; label: string; path: string }>;
    for (const [id, label] of [['northwind-v1', 'Northwind Shop, revision 1 (internal inventory service)'], ['northwind-v2', 'Northwind Shop, revision 2 (inventory port published)'], ['k8s-demo', 'Kubernetes manifests demo']] as const) {
      const p = join(o.examplesDir, 'repos', id);
      if (await exists(p)) repos.push({ id, label, path: p });
    }
    const models = (await exists(join(o.examplesDir, 'northwind.threatweave.json'))) ? [{ id: 'northwind', label: 'Northwind Shop (demonstration model)' }] : [];
    return c.json({ models, repos });
  });

  /* ---------------- static web app ---------------- */
  if (o.webDir) {
    const root = normalize(o.webDir);
    app.get('*', async (c) => {
      const url = new URL(c.req.url);
      let rel = decodeURIComponent(url.pathname);
      if (rel.startsWith('/api/')) return c.json({ error: 'Not found' }, 404);
      if (rel === '/' || !extname(rel)) rel = '/index.html';
      const full = normalize(join(root, rel));
      if (full !== root && !full.startsWith(root + sep)) return c.json({ error: 'Not found' }, 404);
      try {
        const data = await readFile(full);
        c.header('content-type', MIME[extname(full)] ?? 'application/octet-stream');
        c.header('cache-control', rel === '/index.html' ? 'no-store' : 'public, max-age=3600');
        c.header('content-security-policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        return c.body(data);
      } catch { return c.json({ error: 'Not found' }, 404); }
    });
  }
  void PROJECT_ID;
  return { app, store, settings, runs };
}
