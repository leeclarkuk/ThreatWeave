import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type ProjectSummary } from './api';
import { Workspace, Logo, TABS } from './Workspace';
import { DialogHost, Empty, Mark, Modal, TextField, useDialogs, fmtTime } from './ui';
import { SettingsDialog } from './SettingsDialog';

function parseHash(): { id?: string; tab: string } {
  const m = /^#\/p\/([a-z0-9-]+)(?:\/([a-z]+))?/.exec(window.location.hash);
  if (!m) return { tab: 'architecture' };
  return { id: m[1]!, tab: TABS.some((t) => t.id === m[2]) ? m[2]! : 'architecture' };
}

interface Preview { kind: 'tc' | 'native'; data: unknown; name?: string; ok: boolean; error?: string; stats?: Record<string, number>; warnings: Array<{ level: string; code: string; message: string; count: number }>; issues: Array<{ severity: string; message: string }> }

function Home({ go }: { go: (id: string, tab?: string) => void }) {
  const { toast } = useDialogs();
  const [projects, setProjects] = useState<ProjectSummary[] | null>(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [examples, setExamples] = useState<{ models: Array<{ id: string; label: string }> }>({ models: [] });
  const [preview, setPreview] = useState<Preview | null>(null);
  const [settings, setSettings] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const load = useCallback(() => { api.projects().then(setProjects).catch((e) => setError((e as Error).message)); }, []);
  useEffect(() => { load(); api.examples().then(setExamples).catch(() => {}); }, [load]);

  const create = async () => { if (!name.trim()) return; try { const r = await api.create({ name: name.trim() }); go(r.id, 'architecture'); } catch (e) { toast((e as Error).message); } };
  const loadExample = async (id: string) => { try { const r = await api.create({ example: id }); go(r.id, 'architecture'); } catch (e) { toast((e as Error).message); } };
  const pick = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 25 * 1024 * 1024) { toast('That file is over 25 MB; refusing to load it.'); return; }
    try {
      const data = JSON.parse(await f.text());
      const kind: 'tc' | 'native' = data && typeof data === 'object' && 'format' in data ? 'native' : 'tc';
      const r = await api.importPreview(kind, data);
      setPreview({ kind, data, ...r, warnings: r.warnings ?? [], issues: r.issues ?? [] });
    } catch (e) { setPreview({ kind: 'tc', data: null, ok: false, error: `Not valid JSON: ${(e as Error).message}`, warnings: [], issues: [] }); }
  };
  const confirmImport = async () => {
    if (!preview) return;
    try { const r = await api.create(preview.kind === 'tc' ? { tc: preview.data, name: preview.name } : { model: preview.data }); setPreview(null); toast(r.warnings.length ? `Imported with ${r.warnings.length} note(s) about unsupported or converted content. See the Evidence and Report sections.` : 'Imported.'); go(r.id, 'threats'); }
    catch (e) { toast((e as Error).message); }
  };
  const del = async (p: ProjectSummary) => { if (confirm(`Delete "${p.name}" and its saved revisions from disk? This cannot be undone. Export it first if unsure.`)) { await api.remove(p.id); load(); } };

  return (
    <div className="home">
      <div className="row"><a className="brand" href="#/"><Logo />ThreatWeave</a><span className="spacer" /><button className="small" onClick={() => setSettings(true)}>Settings</button></div>
      <h1 style={{ marginTop: 22 }}>What changed, which assumptions did it invalidate, and what needs review?</h1>
      <p className="lede">A local workbench for threat models that stay true to the system they describe. Model by hand, import, or derive structure from your repository; keep your decisions when things change.</p>
      {error && <div className="callout err" role="alert">Could not reach the local server: {error}. Is <code>threatweave serve</code> running?</div>}
      <div className="home-grid">
        <section aria-labelledby="h-projects">
          <h2 id="h-projects" style={{ marginBottom: 10 }}>Your models</h2>
          {projects === null && !error ? <p role="status">Loading…</p> : projects && projects.length === 0 ? (
            <Empty title="No models yet">Start a new one, import a Threat Composer or ThreatWeave file, or open the demonstration to see the review workflow.</Empty>
          ) : (
            <ul className="projlist">{projects?.map((p) => p.broken ? (
              <li key={p.id} style={{ borderColor: 'var(--danger)' }}>
                <div className="grow"><strong>{p.id}</strong> <Mark kind="danger">✕ Cannot be opened</Mark>
                  <div className="hint">{p.broken.reason}</div>
                  <div className="hint">{p.broken.hasBackup ? 'A valid backup of the previous version exists. The damaged file is kept as model.json.damaged.' : 'No valid backup exists. The file was not changed; inspect it with threatweave validate.'}</div></div>
                {p.broken.hasBackup && <button className="small" onClick={async () => { try { await api.restore(p.id); toast('Restored the previous version.'); load(); } catch (e) { toast((e as Error).message); } }}>Restore previous version</button>}
              </li>
            ) : (
              <li key={p.id}>
                <div className="grow"><a className="name" href={`#/p/${p.id}/${p.counts.openReview + p.counts.pendingProposals > 0 ? 'review' : 'architecture'}`}>{p.name}</a> {p.example && <Mark kind="info" dashed>Demonstration</Mark>}
                  <div className="hint">{p.counts.elements} components · {p.counts.threats} threats · {p.counts.mitigations} mitigations · updated {fmtTime(p.updatedAt.replace(/\.\d+Z$/, 'Z'))}</div></div>
                {p.counts.openReview + p.counts.pendingProposals > 0 && <Mark kind="review">◆ {p.counts.openReview} to review{p.counts.pendingProposals ? ` · ${p.counts.pendingProposals} proposals` : ''}</Mark>}
                <button className="small ghost" onClick={() => del(p)} aria-label={`Delete ${p.name}`}>Delete</button>
              </li>))}</ul>)}
        </section>
        <section className="stack" aria-label="Start">
          <div className="card">
            <h2 style={{ marginBottom: 8 }}>New model</h2>
            <form onSubmit={(e) => { e.preventDefault(); void create(); }}>
              <TextField live label="System name" value={name} onCommit={setName} placeholder="e.g. Payments service" />
              <button type="submit" className="primary" disabled={!name.trim()}>Create and start modelling</button>
            </form>
            <p className="hint" style={{ marginTop: 8 }}>Works with no account, no network and no AI provider.</p>
          </div>
          <div className="card">
            <h2 style={{ marginBottom: 8 }}>Import</h2>
            <p>Native <code>.threatweave.json</code> or Threat Composer <code>.tc.json</code> (schema 1). You see what converts, what is lost, and any problems before anything is saved.</p>
            <input ref={file} type="file" accept=".json,application/json" className="sr" aria-label="Choose a file to import" onChange={(e) => { void pick(e.target.files?.[0]); e.target.value = ''; }} />
            <button onClick={() => file.current?.click()}>Choose a file…</button>
          </div>
          {examples.models.map((m) => (
            <div key={m.id} className="card demo">
              <Mark kind="info" dashed>Demonstration content</Mark>
              <h2 style={{ margin: '8px 0 6px' }}>{m.label}</h2>
              <p>A fictional shop with human-written reasoning on top of a scanned Docker Compose file. Try the scenario:</p>
              <ol className="steps">
                <li>Open the demo and look at the architecture, threats and the assumption that inventory is internal-only.</li>
                <li>Source tab: choose <em>Northwind Shop, revision 2</em>, preview, then <em>Sync</em>. An internal service now publishes a port.</li>
                <li>Review tab: see which assumption, threat, mitigation and boundary are flagged, and why.</li>
              </ol>
              <button onClick={() => loadExample(m.id)}>Open a copy of the demonstration</button>
            </div>))}
        </section>
      </div>
      {settings && <SettingsDialog onClose={() => setSettings(false)} onSaved={() => {}} />}
      {preview && (
        <Modal title={preview.ok ? `Import “${preview.name}”` : 'Cannot import this file'} onClose={() => setPreview(null)} wide>
          {preview.error && <div className="callout err" role="alert">{preview.error}</div>}
          {preview.ok && preview.stats && <p>Will create a new model with {Object.entries(preview.stats).map(([k, v]) => `${v} ${k}`).join(', ')}. Stable identifiers are preserved.</p>}
          {preview.warnings.length > 0 && <div className="callout warn"><strong>Conversion notes</strong><ul className="kvlist">{preview.warnings.map((w, i) => <li key={i}>{w.level === 'warning' ? '▲ ' : 'ℹ '}{w.message}{w.count > 1 ? ` (×${w.count})` : ''}</li>)}</ul></div>}
          {preview.issues.filter((i) => i.severity === 'error').length > 0 && <div className="callout err"><strong>Validation errors</strong><ul className="kvlist">{preview.issues.filter((i) => i.severity === 'error').slice(0, 12).map((i, k) => <li key={k}>{i.message}</li>)}</ul></div>}
          {preview.ok && preview.issues.filter((i) => i.severity === 'warning').length > 0 && <details><summary>{preview.issues.filter((i) => i.severity === 'warning').length} model warning(s)</summary><ul className="kvlist">{preview.issues.filter((i) => i.severity === 'warning').slice(0, 12).map((i, k) => <li key={k}>{i.message}</li>)}</ul></details>}
          <div className="actions"><button onClick={() => setPreview(null)}>Cancel</button>{preview.ok && <button className="primary" onClick={confirmImport}>Import as a new model</button>}</div>
        </Modal>)}
    </div>
  );
}

export function App() {
  const [h, setH] = useState(parseHash());
  useEffect(() => { const f = () => setH(parseHash()); window.addEventListener('hashchange', f); return () => window.removeEventListener('hashchange', f); }, []);
  const go = useCallback((id: string, tab = 'architecture') => { window.location.hash = `#/p/${id}/${tab}`; }, []);
  const onTab = useCallback((t: string) => { if (h.id) window.location.hash = `#/p/${h.id}/${t}`; }, [h.id]);
  return (
    <DialogHost>
      <a className="skip" href="#main">Skip to content</a>
      {h.id ? <Workspace id={h.id} tab={h.tab} onTab={onTab} onHome={() => { window.location.hash = '#/'; }} /> : <Home go={go} />}
    </DialogHost>
  );
}
