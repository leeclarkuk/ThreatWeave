import { useEffect, useRef, useState } from 'react';
import { suggestFromPackClient } from './packs';
import { api, ApiError, type Disclosure, type ScanResult, type SettingsPayload } from './api';
import { useWs } from './ctx';
import { Empty, Mark, fmtTime, useDialogs } from './ui';

const bytes = (n: number) => (n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

function RunPanel({ runId, onDone }: { runId: string; onDone: () => void }) {
  const { session } = useWs();
  const [state, setState] = useState<{ run: any; log: string[] } | null>(null);
  const done = useRef(false);
  useEffect(() => {
    done.current = false;
    const t = setInterval(async () => {
      try {
        const r = await api.run(session.id, runId);
        if (r.run.status === 'running') { setState(r); return; }
        if (done.current) return;
        // Announce the result only once the project has reloaded, so Review already shows the new proposals.
        done.current = true; clearInterval(t);
        await session.reload();
        setState(r); onDone();
      } catch { /* transient */ }
    }, 900);
    return () => clearInterval(t);
  }, [runId]);
  const run = state?.run;
  return (
    <div className="card" role="status" aria-live="polite" style={{ marginTop: 10 }}>
      <div className="row"><strong>{!run || run.status === 'running' ? 'Analysis running…' : run.status === 'completed' ? 'Analysis finished' : run.status === 'cancelled' ? 'Analysis cancelled' : 'Analysis failed'}</strong><span className="spacer" />
        {(!run || run.status === 'running') && <button className="danger small" onClick={async () => { const r = await api.cancelRun(session.id, runId); void r; }}>Cancel</button>}</div>
      {state && <div className="runlog" style={{ marginTop: 6 }}>{[...state.log, ...(run && run.status !== 'running' ? run.notes ?? [] : [])].join('\n') || 'Waiting for the provider…'}</div>}
      {run && run.status !== 'running' && (
        <p style={{ marginBottom: 0 }}>{run.error ? <span><Mark kind="danger">✕ {run.status}</Mark> {run.error}. Your project is unchanged.</span> : <span>{run.proposalIds.length} proposal(s) added for review. Tokens: {run.usage.inputTokens ?? 'unavailable'} in / {run.usage.outputTokens ?? 'unavailable'} out. Cost: {run.usage.costUsd !== null ? `$${run.usage.costUsd.toFixed(4)}` : 'unavailable'}.</span>}</p>)}
    </div>
  );
}

export function SourceView() {
  const { session, model, go } = useWs();
  const { toast } = useDialogs();
  const [path, setPath] = useState(() => { try { return localStorage.getItem(`tw.path.${session.id}`) ?? ''; } catch { return ''; } });
  const [examples, setExamples] = useState<Array<{ id: string; label: string; path: string }>>([]);
  const [scan, setScan] = useState<{ scan: ScanResult; disclosure: Disclosure | null } | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');
  const [syncRes, setSyncRes] = useState<{ changes: Array<{ kind: string; summary: string }>; reviewItems: number; proposals: number; notes: string[] } | null>(null);
  const [settings, setSettings] = useState<SettingsPayload | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [runId, setRunId] = useState<string | null>(() => model.runs.find((r) => r.status === 'running')?.id ?? null);
  const [packMsg, setPackMsg] = useState('');

  useEffect(() => { api.examples().then((e) => setExamples(e.repos)).catch(() => {}); api.settings().then(setSettings).catch(() => {}); }, []);
  const remember = (p: string) => { try { localStorage.setItem(`tw.path.${session.id}`, p); } catch { /* ignore */ } };
  const doScan = async (p = path) => {
    setErr(''); setBusy('scan'); setSyncRes(null); setConfirm(false);
    try { await session.flush(); const r = await api.scan(session.id, p); setScan(r); setPicked(new Set(r.scan.files.map((f) => f.path))); remember(p); }
    catch (e) { setScan(null); setErr((e as Error).message); } finally { setBusy(''); }
  };
  const doSync = async () => {
    setErr(''); setBusy('sync');
    try { await session.flush(); const r = await api.sync(session.id, path); setSyncRes(r.summary); await session.reload(); toast(`Synced. ${r.summary.reviewItems} review item(s), ${r.summary.proposals} proposal(s).`); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(''); }
  };
  const ai = settings?.settings.ai;
  const adapterReady = !!settings && (ai?.adapter === 'anthropic' ? !!ai.anthropic.model && settings.secrets.anthropic.configured : !!ai?.openaiCompatible.model);
  const doAnalyze = async (focus?: string) => {
    if (!scan || !settings) return;
    setErr(''); setBusy('ai');
    try { await session.flush(); const r = await api.analyze(session.id, { path, files: [...picked], expectHost: settings.active.host, confirmSend: true, ...(focus ? { focus } : {}) }); setRunId(r.runId); await session.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : (e as Error).message); } finally { setBusy(''); }
  };
  const focus = () => {
    const open = model.reviewItems.filter((r) => r.status === 'open').slice(0, 12).map((r) => `- ${r.change}`);
    return open.length ? `A deterministic comparison found these changes since the previous revision. Propose only what they imply for this system:\n${[...new Set(open)].join('\n')}` : undefined;
  };
  const sd = scan?.disclosure;
  const runs = [...model.runs].reverse();
  return (
    <div className="main">
      <div className="pagehead"><div className="grow"><h1>Source</h1><p>Point at a folder to derive components, flows and boundaries, and to keep evidence current. Supported today: Docker Compose and Kubernetes manifests. Nothing leaves this machine unless you explicitly run an AI analysis.</p></div></div>

      <section className="card" aria-labelledby="src-path">
        <h2 id="src-path" style={{ marginBottom: 8 }}>1. Choose a folder</h2>
        <form className="row wrap" onSubmit={(e) => { e.preventDefault(); void doScan(); }}>
          <label className="grow" style={{ margin: 0 }}><span className="sr">Folder path on the machine running ThreatWeave</span><input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/path/to/repository (a directory on the machine running ThreatWeave)" aria-label="Folder path" className="mono" /></label>
          <button type="submit" className="primary" disabled={!path.trim() || !!busy}>{busy === 'scan' ? 'Scanning…' : 'Preview files'}</button>
        </form>
        {examples.length > 0 && <div className="row wrap" style={{ marginTop: 8 }}><span className="hint">Bundled fictional demonstration folders:</span>{examples.map((e) => <button key={e.id} className="small" onClick={() => { setPath(e.path); void doScan(e.path); }} title={e.path}>{e.label}</button>)}</div>}
        <p className="hint" style={{ marginTop: 8 }}>The folder is read on this machine. Symlinks are never followed, archives are not opened, files that look like secrets are never read, and nothing in the folder is executed. Folder contents are treated as untrusted data.</p>
      </section>
      {err && <div className="callout err" role="alert" style={{ marginTop: 12 }}>{err}</div>}

      {scan && (
        <section className="card" style={{ marginTop: 14 }} aria-labelledby="src-prev">
          <h2 id="src-prev" style={{ marginBottom: 6 }}>2. What would be analysed</h2>
          <p className="hint">{scan.scan.label}{scan.scan.vcsRevision ? ` · git ${scan.scan.vcsRevision.slice(0, 10)}` : ' · not a git checkout, or revision not readable'} · {scan.scan.files.length} files · {bytes(scan.scan.totalBytes)}{scan.scan.truncated ? ' · LIMIT REACHED, list is partial' : ''}</p>
          {scan.scan.files.length === 0 ? <Empty title="No supported files found">Looked for Docker Compose files, Kubernetes manifests and README or architecture notes. See what is unsupported below.</Empty> : (
            <div className="filechk" role="group" aria-label="Files to include">
              {scan.scan.files.map((f) => <label key={f.path}><input type="checkbox" checked={picked.has(f.path)} onChange={(e) => { const n = new Set(picked); if (e.target.checked) n.add(f.path); else n.delete(f.path); setPicked(n); }} /><span className="mono grow">{f.path}</span><Mark>{f.role === 'document' ? 'context doc' : 'config'}</Mark><span className="hint">{bytes(f.bytes)}</span></label>)}
            </div>)}
          {scan.scan.skipped.length > 0 && <details style={{ marginTop: 8 }}><summary style={{ cursor: 'pointer' }}>{scan.scan.skipped.length} skipped, with reasons</summary><ul className="kvlist">{scan.scan.skipped.map((s, i) => <li key={i}><span className="mono">{s.path}</span>: {s.reason}</li>)}</ul></details>}
          <details style={{ marginTop: 6 }}><summary style={{ cursor: 'pointer' }}>Supported and unsupported inputs</summary><div className="row" style={{ alignItems: 'flex-start', gap: 24 }}><div><h3>Supported</h3><ul className="kvlist">{scan.scan.supported.map((s, i) => <li key={i}>{s}</li>)}</ul></div><div><h3>Not supported</h3><ul className="kvlist">{scan.scan.unsupported.map((s, i) => <li key={i}>{s}</li>)}</ul></div></div></details>
        </section>)}

      {scan && scan.scan.files.length > 0 && (
        <div className="home-grid" style={{ marginTop: 14, gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)' }}>
          <section className="card" aria-labelledby="src-sync">
            <h2 id="src-sync" style={{ marginBottom: 6 }}>3a. Sync topology (no AI)</h2>
            <p>Deterministic. Derives components, flows and boundaries from the files, records evidence with file, line and revision, compares with the previous state, and raises review items for connected threats, assumptions and mitigations. Your accepted work is never overwritten.</p>
            <button className="primary" disabled={!!busy} onClick={doSync}>{busy === 'sync' ? 'Syncing…' : 'Sync from this folder'}</button>
            {syncRes && (
              <div style={{ marginTop: 10 }}>
                <p style={{ margin: 0 }}><strong>{syncRes.changes.length}</strong> change(s) · <strong>{syncRes.reviewItems}</strong> new review item(s) · <strong>{syncRes.proposals}</strong> rule-pack proposal(s)</p>
                <ul className="kvlist">{syncRes.changes.filter((c) => !c.kind.endsWith('-added') || syncRes.changes.length < 8).slice(0, 8).map((c, i) => <li key={i}>{c.summary}</li>)}</ul>
                {syncRes.notes.length > 0 && <div className="callout warn">{syncRes.notes.join(' ')}</div>}
                <button onClick={() => go('review')}>{syncRes.reviewItems + syncRes.proposals > 0 ? 'Review what changed →' : 'Open Review'}</button>
              </div>)}
          </section>
          <section className="card" aria-labelledby="src-ai">
            <h2 id="src-ai" style={{ marginBottom: 6 }}>3b. AI-assisted draft (optional)</h2>
            {!settings ? <p className="hint">Loading settings…</p> : !adapterReady ? (
              <div className="callout warn">No AI provider is ready. Add a model identifier and credential in Settings. Everything else works without one.</div>
            ) : (
              <>
                <p>Sends the selected file text and the model's component, flow and threat names to <strong className="mono">{settings.active.host}</strong> (model <span className="mono">{settings.active.model}</span>). Output is validated and arrives as proposals you accept, edit or reject.</p>
                <div className="callout info"><strong>What would be sent</strong>
                  <ul className="kvlist">{[...picked].map((p) => <li key={p} className="mono">{p}</li>)}</ul>
                  {sd && <p className="hint" style={{ margin: 0 }}>{bytes(scan.scan.files.filter((f) => picked.has(f.path)).reduce((n, f) => n + f.bytes, 0))} of file text · {sd.redactions} secret-looking value(s) will be replaced with [REDACTED] · model context included</p>}
                </div>
                <p className="hint">{settings.active.capabilities.liveVerified ? '' : 'This adapter has not been verified against a live endpoint in this installation. '}Usage is reported when the provider returns it; cost only if you configure prices.</p>
                <label className="row" style={{ gap: 6, margin: '8px 0' }}><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I understand this text will be sent to {settings.active.host}</label>
                <div className="row wrap"><button className="primary" disabled={!confirm || picked.size === 0 || !!busy || !!runId && model.runs.find((r) => r.id === runId)?.status === 'running'} onClick={() => doAnalyze()}>Run analysis</button>
                  {model.reviewItems.some((r) => r.status === 'open') && <button disabled={!confirm || picked.size === 0 || !!busy} onClick={() => doAnalyze(focus())} title="Include the open review items as the focus">Analyse the open changes</button>}</div>
              </>)}
            {runId && <RunPanel runId={runId} onDone={() => toast('Analysis run finished.')} />}
          </section>
        </div>)}

      <section className="card" style={{ marginTop: 14 }} aria-labelledby="src-pack">
        <h2 id="src-pack" style={{ marginBottom: 6 }}>Offline suggestions from the generic rule pack</h2>
        <p>Looks at facts already in your model (externally reachable data stores, privileged containers, cleartext flows that cross a boundary) and proposes template threats. They are labelled as templates and arrive as proposals.</p>
        <button onClick={async () => { await session.flush(); const r = suggestFromPackClient(session); setPackMsg(r); }}>Suggest from rule pack</button> {packMsg && <span className="hint" role="status">{packMsg}</span>}
      </section>

      <section style={{ marginTop: 22 }} aria-labelledby="src-runs">
        <h2 id="src-runs" style={{ marginBottom: 8 }}>Analysis runs ({runs.length})</h2>
        {runs.length === 0 ? <p className="hint">No runs yet.</p> : (
          <table className="grid"><thead><tr><th scope="col">Started</th><th scope="col">Kind</th><th scope="col">Provider / model</th><th scope="col">Status</th><th scope="col">Tokens in / out</th><th scope="col">Cost</th><th scope="col">Proposals</th><th scope="col">Sent</th></tr></thead>
            <tbody>{runs.map((r) => (
              <tr key={r.id}><td>{fmtTime(r.startedAt)}</td><td>{r.kind}</td><td>{r.adapter ? `${r.adapter}${r.modelId ? ` / ${r.modelId}` : ''}` : 'none (deterministic)'}</td>
                <td>{r.status === 'completed' ? <Mark kind="ok">✓ completed</Mark> : r.status === 'running' ? <Mark kind="info">… running</Mark> : <Mark kind={r.status === 'failed' ? 'danger' : 'plain'}>{r.status === 'failed' ? '✕' : '⊘'} {r.status}</Mark>}{r.error && <div className="hint">{r.error}</div>}</td>
                <td>{r.usage.inputTokens ?? 'n/a'} / {r.usage.outputTokens ?? 'n/a'}</td><td>{r.usage.costUsd !== null ? `$${r.usage.costUsd.toFixed(4)}` : 'n/a'}</td><td>{r.proposalIds.length}</td><td>{r.kind === 'ai-analysis' ? `${r.inputManifest.length} file(s)` : '-'}</td></tr>))}</tbody></table>)}
      </section>
    </div>
  );
}
