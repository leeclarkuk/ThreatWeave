import { useCallback, useEffect, useMemo, useState } from 'react';
import { effectiveMitigationStatus, renderMarkdownReport } from '@threatweave/core';
import { api } from './api';
import { WorkspaceCtx, TAB_OF, type Sel } from './ctx';
import { Session, useSession } from './session';
import { Mark, Modal, ReviewMark, useDialogs } from './ui';
import { ArchitectureView } from './ArchitectureView';
import { AssumptionsView, EvidenceView, MitigationsView, ThreatsView } from './ReasoningViews';
import { ReviewView } from './ReviewView';
import { SourceView } from './SourceView';
import { Inspector } from './Inspector';
import { SettingsDialog } from './SettingsDialog';

export const TABS = [
  { id: 'architecture', label: 'Architecture' }, { id: 'threats', label: 'Threats' }, { id: 'assumptions', label: 'Assumptions' }, { id: 'mitigations', label: 'Mitigations' },
  { id: 'evidence', label: 'Evidence' }, { id: 'review', label: 'Review' }, { id: 'source', label: 'Source' }, { id: 'report', label: 'Report' },
];

function ReportView() {
  const { model, session } = useWsLazy();
  const { toast } = useDialogs();
  const [warn, setWarn] = useState<{ text: string; filename: string; warnings: Array<{ level: string; message: string; count: number }> } | null>(null);
  const md = useMemo(() => renderMarkdownReport(model), [model]);
  const download = (text: string, filename: string, type: string) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); };
  const exp = async (fmt: 'json' | 'markdown' | 'tc') => {
    await session.flush();
    const r = await api.exportFile(session.id, fmt);
    if (fmt === 'tc' && r.warnings.length) { setWarn(r); return; }
    download(r.text, r.filename, fmt === 'markdown' ? 'text/markdown' : 'application/json'); toast(`Exported ${r.filename}.`);
  };
  return (
    <div className="main">
      <div className="pagehead"><div className="grow"><h1>Report and export</h1><p>The native JSON file is the portable, versioned source of truth and diffs cleanly in Git. The Markdown report is for reading and review.</p></div></div>
      <div className="row wrap" style={{ marginBottom: 14 }}>
        <button className="primary" onClick={() => exp('json')}>Download native JSON</button>
        <button onClick={() => exp('markdown')}>Download Markdown report</button>
        <button onClick={() => exp('tc')}>Export to Threat Composer (lossy)…</button>
      </div>
      <div className="callout info">Threat Composer export is a one-way, lossy conversion: it has no structured architecture, likelihood or impact, evidence, or provenance. You are shown exactly what is lost before download. Round trips are not lossless.</div>
      <h2 style={{ margin: '14px 0 8px' }}>Report preview</h2>
      <pre className="runlog" style={{ maxHeight: 'none', whiteSpace: 'pre-wrap' }} tabIndex={0} aria-label="Markdown report preview">{md}</pre>
      {warn && <Modal title="What the Threat Composer export loses" onClose={() => setWarn(null)}>
        <ul className="kvlist">{warn.warnings.map((w, i) => <li key={i}>{w.level === 'warning' ? '▲ ' : ''}{w.message}{w.count > 1 ? ` (×${w.count})` : ''}</li>)}</ul>
        <div className="actions"><button onClick={() => setWarn(null)}>Cancel</button><button className="primary" onClick={() => { download(warn.text, warn.filename, 'application/json'); setWarn(null); }}>Download anyway</button></div></Modal>}
    </div>
  );
}

import { useWs } from './ctx';
function useWsLazy() { return useWs(); }

export function Workspace({ id, tab, onTab, onHome }: { id: string; tab: string; onTab: (t: string) => void; onHome: () => void }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [selection, setSel] = useState<Sel | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [help, setHelp] = useState(false);
  const [actor, setActor] = useState('local-user');
  const model = useSession(session);

  useEffect(() => {
    let alive = true;
    setSession(null); setLoadErr(''); setSel(null);
    api.load(id).then((r) => { if (alive) setSession(new Session(id, r.model, r.etag, r.issues)); }).catch((e) => alive && setLoadErr((e as Error).message));
    api.settings().then((s) => alive && setActor(s.settings.actor)).catch(() => {});
    return () => { alive = false; };
  }, [id]);

  const select = useCallback((s: Sel | null) => setSel(s), []);
  useEffect(() => { document.getElementById('main')?.scrollTo(0, 0); }, [tab]);
  const open = useCallback((s: Sel) => { setSel(s); const t = TAB_OF[s.type]; if (t && t !== tab) onTab(t); }, [tab, onTab]);

  useEffect(() => {
    if (!session) return;
    const flush = () => { if (session.saveState === 'dirty') void session.flush(); };
    window.addEventListener('beforeunload', flush);
    const key = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'z' && !typing) { e.preventDefault(); if (e.shiftKey) session.redo(); else session.undo(); }
      else if (mod && e.key.toLowerCase() === 'y' && !typing) { e.preventDefault(); session.redo(); }
      else if (e.altKey && /^[1-8]$/.test(e.key)) { e.preventDefault(); onTab(TABS[Number(e.key) - 1]!.id); }
      else if (e.key === '?' && !typing) setHelp(true);
      else if (e.key === '/' && !typing) { const el = document.querySelector<HTMLInputElement>('[data-search],[data-quickadd]'); if (el) { e.preventDefault(); el.focus(); } }
      else if (e.key === 'Escape' && !typing && selection) setSel(null);
    };
    window.addEventListener('keydown', key);
    return () => { window.removeEventListener('beforeunload', flush); window.removeEventListener('keydown', key); };
  }, [session, selection, onTab]);

  if (loadErr) return <div className="main"><div className="callout err" role="alert">Could not open this project: {loadErr}</div><button onClick={onHome}>Back to projects</button></div>;
  if (!session || !model) return <div className="main" role="status">Loading project…</div>;

  const openReview = model.reviewItems.filter((r) => r.status === 'open').length;
  const pending = model.proposals.filter((p) => p.status === 'pending').length;
  const counts: Record<string, string | number> = { architecture: model.elements.length, threats: model.threats.length, assumptions: model.assumptions.length, mitigations: model.mitigations.length, evidence: model.evidence.length, review: openReview + pending, source: '' };
  const staleCount = model.evidence.filter((e) => e.stale).length;
  const ws = { session, model, actor, selection, select, go: onTab, tab, open, refreshExamples: 0 };
  const errs = session.issues.filter((i) => i.severity === 'warning');
  const flush = { saved: '✓ Saved', dirty: '● Unsaved changes', saving: '… Saving', error: '✕ Save failed', reloaded: '✓ Saved (merged)' }[session.saveState];
  void effectiveMitigationStatus;
  const view = tab === 'architecture' ? <ArchitectureView /> : tab === 'threats' ? <ThreatsView /> : tab === 'assumptions' ? <AssumptionsView /> : tab === 'mitigations' ? <MitigationsView /> : tab === 'evidence' ? <EvidenceView /> : tab === 'review' ? <ReviewView /> : tab === 'source' ? <SourceView /> : <ReportView />;
  const showInspector = tab !== 'report';
  return (
    <WorkspaceCtx.Provider value={ws}>
      <div className="app">
        <header className="topbar">
          <a className="brand" href="#/" onClick={(e) => { e.preventDefault(); void session.flush().then(onHome); }}><Logo />ThreatWeave</a>
          <div className="crumb"><span aria-hidden>/</span><strong>{model.name}</strong>{model.example && <Mark kind="info" dashed>Demonstration</Mark>}</div>
          <span className="spacer" />
          <span className="savestate" role="status" aria-live="polite">{flush}</span>
          <button className="small" disabled={!session.canUndo} onClick={() => session.undo()} aria-label="Undo" title="Undo (Ctrl+Z)">↶ Undo</button>
          <button className="small" disabled={!session.canRedo} onClick={() => session.redo()} aria-label="Redo" title="Redo (Ctrl+Shift+Z)">↷ Redo</button>
          <button className="small" onClick={() => setHelp(true)} aria-label="Keyboard shortcuts">?</button>
          <button className="small" onClick={() => setSettingsOpen(true)}>Settings</button>
        </header>
        <div className={`workspace${showInspector ? '' : ' noinspector'}`}>
          <nav className="rail" aria-label="Sections">
            {TABS.map((t, i) => (
              <a key={t.id} href={`#/p/${id}/${t.id}`} aria-current={tab === t.id ? 'page' : undefined} onClick={(e) => { e.preventDefault(); onTab(t.id); }} title={`Alt+${i + 1}`}>
                <span>{t.label}</span>
                {t.id === 'review' && openReview + pending > 0 ? <span className="mark review" title={`${openReview} open review item(s), ${pending} proposal(s)`}>◆ {openReview + pending}<span className="sr"> need review</span></span> : counts[t.id] !== undefined && counts[t.id] !== '' ? <span className="count">{counts[t.id]}</span> : null}
              </a>))}
            <div className="sep" />
            <p className="hint" style={{ padding: '0 8px' }}>{staleCount > 0 ? `▲ ${staleCount} stale evidence` : ''}</p>
          </nav>
          <main id="main" className={`${tab === 'architecture' ? 'main flush' : ''}`} style={tab === 'architecture' ? { padding: 0, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' } : { overflow: 'auto', padding: 0 }}>
            {session.message && <div className={`callout ${session.saveState === 'error' ? 'err' : 'warn'}`} role="alert" style={{ margin: 12, display: 'flex', gap: 10 }}><span className="grow">{session.message}</span><button className="small" onClick={() => session.dismissMessage()}>Dismiss</button>{session.saveState === 'error' && <button className="small" onClick={() => void session.flush()}>Retry save</button>}</div>}
            {errs.length > 0 && tab !== 'architecture' && <details style={{ margin: '8px 22px 0' }}><summary className="hint" style={{ cursor: 'pointer' }}>{errs.length} model warning(s)</summary><ul className="kvlist hint">{errs.slice(0, 10).map((e, i) => <li key={i}>{e.message}</li>)}</ul></details>}
            {view}
          </main>
          {showInspector && <aside className={`inspector${selection ? ' open' : ''}`} aria-label="Inspector" tabIndex={-1}><button className="small inspector-close" onClick={() => select(null)}>✕ Close inspector</button><Inspector /></aside>}
        </div>
        {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} onSaved={(s) => setActor(s.actor)} />}
        {help && <Modal title="Keyboard shortcuts" onClose={() => setHelp(false)}>
          <dl className="kv" style={{ gridTemplateColumns: '150px 1fr' }}>
            <dt><code>Ctrl/⌘ Z</code></dt><dd>Undo</dd><dt><code>Ctrl/⌘ Shift Z</code></dt><dd>Redo</dd><dt><code>Alt 1 to 8</code></dt><dd>Switch section</dd><dt><code>/</code></dt><dd>Focus search or the add field</dd>
            <dt><code>Esc</code></dt><dd>Clear selection</dd><dt><code>Tab</code></dt><dd>Move through controls; table rows are buttons</dd><dt><code>Delete</code></dt><dd>On the canvas: remove the selected component or flow</dd>
            <dt><code>Arrow keys</code></dt><dd>On the canvas: move the focused, selected component</dd>
          </dl><p className="hint">The Architecture section has a Table view with every canvas operation, no pointer needed.</p><div className="actions"><button className="primary" onClick={() => setHelp(false)}>Close</button></div></Modal>}
      </div>
    </WorkspaceCtx.Provider>
  );
}

export const Logo = () => (
  <svg width="24" height="24" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="6" fill="#273449" /><path d="M6 10h20M6 16h20M6 22h20M10 6v20M16 6v20M22 6v20" stroke="#f0b45a" strokeWidth="2" fill="none" /></svg>
);
