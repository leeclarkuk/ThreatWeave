import { useMemo, useState, type ReactNode } from 'react';
import { addEntity, effectiveMitigationStatus, labelOf, type Model } from '@threatweave/core';
import { useWs } from './ctx';
import { BasisMark, Empty, LEVEL_TEXT, MitigationMark, OriginMark, ReviewMark, StaleMark, STRENGTH_GLYPH, TextField, fmtTime, Mark } from './ui';

const useOpenReview = (model: Model) => useMemo(() => {
  const m = new Map<string, number>();
  for (const r of model.reviewItems) if (r.status === 'open') m.set(r.target.id, (m.get(r.target.id) ?? 0) + 1);
  return m;
}, [model.reviewItems]);

function Head({ title, blurb, children }: { title: string; blurb: string; children?: ReactNode }) {
  return <div className="pagehead"><div className="grow"><h1>{title}</h1><p>{blurb}</p></div>{children}</div>;
}

function QuickAdd({ label, placeholder, onAdd }: { label: string; placeholder: string; onAdd: (text: string) => void }) {
  const [v, setV] = useState('');
  return (
    <form className="row" style={{ marginBottom: 12 }} onSubmit={(e) => { e.preventDefault(); if (v.trim()) { onAdd(v.trim()); setV(''); } }}>
      <label className="grow" style={{ margin: 0 }}><span className="sr">{label}</span><input value={v} onChange={(e) => setV(e.target.value)} placeholder={placeholder} aria-label={label} data-quickadd /></label>
      <button type="submit" className="primary" disabled={!v.trim()}>{label}</button>
    </form>
  );
}

export function ThreatsView() {
  const { session, model, actor, selection, select } = useWs();
  const review = useOpenReview(model);
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('all');
  const [flagged, setFlagged] = useState(false);
  const rows = model.threats.filter((t) => (status === 'all' || t.status === status) && (!flagged || review.has(t.id)) && (!q || `${t.title} ${t.source} ${t.action}`.toLowerCase().includes(q.toLowerCase())));
  const add = (title: string) => { let id = ''; session.mutate('Add threat', (m) => { const r = addEntity(m, 'threat', { title, status: 'open', basis: 'hypothesis' }, actor); id = r.id; return r.model; }, { immediate: true }); if (id) select({ type: 'threat', id }); };
  return (
    <div className="main">
      <Head title="Threats" blurb="Hypotheses about what could go wrong, each tied to the parts of the system it affects. Severity and evidence strength are judged separately." />
      <QuickAdd label="Add threat" placeholder="Name a threat, then describe it in the inspector…" onAdd={add} />
      <div className="row wrap" style={{ marginBottom: 10 }}>
        <label style={{ width: 240 }}><span className="sr">Search threats</span><input type="search" placeholder="Search threats" value={q} onChange={(e) => setQ(e.target.value)} data-search /></label>
        <label className="row" style={{ gap: 4 }}>Status <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 'auto' }}><option value="all">All</option><option value="open">Open</option><option value="mitigated">Mitigated</option><option value="accepted-risk">Risk accepted</option><option value="not-applicable">Not applicable</option></select></label>
        <label className="row" style={{ gap: 4 }}><input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} /> Needs review only</label>
      </div>
      {model.threats.length === 0 ? <Empty title="No threats yet">Name the first threat above. Describe the actor, what must be true, what they could do, and what it would cost you, then link it to a component or flow.</Empty> : rows.length === 0 ? <p className="hint">No threats match the filters.</p> : (
        <table className="grid">
          <thead><tr><th scope="col">Threat</th><th scope="col">Affects</th><th scope="col">Likelihood</th><th scope="col">Impact</th><th scope="col">Evidence</th><th scope="col">Claim</th><th scope="col">Status</th><th scope="col">Mitigations</th></tr></thead>
          <tbody>{rows.map((t) => {
            const ms = model.mitigations.filter((m) => m.threatIds.includes(t.id));
            return (
              <tr key={t.id} aria-selected={selection?.type === 'threat' && selection.id === t.id}>
                <td><button className="rowbtn" onClick={() => select({ type: 'threat', id: t.id })}>{t.title}</button> {review.has(t.id) && <ReviewMark n={review.get(t.id)} />}{t.provenance.origin !== 'human' && <> <OriginMark origin={t.provenance.origin} /></>}</td>
                <td>{t.targets.map((r) => labelOf(model, r)).join(', ') || <span className="hint">nothing linked</span>}</td>
                <td>{LEVEL_TEXT[t.likelihood.level]}</td><td>{LEVEL_TEXT[t.impact.level]}</td>
                <td className="mono">{STRENGTH_GLYPH[t.evidenceStrength]}</td>
                <td><BasisMark basis={t.basis} /></td>
                <td>{{ open: 'Open', mitigated: 'Mitigated', 'accepted-risk': 'Risk accepted', 'not-applicable': 'Not applicable' }[t.status]}</td>
                <td>{ms.length === 0 ? <span className="hint">none</span> : ms.map((m) => <div key={m.id}><MitigationMark status={m.status} staleVerification={effectiveMitigationStatus(model, m).includes('stale')} /></div>)}</td>
              </tr>);
          })}</tbody>
        </table>)}
    </div>
  );
}

export function AssumptionsView() {
  const { session, model, actor, selection, select } = useWs();
  const review = useOpenReview(model);
  const add = (text: string, kind: 'assumption' | 'question') => { let id = ''; session.mutate('Add assumption', (m) => { const r = addEntity(m, 'assumption', { text, kind, status: 'open' }, actor); id = r.id; return r.model; }, { immediate: true }); if (id) select({ type: 'assumption', id }); };
  const [kind, setKind] = useState<'assumption' | 'question'>('assumption');
  return (
    <div className="main">
      <Head title="Assumptions and open questions" blurb="What the model relies on but has not proven, and what is still unknown. Link them to the parts of the system they concern so a change can flag them." />
      <div className="row" style={{ marginBottom: 6 }}>
        <label className="row" style={{ gap: 4 }}><input type="radio" name="ak" checked={kind === 'assumption'} onChange={() => setKind('assumption')} /> Assumption</label>
        <label className="row" style={{ gap: 4 }}><input type="radio" name="ak" checked={kind === 'question'} onChange={() => setKind('question')} /> Open question</label>
      </div>
      <QuickAdd label={kind === 'assumption' ? 'Add assumption' : 'Add question'} placeholder={kind === 'assumption' ? 'e.g. The inventory service is only reachable from the backend network' : 'e.g. Is the API rate limited per customer?'} onAdd={(t) => add(t, kind)} />
      {model.assumptions.length === 0 ? <Empty title="Nothing recorded">State what you are taking on trust. Each assumption you write down is something a later change can be checked against.</Empty> : (
        <table className="grid"><thead><tr><th scope="col">Statement</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Relates to</th><th scope="col">Claim</th></tr></thead>
          <tbody>{model.assumptions.map((a) => (
            <tr key={a.id} aria-selected={selection?.type === 'assumption' && selection.id === a.id}>
              <td><button className="rowbtn" onClick={() => select({ type: 'assumption', id: a.id })}>{a.text}</button> {review.has(a.id) && <ReviewMark n={review.get(a.id)} />}</td>
              <td>{a.kind === 'question' ? 'Question' : 'Assumption'}</td>
              <td>{{ open: a.kind === 'question' ? 'Open' : 'Not yet validated', validated: 'Validated', invalidated: 'Invalidated', answered: 'Answered' }[a.status]}</td>
              <td>{a.relatesTo.map((r) => labelOf(model, r)).join(', ') || <span className="hint">nothing linked</span>}</td>
              <td><BasisMark basis={a.basis} /></td>
            </tr>))}</tbody></table>)}
    </div>
  );
}

export function MitigationsView() {
  const { session, model, actor, selection, select } = useWs();
  const review = useOpenReview(model);
  const add = (title: string) => { let id = ''; session.mutate('Add mitigation', (m) => { const r = addEntity(m, 'mitigation', { title, status: 'planned' }, actor); id = r.id; return r.model; }, { immediate: true }); if (id) select({ type: 'mitigation', id }); };
  const order = ['verified', 'implemented', 'in-progress', 'planned', 'proposed', 'wont-do'];
  const rows = [...model.mitigations].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status));
  return (
    <div className="main">
      <Head title="Mitigations" blurb="What reduces each threat, and its actual status. Implemented and verified are attested by a named person; verified needs evidence you can point to." />
      <QuickAdd label="Add mitigation" placeholder="Describe a control, then link it to threats…" onAdd={add} />
      {model.mitigations.length === 0 ? <Empty title="No mitigations yet">Link controls to the threats they reduce. Start them as planned; record implemented and verified only when true.</Empty> : (
        <table className="grid"><thead><tr><th scope="col">Mitigation</th><th scope="col">Status</th><th scope="col">Set by</th><th scope="col">Mitigates</th><th scope="col">Verification evidence</th></tr></thead>
          <tbody>{rows.map((m) => {
            const eff = effectiveMitigationStatus(model, m);
            return (
              <tr key={m.id} aria-selected={selection?.type === 'mitigation' && selection.id === m.id}>
                <td><button className="rowbtn" onClick={() => select({ type: 'mitigation', id: m.id })}>{m.title}</button> {review.has(m.id) && <ReviewMark n={review.get(m.id)} />}{m.provenance.origin !== 'human' && <> <OriginMark origin={m.provenance.origin} /></>}</td>
                <td><MitigationMark status={m.status} staleVerification={eff.includes('stale')} /></td>
                <td>{m.statusSetBy ? `${m.statusSetBy.actor}${m.statusSetBy.actorKind === 'import' ? ' (import)' : ''}` : <span className="hint">-</span>}</td>
                <td>{m.threatIds.map((t) => labelOf(model, { type: 'threat', id: t })).join('; ') || <span className="hint">no threat linked</span>}</td>
                <td>{m.verification.evidenceIds.length || <span className="hint">none</span>}</td>
              </tr>);
          })}</tbody></table>)}
    </div>
  );
}

export function EvidenceView() {
  const { session, model, actor, selection, select } = useWs();
  const [summary, setSummary] = useState('');
  const [onlyStale, setOnlyStale] = useState(false);
  const rows = model.evidence.filter((e) => !onlyStale || e.stale);
  return (
    <div className="main">
      <Head title="Evidence and sources" blurb="Where claims come from. Evidence tied to a source file records the revision and location, and is flagged stale when the cited text changes." />
      <section aria-labelledby="ev-h">
        <h2 id="ev-h" style={{ marginBottom: 8 }}>Evidence ({model.evidence.length})</h2>
        <form className="row" style={{ marginBottom: 10 }} onSubmit={(e) => { e.preventDefault(); if (!summary.trim()) return; let id = ''; session.mutate('Add evidence', (m) => { const r = addEntity(m, 'evidence', { kind: 'human-note', summary: summary.trim() }, actor); id = r.id; return r.model; }, { immediate: true }); setSummary(''); if (id) select({ type: 'evidence', id }); }}>
          <div className="grow"><TextField live label="Add a note from a person (recorded under your name)" value={summary} onCommit={setSummary} /></div>
          <button type="submit" className="primary" disabled={!summary.trim()} style={{ marginTop: 4 }}>Add note</button>
        </form>
        <label className="row" style={{ gap: 4, marginBottom: 8 }}><input type="checkbox" checked={onlyStale} onChange={(e) => setOnlyStale(e.target.checked)} /> Stale only</label>
        {rows.length === 0 ? <Empty title={onlyStale ? 'No stale evidence' : 'No evidence yet'}>Evidence is created when you attach a note, record a verification, accept a cited proposal, or scan a source.</Empty> : (
          <table className="grid"><thead><tr><th scope="col">Summary</th><th scope="col">Kind</th><th scope="col">Location</th><th scope="col">Revision</th><th scope="col">Origin</th><th scope="col">State</th></tr></thead>
            <tbody>{rows.map((e) => (
              <tr key={e.id} aria-selected={selection?.type === 'evidence' && selection.id === e.id}>
                <td><button className="rowbtn" onClick={() => select({ type: 'evidence', id: e.id })}>{e.summary}</button></td><td>{e.kind}</td>
                <td className="mono">{e.path ? `${e.path}${e.lineStart ? `:${e.lineStart}` : ''}` : '-'}</td><td className="mono">{e.revision?.slice(0, 10) ?? '-'}</td>
                <td><OriginMark origin={e.provenance.origin} actor={e.provenance.actor} /></td>
                <td>{e.stale ? <StaleMark reason={e.staleReason} /> : <Mark kind="ok">✓ Current</Mark>}</td>
              </tr>))}</tbody></table>)}
      </section>
      <section aria-labelledby="src-h" style={{ marginTop: 26 }}>
        <h2 id="src-h" style={{ marginBottom: 8 }}>Sources ({model.sources.length})</h2>
        {model.sources.length === 0 ? <p className="hint">No sources captured. Use the Source tab to scan a folder.</p> : (
          <table className="grid"><thead><tr><th scope="col">Source</th><th scope="col">Kind</th><th scope="col">Revision</th><th scope="col">VCS revision</th><th scope="col">Files</th><th scope="col">Captured</th></tr></thead>
            <tbody>{model.sources.map((s) => <tr key={s.id}><td>{s.label}</td><td>{s.kind}</td><td className="mono">{s.revision.slice(0, 12) || '-'}</td><td className="mono">{s.vcsRevision?.slice(0, 10) ?? '-'}</td><td>{s.files.length}</td><td>{fmtTime(s.capturedAt)}</td></tr>)}</tbody></table>)}
      </section>
    </div>
  );
}
