import { useEffect, useMemo, useState } from 'react';
import {
  ProposalPayload, acceptProposal, deriveReviewItems, diffModels, grammar, labelOf, rejectProposal, resolveReviewItem,
  type Change, type Model, type Proposal, type ReviewItem,
} from '@threatweave/core';
import { api } from './api';
import { useWs } from './ctx';
import { BasisMark, Empty, Mark, OriginMark, ReviewMark, SelectField, TextField, ListField, fmtTime, useDialogs } from './ui';

const KIND_TITLE: Record<string, string> = { 'add-element': 'Component', 'add-flow': 'Data flow', 'add-boundary': 'Trust boundary', 'add-asset': 'Asset', 'add-threat': 'Threat', 'add-mitigation': 'Mitigation', 'add-assumption': 'Assumption', 'add-question': 'Open question' };
const payloadTitle = (p: Proposal['payload']): string => (p.kind === 'add-flow' ? `${p.from} → ${p.to}` : 'title' in p ? p.title : 'name' in p ? p.name : p.text);

/* ---------------- review items, grouped per target ---------------- */
function ReviewGroup({ items }: { items: ReviewItem[] }) {
  const { model, session, actor, open, select, selection, go } = useWs();
  const { ask, toast } = useDialogs();
  const first = items[0]!;
  const close = async (r: ReviewItem, action: 'resolve' | 'dismiss') => {
    const reason = await ask({ title: action === 'resolve' ? 'Resolve review item' : 'Dismiss review item', label: action === 'resolve' ? 'What did you check or change?' : 'Why is no action needed?', required: true, confirmLabel: action === 'resolve' ? 'Resolve' : 'Dismiss', body: <p className="hint">{r.reason}</p> });
    if (reason === null) return;
    if (session.mutate('Close review item', (m) => resolveReviewItem(m, r.id, action, actor, reason), { immediate: true })) toast('Recorded as a decision under your name.');
  };
  const closeAll = async (action: 'resolve' | 'dismiss') => {
    const open_ = items.filter((i) => i.status === 'open');
    const reason = await ask({ title: `${action === 'resolve' ? 'Resolve' : 'Dismiss'} all ${open_.length} items for this ${first.target.type}`, label: action === 'resolve' ? 'What did you check or change?' : 'Why is no action needed?', required: true, confirmLabel: action === 'resolve' ? 'Resolve all' : 'Dismiss all' });
    if (reason === null) return;
    if (session.mutate('Close review items', (m) => open_.reduce((acc, i) => resolveReviewItem(acc, i.id, action, actor, reason), m), { immediate: true })) toast(`Recorded ${open_.length} decisions under your name.`);
  };
  const anyOpen = items.some((i) => i.status === 'open');
  const sel = selection?.type === 'review' && items.some((i) => i.id === selection.id);
  return (
    <article className="card flag" style={{ marginBottom: 10, outline: sel ? '2px solid var(--focus)' : undefined }} aria-label={`Review items for ${first.target.type} ${labelOf(model, first.target)}`}>
      <div className="row wrap">
        {anyOpen ? <ReviewMark n={items.filter((i) => i.status === 'open').length} /> : <Mark kind="plain">✓ Closed</Mark>}
        <Mark>{first.target.type}</Mark>
        <button className="ghost" style={{ fontWeight: 650, padding: '0 4px' }} onClick={() => open({ type: first.target.type, id: first.target.id })}>{labelOf(model, first.target)}</button>
        <span className="spacer" />
        <button className="small ghost" onClick={() => { select({ type: 'review', id: first.id }); go('architecture'); }}>Show on diagram</button>
      </div>
      {items.map((r) => (
        <div key={r.id} style={{ borderTop: '1px solid var(--line)', marginTop: 8, paddingTop: 8 }}>
          <p style={{ margin: 0 }}>{r.status !== 'open' && <Mark kind="plain">{r.status === 'resolved' ? '✓ Resolved' : '✕ Dismissed'}</Mark>} {r.reason}</p>
          <details className="why"><summary>Why was this flagged?</summary>
            <ol>{r.trace.map((t, i) => <li key={i}>{t}</li>)}</ol>
            <p className="hint" style={{ marginTop: 6 }}>{r.deterministic ? 'Deterministic: raised by comparing two model revisions and following explicit links. It is not an AI judgement and not an attack-path analysis.' : 'Interpretation.'} Raised {fmtTime(r.raisedAt)}.</p>
          </details>
          {r.status === 'open' ? (items.length > 1 && <div className="row" style={{ marginTop: 4 }}><button className="small ghost" onClick={() => close(r, 'resolve')}>Resolve this one…</button><button className="small ghost" onClick={() => close(r, 'dismiss')}>Dismiss this one…</button></div>)
            : <p className="hint" style={{ margin: '4px 0 0' }}>{(() => { const d = model.decisions.find((x) => x.id === r.decisionId); return d ? `${d.actor}: “${d.rationale}” (${fmtTime(d.at)})` : ''; })()}</p>}
        </div>))}
      {anyOpen && <div className="row" style={{ marginTop: 10 }}>
        <button className="small primary" onClick={() => (items.length > 1 ? closeAll('resolve') : close(items[0]!, 'resolve'))}>Resolve{items.length > 1 ? ' all' : ''}…</button>
        <button className="small" onClick={() => (items.length > 1 ? closeAll('dismiss') : close(items[0]!, 'dismiss'))}>Dismiss{items.length > 1 ? ' all' : ''}…</button>
      </div>}
    </article>
  );
}

/* ---------------- proposal editor ---------------- */
const ENUMS: Record<string, string[]> = {
  elementKind: ['process', 'datastore', 'external-system', 'actor'], exposure: ['unknown', 'internal', 'external'], authenticated: ['unknown', 'yes', 'no'], encrypted: ['unknown', 'yes', 'no'],
  boundaryKind: ['network', 'process', 'account', 'organisation', 'physical', 'other'], classification: ['unknown', 'public', 'internal', 'confidential', 'restricted'], evidenceStrength: ['none', 'weak', 'moderate', 'strong'],
};
const LONG = new Set(['description', 'action', 'consequence', 'text']);
function PayloadEditor({ value, onChange }: { value: Record<string, any>; onChange: (v: Record<string, any>) => void }) {
  const set = (k: string, v: unknown) => onChange({ ...value, [k]: v });
  return (
    <div>
      {Object.entries(value).filter(([k]) => k !== 'kind').map(([k, v]) => {
        if (ENUMS[k]) return <SelectField key={k} label={k} value={String(v)} onChange={(x) => set(k, x)} options={ENUMS[k]!.map((o) => ({ value: o, label: o }))} />;
        if (typeof v === 'string') return <TextField key={k} label={k} multiline={LONG.has(k) || v.length > 80} value={v} onCommit={(x) => set(k, x)} />;
        if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return <ListField key={k} label={k} value={v} onCommit={(x) => set(k, x)} hint={['stride', 'threats', 'members', 'storedIn'].includes(k) ? 'One per line (ids or exact names)' : 'One per line'} />;
        if (v && typeof v === 'object' && 'level' in v) return (
          <div key={k}><SelectField label={`${k} level`} value={v.level} onChange={(x) => set(k, { ...v, level: x })} options={['unknown', 'low', 'medium', 'high'].map((o) => ({ value: o, label: o }))} /><TextField label={`${k} rationale`} multiline value={v.rationale} onCommit={(x) => set(k, { ...v, rationale: x })} /></div>);
        return <p key={k} className="hint">{k}: {JSON.stringify(v)} (edit in Advanced JSON)</p>;
      })}
    </div>
  );
}

function ProposalCard({ p }: { p: Proposal }) {
  const { model, session, actor, select, selection, go } = useWs();
  const { ask, toast } = useDialogs();
  const [editing, setEditing] = useState(false);
  const [adv, setAdv] = useState(false);
  const [draft, setDraft] = useState<Record<string, any>>(p.payload as Record<string, any>);
  const [json, setJson] = useState('');
  const [err, setErr] = useState('');
  const run = model.runs.find((r) => r.id === p.runId);
  const sel = selection?.type === 'proposal' && selection.id === p.id;
  const pl = p.payload;

  const parsed = ProposalPayload.safeParse(adv ? (() => { try { return JSON.parse(json); } catch { return null; } })() : draft);
  const accept = (edited?: unknown) => {
    setErr('');
    const ok = session.mutate('Accept proposal', (m) => acceptProposal(m, p.id, { actor, ...(edited !== undefined ? { edited } : {}) }), { immediate: true });
    if (ok) { toast(`Accepted by ${actor}. It is in the model with ${p.origin === 'pack-rule' ? 'rule-pack' : 'AI'} provenance${pl.kind === 'add-mitigation' ? ' and status "proposed"' : ''}.`); setEditing(false); }
    else setErr(session.message ?? 'Could not accept');
  };
  const reject = async () => {
    const reason = await ask({ title: 'Reject proposal', label: 'Why?', required: true, placeholder: 'e.g. Not applicable here / Already covered by … / Wrong', confirmLabel: 'Reject' });
    if (reason === null) return;
    if (session.mutate('Reject proposal', (m) => rejectProposal(m, p.id, { actor, rationale: reason }), { immediate: true })) toast('Rejected. Re-analysis will not bring it back.');
  };
  const decision = model.decisions.find((d) => d.id === p.decisionId);
  return (
    <article className={`card proposal${sel ? '' : ''}`} style={{ outline: sel ? '2px solid var(--focus)' : undefined }} aria-label={`Proposal: ${payloadTitle(pl)}`}>
      <div className="head">
        <Mark kind="info">◇ Proposed {KIND_TITLE[pl.kind]}</Mark><OriginMark origin={p.origin} /><BasisMark basis={p.basis} />
        {p.status !== 'pending' && <Mark kind={p.status === 'accepted' ? 'ok' : 'plain'}>{p.status === 'accepted' ? '✓ Accepted' : '✕ Rejected'}</Mark>}
        <span className="spacer" />
        <button className="small ghost" onClick={() => { select({ type: 'proposal', id: p.id }); go('architecture'); }}>Show on diagram</button>
      </div>
      <h2 style={{ marginBottom: 4 }}>{payloadTitle(pl)}</h2>
      {pl.kind === 'add-threat' && <p style={{ margin: '0 0 6px', color: 'var(--ink-2)' }}>{grammar(pl.source, pl.preconditions, pl.action, pl.consequence)}</p>}
      {pl.kind === 'add-mitigation' && <p style={{ margin: '0 0 6px', color: 'var(--ink-2)' }}>{pl.description}</p>}
      {'description' in pl && pl.kind !== 'add-mitigation' && pl.description && <p style={{ margin: '0 0 6px', color: 'var(--ink-2)' }}>{pl.description}</p>}
      <dl className="kv" style={{ marginBottom: 6 }}>
        {pl.kind === 'add-threat' && <><dt>Affects</dt><dd>{pl.targets.map((t) => resolveName(model, t.ref)).join(', ')}</dd><dt>Likelihood</dt><dd>{pl.likelihood.level} <span className="hint">{pl.likelihood.rationale}</span></dd><dt>Impact</dt><dd>{pl.impact.level} <span className="hint">{pl.impact.rationale}</span></dd><dt>Evidence</dt><dd>{pl.evidenceStrength}</dd></>}
        {pl.kind === 'add-mitigation' && <><dt>Mitigates</dt><dd>{pl.threats.map((t) => resolveName(model, t)).join(', ')}</dd>{pl.verificationSteps.length > 0 && <><dt>Check by</dt><dd>{pl.verificationSteps.join('; ')}</dd></>}</>}
        {(pl.kind === 'add-question' || pl.kind === 'add-assumption') && pl.relatesTo.length > 0 && <><dt>Relates to</dt><dd>{pl.relatesTo.map((t) => resolveName(model, t.ref)).join(', ')}</dd></>}
        {pl.kind === 'add-flow' && <><dt>Flow</dt><dd>{resolveName(model, pl.from)} → {resolveName(model, pl.to)}</dd></>}
      </dl>
      <h3 style={{ marginTop: 8 }}>Why it applies</h3>
      <p style={{ margin: '2px 0 6px' }}>{p.reasoning}</p>
      {p.trigger && <p className="hint">Trigger: {p.trigger}</p>}
      <h3>Evidence</h3>
      {p.evidence.length === 0 ? <p className="hint">No citation. This is a {p.basis}, not something shown by a file.</p> : p.evidence.map((e, i) => (
        <div key={i}><span className="mono">{e.path}:{e.lineStart}{e.lineEnd !== e.lineStart ? `-${e.lineEnd}` : ''}</span> {e.verified ? <Mark kind="ok">✓ quote found in analysed file</Mark> : <Mark kind="danger">✕ not verified</Mark>}<blockquote>{e.quote}</blockquote></div>))}
      {p.missingInformation.length > 0 && <><h3>Missing information</h3><ul className="kvlist">{p.missingInformation.map((m, i) => <li key={i}>{m}</li>)}</ul></>}
      {p.validationNotes.length > 0 && <div className="callout warn" style={{ marginTop: 8 }}><strong>Validation notes</strong><ul className="kvlist">{p.validationNotes.map((m, i) => <li key={i}>{m}</li>)}</ul></div>}
      {run && <p className="hint">From run {fmtTime(run.startedAt)}{run.adapter ? ` · ${run.adapter}${run.modelId ? ` / ${run.modelId}` : ''}` : ''}</p>}
      {p.status === 'pending' && !editing && (
        <div className="actions">
          <button className="primary" onClick={() => accept()}>Accept</button>
          <button onClick={() => { setDraft(structuredClone(p.payload) as Record<string, any>); setJson(JSON.stringify(p.payload, null, 2)); setAdv(false); setEditing(true); }}>Edit then accept…</button>
          <button onClick={reject}>Reject…</button>
        </div>)}
      {err && <div className="callout err" role="alert" style={{ marginTop: 8 }}>{err}</div>}
      {editing && (
        <div className="card" style={{ marginTop: 10, background: 'var(--surface-2)' }}>
          <div className="row" style={{ marginBottom: 8 }}><strong>Edit before accepting</strong><span className="spacer" /><label className="row" style={{ gap: 4 }}><input type="checkbox" checked={adv} onChange={(e) => { setAdv(e.target.checked); if (e.target.checked) setJson(JSON.stringify(draft, null, 2)); else { try { setDraft(JSON.parse(json)); } catch { /* keep draft */ } } }} /> Advanced JSON</label></div>
          {adv ? <TextField label="Payload JSON" multiline rows={14} mono value={json} onCommit={setJson} /> : <PayloadEditor value={draft} onChange={setDraft} />}
          {!parsed.success && <div className="callout err" role="alert">{parsed.error.issues[0]?.path.join('.')}: {parsed.error.issues[0]?.message}</div>}
          <div className="actions"><button onClick={() => setEditing(false)}>Cancel</button><button className="primary" disabled={!parsed.success} onClick={() => accept(parsed.data)}>Accept with edits</button></div>
        </div>)}
      {decision && <p className="hint" style={{ marginTop: 8 }}>{decision.actor} {decision.action}ed{decision.rationale ? `: “${decision.rationale}”` : ''} ({fmtTime(decision.at)})</p>}
    </article>
  );
}
function resolveName(model: Model, ref: string): string {
  const all = [...model.elements, ...model.flows, ...model.boundaries, ...model.assets, ...model.threats, ...model.assumptions];
  const hit = all.find((e) => e.id === ref);
  if (hit) { const t = ('name' in hit ? hit.name : 'title' in hit ? hit.title : 'text' in hit ? hit.text : ref) as string; return t; }
  const sib = model.proposals.find((x) => x.key === ref);
  return sib ? `${payloadTitle(sib.payload)} (proposed)` : ref;
}

/* ---------------- compare ---------------- */
function ComparePanel() {
  const { session, model } = useWs();
  const [revs, setRevs] = useState<Array<{ id: string }>>([]);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('current');
  const [result, setResult] = useState<{ changes: Change[]; items: ReviewItem[]; a: Model; b: Model } | null>(null);
  const [err, setErr] = useState('');
  const { toast } = useDialogs();
  useEffect(() => { api.revisions(session.id).then((r) => { setRevs(r); if (!from && r.length) setFrom(r[0]!.id); }).catch(() => {}); }, [session.id, model.runs.length]);
  const load = async (id: string): Promise<Model> => (id === 'current' ? session.model : (await api.revision(session.id, id)).model);
  const compare = async () => {
    setErr('');
    try { const [a, b] = await Promise.all([load(from), load(to)]); const changes = diffModels(a, b); setResult({ changes, items: deriveReviewItems(a, b, changes), a, b }); } catch (e) { setErr((e as Error).message); }
  };
  const opts = [...revs.map((r) => ({ value: r.id, label: r.id })), { value: 'current', label: 'current (working copy)' }];
  return (
    <section aria-labelledby="cmp-h" style={{ marginTop: 28 }}>
      <h2 id="cmp-h" style={{ marginBottom: 6 }}>Compare two revisions</h2>
      <p className="hint">Snapshots are taken automatically before and after each source sync, and on request. Comparison is deterministic: it reports what changed in components, flows, boundaries and evidence, and which reasoning is connected through explicit links. It does not claim to find every impact.</p>
      <div className="row wrap" style={{ alignItems: 'flex-end' }}>
        <div style={{ width: 240 }}><SelectField label="From (earlier)" value={from} onChange={setFrom} options={[{ value: '', label: 'Choose…' }, ...opts]} /></div>
        <div style={{ width: 240 }}><SelectField label="To (later)" value={to} onChange={setTo} options={opts} /></div>
        <button className="primary" style={{ marginBottom: 10 }} disabled={!from} onClick={compare}>Compare</button>
        <button style={{ marginBottom: 10 }} onClick={async () => { await session.flush(); const r = await api.snapshot(session.id, 'manual'); toast(`Snapshot ${r.id} saved.`); setRevs(await api.revisions(session.id)); }}>Snapshot current</button>
      </div>
      {err && <div className="callout err">{err}</div>}
      {result && (
        <div className="stack">
          <h3>{result.changes.length} change(s)</h3>
          {result.changes.length === 0 && <p className="hint">No semantic differences.</p>}
          {result.changes.map((c) => <div key={c.id} className="diffrow"><Mark kind={['element-exposure-changed', 'element-added', 'flow-added', 'element-missing-from-source', 'boundary-membership-changed'].includes(c.kind) ? 'review' : 'plain'}>{c.kind.replace(/-/g, ' ')}</Mark><span>{c.summary}</span></div>)}
          <h3>{result.items.length} review item(s) this comparison would raise</h3>
          {result.items.map((r) => (
            <div key={r.id} className="diffrow"><Mark kind="review">◆ {r.target.type}</Mark><div><strong>{labelOf(result.b, r.target) === `${r.target.id} (missing)` ? labelOf(result.a, r.target) : labelOf(result.b, r.target)}</strong><br />{r.reason}<details className="why"><summary>Trace</summary><ol>{r.trace.map((t, i) => <li key={i}>{t}</li>)}</ol></details></div></div>))}
          <p className="hint">Preview only. Items are added to the project when you run a source sync.</p>
        </div>)}
    </section>
  );
}

/* ---------------- main view ---------------- */
export function ReviewView() {
  const { model } = useWs();
  const [showClosed, setShowClosed] = useState(false);
  const open = model.reviewItems.filter((r) => r.status === 'open');
  const closed = model.reviewItems.filter((r) => r.status !== 'open');
  const pending = model.proposals.filter((p) => p.status === 'pending');
  const decided = model.proposals.filter((p) => p.status !== 'pending');
  const items = useMemo(() => (showClosed ? model.reviewItems : open), [model.reviewItems, showClosed]);
  const groups = useMemo(() => {
    const order = ['element', 'flow', 'boundary', 'threat', 'assumption', 'mitigation', 'asset', 'evidence'];
    const m = new Map<string, ReviewItem[]>();
    for (const r of items) { const k = `${r.target.type}:${r.target.id}`; m.set(k, [...(m.get(k) ?? []), r]); }
    return [...m.values()].sort((a, b) => order.indexOf(a[0]!.target.type) - order.indexOf(b[0]!.target.type));
  }, [items]);
  return (
    <div className="main">
      <div className="pagehead"><div className="grow"><h1>Review</h1><p>What changed, which assumptions it may have invalidated, and what needs a decision. Nothing here changes your accepted work until a person decides.</p></div></div>
      <section aria-labelledby="rv-open">
        <div className="row" style={{ marginBottom: 8 }}><h2 id="rv-open">Needs review ({open.length})</h2><span className="spacer" />{closed.length > 0 && <label className="row" style={{ gap: 4 }}><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Show {closed.length} closed</label>}</div>
        {groups.length > 0 && <p className="hint" style={{ marginTop: -4 }}>{items.length} item{items.length === 1 ? '' : 's'} across {groups.length} component{groups.length === 1 ? '' : 's'}, flow{groups.length === 1 ? '' : 's'} or other element{groups.length === 1 ? '' : 's'}. Each card groups everything raised for one element.</p>}
        {items.length === 0 ? <Empty title="Nothing needs review">Review items appear when a source sync or comparison finds a change connected to your threats, assumptions or mitigations.</Empty> : groups.map((g) => <ReviewGroup key={`${g[0]!.target.type}:${g[0]!.target.id}`} items={g} />)}
      </section>
      <section aria-labelledby="rv-prop" style={{ marginTop: 26 }}>
        <h2 id="rv-prop" style={{ marginBottom: 8 }}>Proposals awaiting a decision ({pending.length})</h2>
        {pending.length === 0 ? <Empty title="No pending proposals">Proposals come from AI analysis, the rule pack, or an MCP client. Each is validated before it appears here, and none enters the model until you accept it.</Empty> : pending.map((p) => <ProposalCard key={p.id} p={p} />)}
        {decided.length > 0 && <details style={{ marginTop: 12 }}><summary style={{ cursor: 'pointer' }}>{decided.length} decided proposal(s)</summary><div style={{ marginTop: 10 }}>{decided.slice().reverse().map((p) => <ProposalCard key={p.id} p={p} />)}</div></details>}
      </section>
      <ComparePanel />
    </div>
  );
}
