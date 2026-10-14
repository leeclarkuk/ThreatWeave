import { useState, type ReactNode } from 'react';
import {
  addEntity, labelOf, recordDecision, relatedTo, removeEntity, resolveReviewItem, setMitigationStatus, setThreatStatus, threatStatement, updateEntity, effectiveMitigationStatus,
  type Evidence, type Model, type MitigationStatus, type Ref, type RefType,
} from '@threatweave/core';
import { useWs, TAB_OF, type Sel } from './ctx';
import { BasisMark, LEVEL_TEXT, ListField, MitigationMark, Modal, OriginMark, RefPicker, ReviewMark, SelectField, StaleMark, STRENGTH_GLYPH, TextField, fmtTime, useDialogs, Mark } from './ui';
import { KIND_LABEL } from './ArchitectureView';

type Kind = 'element' | 'flow' | 'boundary' | 'asset' | 'assumption' | 'threat' | 'mitigation' | 'evidence';

function useEdit() {
  const { session, actor, select } = useWs();
  const upd = (type: Kind, id: string, patch: Record<string, unknown>, label = 'Edit') => session.mutate(label, (m) => updateEntity(m, type, id, patch));
  const add = (type: Kind, input: Record<string, unknown>, label = 'Add'): string => {
    let id = '';
    session.mutate(label, (m) => { const r = addEntity(m, type, input, actor); id = r.id; return r.model; }, { immediate: true });
    return id;
  };
  const del = (type: Kind, id: string) => { session.mutate('Delete', (m) => removeEntity(m, type, id), { immediate: true }); select(null); };
  return { upd, add, del, session, actor };
}

const Section = ({ title, children, count }: { title: string; children: ReactNode; count?: number }) => (
  <section style={{ marginTop: 18 }} aria-label={title}><h3 style={{ marginBottom: 6 }}>{title}{count !== undefined ? ` (${count})` : ''}</h3>{children}</section>
);

/* ---------- open review items for an entity ---------- */
export function ReviewHere({ type, id }: { type: string; id: string }) {
  const { model, session, actor, open } = useWs();
  const { ask, toast } = useDialogs();
  const items = model.reviewItems.filter((r) => r.status === 'open' && r.target.type === type && r.target.id === id);
  if (!items.length) return null;
  const close = async (rid: string, action: 'resolve' | 'dismiss') => {
    const reason = await ask({ title: action === 'resolve' ? 'Resolve review item' : 'Dismiss review item', label: action === 'resolve' ? 'What did you check or change?' : 'Why is no action needed?', required: true, confirmLabel: action === 'resolve' ? 'Resolve' : 'Dismiss', placeholder: 'Recorded with your name as a decision' });
    if (reason === null) return;
    if (session.mutate('Close review item', (m) => resolveReviewItem(m, rid, action, actor, reason), { immediate: true })) toast('Recorded.');
  };
  return (
    <Section title="Needs review" count={items.length}>
      {items.map((r) => (
        <div key={r.id} className="card flag" style={{ marginBottom: 8, padding: 10 }}>
          <ReviewMark />
          <p style={{ margin: '6px 0 0' }}>{r.reason}</p>
          <details className="why"><summary>Why was this flagged?</summary>
            <ol>{r.trace.map((t, i) => <li key={i}>{t}</li>)}</ol>
            <p className="hint" style={{ marginTop: 6 }}>{r.deterministic ? 'Deterministic: raised by comparing model revisions and following explicit links. Not an AI judgement.' : 'Interpretation.'} Raised {fmtTime(r.raisedAt)}.</p>
          </details>
          <div className="row" style={{ marginTop: 8 }}>
            <button className="small" onClick={() => close(r.id, 'resolve')}>Resolve…</button>
            <button className="small" onClick={() => close(r.id, 'dismiss')}>Dismiss…</button>
            <button className="small ghost" onClick={() => open({ type: 'review', id: r.id })}>Open in Review</button>
          </div>
        </div>
      ))}
    </Section>
  );
}

/* ---------- evidence ---------- */
function AddEvidence({ onAdded }: { onAdded: (id: string) => void }) {
  const { add } = useEdit();
  const [on, setOn] = useState(false);
  const [kind, setKind] = useState<'human-note' | 'test-result' | 'document'>('human-note');
  const [summary, setSummary] = useState('');
  if (!on) return <button className="small" onClick={() => setOn(true)}>＋ Add evidence…</button>;
  return (
    <div className="card" style={{ padding: 10 }}>
      <SelectField label="Kind" value={kind} onChange={setKind} options={[{ value: 'human-note', label: 'Note from a person' }, { value: 'test-result', label: 'Test or check result' }, { value: 'document', label: 'Document or ticket' }]} />
      <TextField live label="What does this show, and where can it be found?" multiline value={summary} onCommit={setSummary} hint="Recorded under your name. Do not paste secrets." />
      <div className="row"><button className="primary small" disabled={!summary.trim()} onClick={() => { const id = add('evidence', { kind, summary: summary.trim() }, 'Add evidence'); setOn(false); setSummary(''); if (id) onAdded(id); }}>Add</button><button className="small" onClick={() => setOn(false)}>Cancel</button></div>
    </div>
  );
}

function EvidenceList({ model, ids, onChange, label = 'Evidence' }: { model: Model; ids: string[]; onChange: (ids: string[]) => void; label?: string }) {
  const { open } = useWs();
  const rest = model.evidence.filter((e) => !ids.includes(e.id));
  return (
    <Section title={label} count={ids.length}>
      {ids.length === 0 && <p className="hint">None attached.</p>}
      {ids.map((id) => {
        const e = model.evidence.find((x) => x.id === id);
        if (!e) return <p key={id} className="hint">{id} (missing)</p>;
        return (
          <div key={id} className="card" style={{ padding: 8, marginBottom: 6 }}>
            <div className="row wrap">{e.stale && <StaleMark reason={e.staleReason} />}<OriginMark origin={e.provenance.origin} actor={e.provenance.actor} /><span className="spacer" /><button className="small ghost" onClick={() => onChange(ids.filter((x) => x !== id))} aria-label="Detach evidence">Detach</button></div>
            <p style={{ margin: '4px 0 0' }}><button className="ghost small" style={{ padding: 0 }} onClick={() => open({ type: 'evidence', id })}>{e.summary}</button></p>
            {e.path && <p className="hint mono" style={{ margin: 0 }}>{e.path}{e.lineStart ? `:${e.lineStart}${e.lineEnd && e.lineEnd !== e.lineStart ? `-${e.lineEnd}` : ''}` : ''}{e.revision ? ` @ ${e.revision.slice(0, 10)}` : ''}</p>}
            {e.stale && <p className="hint" style={{ margin: 0 }}>{e.staleReason}</p>}
          </div>
        );
      })}
      <div className="row wrap">
        {rest.length > 0 && <select aria-label="Attach existing evidence" value="" onChange={(e) => e.target.value && onChange([...ids, e.target.value])} style={{ width: 'auto', maxWidth: 220 }}><option value="">Attach existing…</option>{rest.map((e) => <option key={e.id} value={e.id}>{e.summary.slice(0, 60)}</option>)}</select>}
        <AddEvidence onAdded={(id) => onChange([...ids, id])} />
      </div>
    </Section>
  );
}

function History({ id }: { id: string }) {
  const { model } = useWs();
  const ds = model.decisions.filter((d) => d.subject.id === id);
  if (!ds.length) return null;
  return (
    <Section title="Decision history" count={ds.length}>
      {ds.slice().reverse().map((d) => <p key={d.id} style={{ margin: '0 0 6px', fontSize: 12 }}><strong>{d.actor}</strong> {d.action} <span className="hint">{fmtTime(d.at)}</span>{d.detail ? <span className="hint"> · {d.detail}</span> : null}{d.rationale ? <><br />“{d.rationale}”</> : null}</p>)}
    </Section>
  );
}

function Provenance({ p }: { p: { origin: string; actor?: string | undefined; at?: string | undefined } }) {
  return <p className="hint" style={{ margin: '4px 0 0' }}><OriginMark origin={p.origin} actor={p.actor} /> {fmtTime(p.at)}</p>;
}

function Related({ model, type, id }: { model: Model; type: Ref['type']; id: string }) {
  const { open } = useWs();
  const r = relatedTo(model, { type, id });
  const none = !r.threats.length && !r.assumptions.length && !r.mitigations.length;
  const link = (s: Sel, text: string, extra?: ReactNode) => <li key={s.id}><button className="ghost small" style={{ padding: 0, textAlign: 'left' }} onClick={() => open(s)}>{text}</button> {extra}</li>;
  return (
    <Section title="Related security reasoning">
      {none && <p className="hint">No threats, assumptions or mitigations reference this yet.</p>}
      {r.threats.length > 0 && <><p className="hint" style={{ margin: 0 }}>Threats</p><ul className="kvlist">{r.threats.map((t) => link({ type: 'threat', id: t.id }, t.title, <>{model.reviewItems.some((x) => x.status === 'open' && x.target.id === t.id) && <ReviewMark />}</>))}</ul></>}
      {r.assumptions.length > 0 && <><p className="hint" style={{ margin: '6px 0 0' }}>Assumptions</p><ul className="kvlist">{r.assumptions.map((a) => link({ type: 'assumption', id: a.id }, a.text.slice(0, 90), <>{model.reviewItems.some((x) => x.status === 'open' && x.target.id === a.id) && <ReviewMark />}</>))}</ul></>}
      {r.mitigations.length > 0 && <><p className="hint" style={{ margin: '6px 0 0' }}>Mitigations</p><ul className="kvlist">{r.mitigations.map((m) => link({ type: 'mitigation', id: m.id }, m.title, <MitigationMark status={m.status} staleVerification={effectiveMitigationStatus(model, m).includes('stale')} />))}</ul></>}
    </Section>
  );
}

const DeleteBtn = ({ onDelete, what }: { onDelete: () => void; what: string }) => {
  const { ask } = useDialogs();
  return <button className="danger small" style={{ marginTop: 18 }} onClick={async () => { if ((await ask({ title: `Delete this ${what}?`, noInput: true, confirmLabel: 'Delete', danger: true, body: <p>You can undo this with Ctrl+Z.</p> })) !== null) onDelete(); }}>Delete {what}</button>;
};

/* ---------- per-type inspectors ---------- */
function ElementInspector({ id }: { id: string }) {
  const { model, open } = useWs();
  const { upd, del } = useEdit();
  const e = model.elements.find((x) => x.id === id);
  if (!e) return <Gone />;
  const pinned = e.properties['pin.exposure'] === 'human';
  const setExposure = (v: 'unknown' | 'internal' | 'external') => upd('element', id, { exposure: v, ...(e.sourceKey ? { properties: { ...e.properties, 'pin.exposure': 'human' } } : {}) }, 'Set exposure');
  return (
    <div>
      <h2>{KIND_LABEL[e.kind]}: {e.name}</h2>
      <Provenance p={e.provenance} />
      <ReviewHere type="element" id={id} />
      <div style={{ marginTop: 12 }}>
        <TextField label="Name" required value={e.name} onCommit={(v) => v.trim() && upd('element', id, { name: v.trim() })} />
        <SelectField label="Kind" value={e.kind} onChange={(v) => upd('element', id, { kind: v })} options={(Object.keys(KIND_LABEL) as Array<keyof typeof KIND_LABEL>).map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
        <SelectField label="Reachability" value={e.exposure} onChange={setExposure} options={[{ value: 'unknown', label: 'Not assessed' }, { value: 'internal', label: 'Internal only' }, { value: 'external', label: 'Externally reachable' }]}
          hint={e.sourceKey ? (pinned ? 'You set this by hand. Source scans will not overwrite it.' : 'Derived from source. Changing it pins your value against future scans.') : undefined} />
        {e.properties['exposure.reason'] && <p className="hint">Source says: {e.properties['exposure.reason']}</p>}
        <TextField label="Technology" value={e.technology} onCommit={(v) => upd('element', id, { technology: v })} />
        <TextField label="Description" multiline value={e.description} onCommit={(v) => upd('element', id, { description: v })} />
        <SelectField label="How well established is this?" value={e.basis} onChange={(v) => upd('element', id, { basis: v })} options={[{ value: 'observed', label: 'Observed' }, { value: 'inferred', label: 'Inferred' }, { value: 'hypothesis', label: 'Hypothesis' }]} />
        <TextField label="Tags" value={e.tags.join(', ')} onCommit={(v) => upd('element', id, { tags: v.split(',').map((s) => s.trim()).filter(Boolean) })} hint="Comma separated" />
      </div>
      <Section title="Trust boundaries">
        {model.boundaries.length === 0 && <p className="hint">No boundaries defined. Add them in the table view.</p>}
        {model.boundaries.map((b) => (
          <label key={b.id} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
            <input type="checkbox" checked={b.memberIds.includes(id)} onChange={(ev) => upd('boundary', b.id, { memberIds: ev.target.checked ? [...b.memberIds, id] : b.memberIds.filter((m) => m !== id) }, 'Change boundary membership')} />
            {b.name} <span className="hint">({b.trust})</span>
          </label>
        ))}
      </Section>
      <Section title="Data flows">
        {model.flows.filter((f) => f.from === id || f.to === id).map((f) => <p key={f.id} style={{ margin: '0 0 4px' }}><button className="ghost small" style={{ padding: 0 }} onClick={() => open({ type: 'flow', id: f.id })}>{labelOf(model, { type: 'flow', id: f.id })}</button></p>)}
        {!model.flows.some((f) => f.from === id || f.to === id) && <p className="hint">None. Drag from this component's handle on the canvas, or use the table view.</p>}
      </Section>
      <Related model={model} type="element" id={id} />
      <EvidenceList model={model} ids={e.evidenceIds} onChange={(ids) => upd('element', id, { evidenceIds: ids })} />
      {Object.keys(e.properties).length > 0 && <Section title="Properties"><dl className="kv">{Object.entries(e.properties).map(([k, v]) => <><dt key={`k${k}`} className="mono">{k}</dt><dd key={`v${k}`}>{v}</dd></>)}</dl></Section>}
      <History id={id} />
      <DeleteBtn what="component" onDelete={() => del('element', id)} />
    </div>
  );
}

function FlowInspector({ id }: { id: string }) {
  const { model } = useWs();
  const { upd, del } = useEdit();
  const f = model.flows.find((x) => x.id === id);
  if (!f) return <Gone />;
  const els = model.elements.map((e) => ({ value: e.id, label: e.name }));
  const tri = [{ value: 'unknown' as const, label: 'Unknown' }, { value: 'yes' as const, label: 'Yes' }, { value: 'no' as const, label: 'No' }];
  const crossing = model.boundaries.filter((b) => b.memberIds.includes(f.from) !== b.memberIds.includes(f.to));
  return (
    <div>
      <h2>Data flow</h2>
      <p style={{ margin: 0 }}>{labelOf(model, { type: 'flow', id })}</p>
      <Provenance p={f.provenance} />
      <div style={{ margin: '6px 0' }}><BasisMark basis={f.basis} /></div>
      {crossing.length > 0 && <div className="callout info">Crosses: {crossing.map((b) => b.name).join(', ')}</div>}
      <ReviewHere type="flow" id={id} />
      <div style={{ marginTop: 12 }}>
        <SelectField label="From" value={f.from} options={els} onChange={(v) => upd('flow', id, { from: v })} />
        <SelectField label="To" value={f.to} options={els} onChange={(v) => upd('flow', id, { to: v })} />
        <TextField label="Label" value={f.label} onCommit={(v) => upd('flow', id, { label: v })} />
        <TextField label="Protocol" value={f.protocol} onCommit={(v) => upd('flow', id, { protocol: v })} />
        <SelectField label="Caller authenticated?" value={f.authenticated} options={tri} onChange={(v) => upd('flow', id, { authenticated: v })} />
        <SelectField label="Encrypted in transit?" value={f.encrypted} options={tri} onChange={(v) => upd('flow', id, { encrypted: v })} />
        <RefPicker model={model} label="Assets carried" types={['asset']} value={f.assetIds.map((a) => ({ type: 'asset' as const, id: a }))} onChange={(v) => upd('flow', id, { assetIds: v.map((r) => r.id) })} />
        <TextField label="Description" multiline value={f.description} onCommit={(v) => upd('flow', id, { description: v })} />
        <SelectField label="How well established is this?" value={f.basis} onChange={(v) => upd('flow', id, { basis: v })} options={[{ value: 'observed', label: 'Observed' }, { value: 'inferred', label: 'Inferred' }, { value: 'hypothesis', label: 'Hypothesis' }]} />
      </div>
      <Related model={model} type="flow" id={id} />
      <EvidenceList model={model} ids={f.evidenceIds} onChange={(ids) => upd('flow', id, { evidenceIds: ids })} />
      <History id={id} />
      <DeleteBtn what="flow" onDelete={() => del('flow', id)} />
    </div>
  );
}

function BoundaryInspector({ id }: { id: string }) {
  const { model } = useWs();
  const { upd, del } = useEdit();
  const b = model.boundaries.find((x) => x.id === id);
  if (!b) return <Gone />;
  return (
    <div>
      <h2>Trust boundary: {b.name}</h2>
      <Provenance p={b.provenance} />
      <ReviewHere type="boundary" id={id} />
      <div style={{ marginTop: 12 }}>
        <TextField label="Name" required value={b.name} onCommit={(v) => v.trim() && upd('boundary', id, { name: v.trim() })} />
        <SelectField label="Kind" value={b.kind} onChange={(v) => upd('boundary', id, { kind: v })} options={['network', 'process', 'account', 'organisation', 'physical', 'other'].map((k) => ({ value: k as 'network', label: k }))} />
        <SelectField label="Trust inside" value={b.trust} onChange={(v) => upd('boundary', id, { trust: v })} options={[{ value: 'unknown', label: 'Not assessed' }, { value: 'untrusted', label: 'Untrusted' }, { value: 'semi-trusted', label: 'Semi-trusted' }, { value: 'trusted', label: 'Trusted' }]} />
        <TextField label="Description" multiline value={b.description} onCommit={(v) => upd('boundary', id, { description: v })} />
      </div>
      <Section title="Members">
        {model.elements.length === 0 && <p className="hint">No components yet.</p>}
        {model.elements.map((e) => (
          <label key={e.id} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
            <input type="checkbox" checked={b.memberIds.includes(e.id)} onChange={(ev) => upd('boundary', id, { memberIds: ev.target.checked ? [...b.memberIds, e.id] : b.memberIds.filter((m) => m !== e.id) }, 'Change boundary membership')} />{e.name}
          </label>))}
      </Section>
      <Related model={model} type="boundary" id={id} />
      <EvidenceList model={model} ids={b.evidenceIds} onChange={(ids) => upd('boundary', id, { evidenceIds: ids })} />
      <History id={id} />
      <DeleteBtn what="boundary" onDelete={() => del('boundary', id)} />
    </div>
  );
}

function AssetInspector({ id }: { id: string }) {
  const { model } = useWs();
  const { upd, del } = useEdit();
  const a = model.assets.find((x) => x.id === id);
  if (!a) return <Gone />;
  return (
    <div>
      <h2>Asset: {a.name}</h2>
      <Provenance p={a.provenance} />
      <div style={{ marginTop: 12 }}>
        <TextField label="Name" required value={a.name} onCommit={(v) => v.trim() && upd('asset', id, { name: v.trim() })} />
        <SelectField label="Classification" value={a.classification} onChange={(v) => upd('asset', id, { classification: v })} options={['unknown', 'public', 'internal', 'confidential', 'restricted'].map((k) => ({ value: k as 'unknown', label: k === 'unknown' ? 'Not assessed' : k }))} />
        <TextField label="Description" multiline value={a.description} onCommit={(v) => upd('asset', id, { description: v })} />
      </div>
      <Section title="Stored in">
        {model.elements.map((e) => <label key={e.id} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}><input type="checkbox" checked={a.storedIn.includes(e.id)} onChange={(ev) => upd('asset', id, { storedIn: ev.target.checked ? [...a.storedIn, e.id] : a.storedIn.filter((m) => m !== e.id) })} />{e.name}</label>)}
      </Section>
      <Related model={model} type="asset" id={id} />
      <History id={id} />
      <DeleteBtn what="asset" onDelete={() => del('asset', id)} />
    </div>
  );
}

const STRIDE_NAMES: Record<string, string> = { S: 'Spoofing', T: 'Tampering', R: 'Repudiation', I: 'Information disclosure', D: 'Denial of service', E: 'Elevation of privilege' };
const LEVELS = [{ value: 'unknown' as const, label: 'Not assessed' }, { value: 'low' as const, label: 'Low' }, { value: 'medium' as const, label: 'Medium' }, { value: 'high' as const, label: 'High' }];

function ThreatInspector({ id }: { id: string }) {
  const { model, session, actor, open, select } = useWs();
  const { upd, add, del } = useEdit();
  const { ask, toast } = useDialogs();
  const t = model.threats.find((x) => x.id === id);
  if (!t) return <Gone />;
  const mits = model.mitigations.filter((m) => m.threatIds.includes(id));
  const unlinked = model.mitigations.filter((m) => !m.threatIds.includes(id));
  const setStatus = async (status: typeof t.status) => {
    let why = '';
    if (status === 'accepted-risk' || status === 'not-applicable') {
      const r = await ask({ title: status === 'accepted-risk' ? 'Accept this risk' : 'Mark not applicable', label: status === 'accepted-risk' ? 'Who accepts it, on what grounds, and until when?' : 'Why does this not apply?', required: true, confirmLabel: 'Record decision' });
      if (r === null) return;
      why = r;
    }
    session.mutate('Set threat status', (m) => setThreatStatus(m, id, status, actor, why), { immediate: true });
  };
  return (
    <div>
      <h2>Threat</h2>
      <p style={{ margin: '4px 0 6px' }}>{threatStatement(model, t)}</p>
      <div className="row wrap"><BasisMark basis={t.basis} /><OriginMark origin={t.provenance.origin} actor={t.provenance.actor} /><Mark kind="plain">Evidence {STRENGTH_GLYPH[t.evidenceStrength]}</Mark></div>
      <p className="hint" style={{ marginTop: 6 }}>A threat is a hypothesis about what could go wrong, not a confirmed vulnerability.</p>
      <ReviewHere type="threat" id={id} />
      <div style={{ marginTop: 12 }}>
        <TextField label="Title" required value={t.title} onCommit={(v) => v.trim() && upd('threat', id, { title: v.trim() })} />
        <TextField label="Who or what (actor or source)" value={t.source} onCommit={(v) => upd('threat', id, { source: v })} />
        <ListField label="Preconditions (what must be true)" value={t.preconditions} onCommit={(v) => upd('threat', id, { preconditions: v })} />
        <TextField label="Action (what they could do)" value={t.action} onCommit={(v) => upd('threat', id, { action: v })} />
        <TextField label="Consequence" value={t.consequence} onCommit={(v) => upd('threat', id, { consequence: v })} />
        <ListField label="Security goals affected" value={t.goals} onCommit={(v) => upd('threat', id, { goals: v })} hint="One per line, e.g. confidentiality" />
        <fieldset style={{ border: 'none', padding: 0, margin: '0 0 10px' }}><legend className="lbl" style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink-2)' }}>STRIDE</legend>
          <div className="row wrap">{Object.entries(STRIDE_NAMES).map(([k, n]) => <label key={k} style={{ display: 'flex', gap: 4, alignItems: 'center' }}><input type="checkbox" checked={t.stride.includes(k as 'S')} onChange={(ev) => upd('threat', id, { stride: ev.target.checked ? [...t.stride, k] : t.stride.filter((s) => s !== k) })} /> {k}<span className="sr">{n}</span></label>)}</div>
        </fieldset>
        <RefPicker model={model} label="Affects" value={t.targets} onChange={(v) => upd('threat', id, { targets: v })} onOpen={(r) => open({ type: r.type, id: r.id })} />
      </div>
      <Section title="Severity judgement (reasoned, not scored)">
        <SelectField label="Likelihood" value={t.likelihood.level} options={LEVELS} onChange={(v) => upd('threat', id, { likelihood: { ...t.likelihood, level: v } })} />
        <TextField label="Why this likelihood" multiline value={t.likelihood.rationale} onCommit={(v) => upd('threat', id, { likelihood: { ...t.likelihood, rationale: v } })} />
        <SelectField label="Impact" value={t.impact.level} options={LEVELS} onChange={(v) => upd('threat', id, { impact: { ...t.impact, level: v } })} />
        <TextField label="Why this impact" multiline value={t.impact.rationale} onCommit={(v) => upd('threat', id, { impact: { ...t.impact, rationale: v } })} />
      </Section>
      <Section title="How well supported is it? (separate from severity)">
        <SelectField label="Evidence strength" value={t.evidenceStrength} onChange={(v) => upd('threat', id, { evidenceStrength: v })} options={[{ value: 'none', label: 'None' }, { value: 'weak', label: 'Weak' }, { value: 'moderate', label: 'Moderate' }, { value: 'strong', label: 'Strong' }]} />
        <TextField label="Basis of the evidence rating" multiline value={t.evidenceRationale} onCommit={(v) => upd('threat', id, { evidenceRationale: v })} />
        <SelectField label="Claim type" value={t.basis} onChange={(v) => upd('threat', id, { basis: v })} options={[{ value: 'observed', label: 'Observed' }, { value: 'inferred', label: 'Inferred' }, { value: 'hypothesis', label: 'Hypothesis' }]} />
      </Section>
      <Section title="Decision">
        <SelectField label="Status" value={t.status} onChange={setStatus} options={[{ value: 'open', label: 'Open' }, { value: 'mitigated', label: 'Mitigated' }, { value: 'accepted-risk', label: 'Risk accepted' }, { value: 'not-applicable', label: 'Not applicable' }]} hint="Accepting a risk or marking it not applicable asks for a reason and records you as the decider." />
      </Section>
      <Section title="Mitigations" count={mits.length}>
        {mits.map((m) => <p key={m.id} style={{ margin: '0 0 6px' }}><button className="ghost small" style={{ padding: 0 }} onClick={() => open({ type: 'mitigation', id: m.id })}>{m.title}</button> <MitigationMark status={m.status} staleVerification={effectiveMitigationStatus(model, m).includes('stale')} /></p>)}
        <div className="row wrap">
          {unlinked.length > 0 && <select aria-label="Link existing mitigation" value="" onChange={(e) => { const mid = e.target.value; if (mid) session.mutate('Link mitigation', (m) => updateEntity(m, 'mitigation', mid, { threatIds: [...(m.mitigations.find((x) => x.id === mid)?.threatIds ?? []), id] }), { immediate: true }); }} style={{ width: 'auto', maxWidth: 220 }}><option value="">Link existing…</option>{unlinked.map((m) => <option key={m.id} value={m.id}>{m.title.slice(0, 60)}</option>)}</select>}
          <button className="small" onClick={async () => { const title = await ask({ title: 'New mitigation for this threat', label: 'What would reduce this threat?', required: true, confirmLabel: 'Add as planned' }); if (title) { const mid = add('mitigation', { title: title.slice(0, 300), threatIds: [id], status: 'planned' }, 'Add mitigation'); if (mid) { select({ type: 'mitigation', id: mid }); toast('Added as planned. Implementation status is set separately.'); } } }}>＋ New mitigation…</button>
        </div>
      </Section>
      <EvidenceList model={model} ids={t.evidenceIds} onChange={(ids) => upd('threat', id, { evidenceIds: ids })} />
      <Section title="Notes"><TextField label="Notes" multiline rows={4} value={t.notes} onCommit={(v) => upd('threat', id, { notes: v })} /></Section>
      <Provenance p={t.provenance} />
      <History id={id} />
      <DeleteBtn what="threat" onDelete={() => del('threat', id)} />
    </div>
  );
}

function VerifyDialog({ model, mitigationId, onDone, onCancel }: { model: Model; mitigationId: string; onDone: (a: { evidenceIds: string[]; newSummary: string; newKind: 'test-result' | 'document' | 'human-note'; rationale: string }) => void; onCancel: () => void }) {
  const m = model.mitigations.find((x) => x.id === mitigationId)!;
  const [sel, setSel] = useState<string[]>(m.verification.evidenceIds);
  const [summary, setSummary] = useState('');
  const [kind, setKind] = useState<'test-result' | 'document' | 'human-note'>('test-result');
  const [rationale, setRationale] = useState('');
  const ok = (sel.length > 0 || summary.trim().length > 0) && rationale.trim().length > 0;
  return (
    <Modal title="Record verification" onClose={onCancel}>
      <p>“Verified” means someone checked that this control works, and the check can be found. Choose existing evidence or describe the check.</p>
      {model.evidence.length > 0 && (
        <fieldset style={{ border: '1px solid var(--line)', padding: 8, marginBottom: 10 }}><legend className="lbl">Existing evidence</legend>
          {model.evidence.map((e) => <label key={e.id} style={{ display: 'flex', gap: 8, marginBottom: 4 }}><input type="checkbox" checked={sel.includes(e.id)} onChange={(ev) => setSel(ev.target.checked ? [...sel, e.id] : sel.filter((x) => x !== e.id))} /><span>{e.stale ? '▲ stale: ' : ''}{e.summary}</span></label>)}
        </fieldset>)}
      <SelectField label="New evidence kind" value={kind} onChange={setKind} options={[{ value: 'test-result', label: 'Test or check result' }, { value: 'document', label: 'Document or ticket' }, { value: 'human-note', label: 'Note from a person' }]} />
      <TextField live label="New evidence: what was checked, how, and where is the record?" multiline value={summary} onCommit={setSummary} />
      <TextField live label="Rationale" required multiline value={rationale} onCommit={setRationale} />
      <div className="actions"><button onClick={onCancel}>Cancel</button><button className="primary" disabled={!ok} onClick={() => onDone({ evidenceIds: sel, newSummary: summary.trim(), newKind: kind, rationale })}>Record as verified</button></div>
    </Modal>
  );
}

function MitigationInspector({ id }: { id: string }) {
  const { model, session, actor, open } = useWs();
  const { upd, del } = useEdit();
  const { ask, toast } = useDialogs();
  const [verifying, setVerifying] = useState(false);
  const m = model.mitigations.find((x) => x.id === id);
  if (!m) return <Gone />;
  const eff = effectiveMitigationStatus(model, m);
  const change = async (status: MitigationStatus) => {
    if (status === m.status) return;
    if (status === 'verified') { setVerifying(true); return; }
    let rationale = '';
    if (status === 'implemented') {
      const r = await ask({ title: 'Record as implemented', label: 'Where is it implemented, and how do you know?', required: true, confirmLabel: 'I confirm', body: <p>This records <strong>{actor}</strong> as the person who confirmed it. Implemented is not the same as verified.</p> });
      if (r === null) return; rationale = r;
    } else if (status === 'wont-do') {
      const r = await ask({ title: "Record as won't do", label: 'Why not?', required: true, confirmLabel: 'Record decision' });
      if (r === null) return; rationale = r;
    }
    session.mutate('Set mitigation status', (mm) => setMitigationStatus(mm, id, status, { actor }, { rationale }), { immediate: true });
  };
  const finishVerify = (a: { evidenceIds: string[]; newSummary: string; newKind: 'test-result' | 'document' | 'human-note'; rationale: string }) => {
    setVerifying(false);
    session.mutate('Verify mitigation', (mm) => {
      let next = mm; const ids = [...a.evidenceIds];
      if (a.newSummary) { const r = addEntity(next, 'evidence', { kind: a.newKind, summary: a.newSummary }, actor); next = r.model; ids.push(r.id); }
      return setMitigationStatus(next, id, 'verified', { actor }, { rationale: a.rationale, verificationEvidenceIds: ids });
    }, { immediate: true });
    toast('Recorded as verified with evidence, under your name.');
  };
  return (
    <div>
      <h2>Mitigation</h2>
      <p style={{ margin: '4px 0' }}>{m.title}</p>
      <div className="row wrap"><MitigationMark status={m.status} staleVerification={eff.includes('stale')} /><OriginMark origin={m.provenance.origin} actor={m.provenance.actor} /></div>
      {m.statusSetBy && <p className="hint">Status set by {m.statusSetBy.actor} ({m.statusSetBy.actorKind}) {fmtTime(m.statusSetBy.at)}</p>}
      {m.status === 'proposed' && <div className="callout">Proposed only. It becomes “implemented” only when a person records it.</div>}
      {eff.includes('stale') && <div className="callout warn">The evidence behind “verified” is stale. Re-verify before relying on it.</div>}
      <ReviewHere type="mitigation" id={id} />
      <div style={{ marginTop: 12 }}>
        <TextField label="Title" required value={m.title} onCommit={(v) => v.trim() && upd('mitigation', id, { title: v.trim() })} />
        <TextField label="Description" multiline value={m.description} onCommit={(v) => upd('mitigation', id, { description: v })} />
        <SelectField label="Actual implementation status" value={m.status} onChange={change} options={(['proposed', 'planned', 'in-progress', 'implemented', 'verified', 'wont-do'] as MitigationStatus[]).map((s) => ({ value: s, label: { proposed: 'Proposed', planned: 'Planned', 'in-progress': 'In progress', implemented: 'Implemented (not verified)', verified: 'Verified (with evidence)', 'wont-do': "Won't do" }[s] }))} hint="Implemented and verified are attested under your name; verified needs evidence." />
        <RefPicker model={model} label="Mitigates threats" types={['threat']} value={m.threatIds.map((t) => ({ type: 'threat' as const, id: t }))} onChange={(v) => upd('mitigation', id, { threatIds: v.map((r) => r.id) })} onOpen={(r) => open({ type: 'threat', id: r.id })} />
        <RefPicker model={model} label="Relies on assumptions" types={['assumption' as RefType]} value={m.assumptionIds.map((t) => ({ type: 'assumption' as const, id: t }))} onChange={(v) => upd('mitigation', id, { assumptionIds: v.map((r) => r.id) })} onOpen={(r) => open({ type: 'assumption', id: r.id })} />
        <ListField label="Verification plan" value={m.verification.plan} onCommit={(v) => upd('mitigation', id, { verification: { ...m.verification, plan: v } })} hint="How could someone check this works? One step per line." />
      </div>
      <EvidenceList model={model} label="Implementation evidence" ids={m.evidenceIds} onChange={(ids) => upd('mitigation', id, { evidenceIds: ids })} />
      <EvidenceList model={model} label="Verification evidence" ids={m.verification.evidenceIds} onChange={(ids) => session.mutate('Edit verification evidence', (mm) => { const r = updateEntity(mm, 'mitigation', id, { verification: { ...m.verification, evidenceIds: ids } }); return r; })} />
      <Provenance p={m.provenance} />
      <History id={id} />
      <DeleteBtn what="mitigation" onDelete={() => del('mitigation', id)} />
      {verifying && <VerifyDialog model={model} mitigationId={id} onCancel={() => setVerifying(false)} onDone={finishVerify} />}
    </div>
  );
}

function AssumptionInspector({ id }: { id: string }) {
  const { model, open } = useWs();
  const { upd, del } = useEdit();
  const a = model.assumptions.find((x) => x.id === id);
  if (!a) return <Gone />;
  return (
    <div>
      <h2>{a.kind === 'question' ? 'Open question' : 'Assumption'}</h2>
      <div className="row wrap"><BasisMark basis={a.basis} /><OriginMark origin={a.provenance.origin} actor={a.provenance.actor} /></div>
      <ReviewHere type="assumption" id={id} />
      <div style={{ marginTop: 12 }}>
        <SelectField label="Type" value={a.kind} onChange={(v) => upd('assumption', id, { kind: v, status: v === 'question' ? 'open' : a.status === 'answered' ? 'open' : a.status })} options={[{ value: 'assumption', label: 'Assumption' }, { value: 'question', label: 'Unresolved question' }]} />
        <TextField label="Statement" required multiline value={a.text} onCommit={(v) => v.trim() && upd('assumption', id, { text: v.trim() })} />
        <SelectField label="Status" value={a.status} onChange={(v) => upd('assumption', id, { status: v })} options={a.kind === 'question' ? [{ value: 'open', label: 'Open' }, { value: 'answered', label: 'Answered' }] : [{ value: 'open', label: 'Not yet validated' }, { value: 'validated', label: 'Validated' }, { value: 'invalidated', label: 'Invalidated' }]} />
        {a.kind === 'question' && <TextField label="Answer" multiline value={a.answer} onCommit={(v) => upd('assumption', id, { answer: v })} />}
        <TextField label="Why we believe this, or how it was checked" multiline value={a.rationale} onCommit={(v) => upd('assumption', id, { rationale: v })} />
        <RefPicker model={model} label="Relates to" types={['element', 'flow', 'boundary', 'asset', 'threat', 'mitigation']} value={a.relatesTo} onChange={(v) => upd('assumption', id, { relatesTo: v })} onOpen={(r) => open({ type: r.type, id: r.id })} />
        <SelectField label="How well established is this?" value={a.basis} onChange={(v) => upd('assumption', id, { basis: v })} options={[{ value: 'observed', label: 'Observed' }, { value: 'inferred', label: 'Inferred' }, { value: 'hypothesis', label: 'Hypothesis' }]} />
      </div>
      <EvidenceList model={model} ids={a.evidenceIds} onChange={(ids) => upd('assumption', id, { evidenceIds: ids })} />
      <Provenance p={a.provenance} />
      <History id={id} />
      <DeleteBtn what="assumption" onDelete={() => del('assumption', id)} />
    </div>
  );
}

function EvidenceInspector({ id }: { id: string }) {
  const { model, session, actor, open } = useWs();
  const { upd, del } = useEdit();
  const { ask } = useDialogs();
  const e = model.evidence.find((x) => x.id === id) as Evidence | undefined;
  if (!e) return <Gone />;
  const src = model.sources.find((s) => s.id === e.sourceId);
  const citedBy: Array<{ type: Sel['type']; id: string; label: string }> = [
    ...model.elements.filter((x) => x.evidenceIds.includes(id)).map((x) => ({ type: 'element' as const, id: x.id, label: x.name })),
    ...model.flows.filter((x) => x.evidenceIds.includes(id)).map((x) => ({ type: 'flow' as const, id: x.id, label: labelOf(model, { type: 'flow', id: x.id }) })),
    ...model.threats.filter((x) => x.evidenceIds.includes(id)).map((x) => ({ type: 'threat' as const, id: x.id, label: x.title })),
    ...model.assumptions.filter((x) => x.evidenceIds.includes(id)).map((x) => ({ type: 'assumption' as const, id: x.id, label: x.text.slice(0, 80) })),
    ...model.mitigations.filter((x) => x.evidenceIds.includes(id) || x.verification.evidenceIds.includes(id)).map((x) => ({ type: 'mitigation' as const, id: x.id, label: x.title })),
  ];
  const reaffirm = async () => {
    const r = await ask({ title: 'Clear the stale flag', label: 'What did you re-check?', required: true, confirmLabel: 'Clear flag', body: <p>Use this when you have confirmed the claim still holds against the current source.</p> });
    if (r === null) return;
    session.mutate('Re-affirm evidence', (m) => { const u = updateEntity(m, 'evidence', id, { stale: false, staleReason: undefined }); return recordDecision(u, { subject: { type: 'evidence', id }, action: 'resolve', rationale: r, actor, detail: 'stale flag cleared' }).model; }, { immediate: true });
  };
  return (
    <div>
      <h2>Evidence</h2>
      <div className="row wrap">{e.stale ? <StaleMark reason={e.staleReason} /> : <Mark kind="ok">✓ Current</Mark>}<OriginMark origin={e.provenance.origin} actor={e.provenance.actor} /><Mark>{e.kind}</Mark></div>
      {e.stale && <div className="callout warn" style={{ marginTop: 8 }}>{e.staleReason}<div style={{ marginTop: 6 }}><button className="small" onClick={reaffirm}>I re-checked this…</button></div></div>}
      <div style={{ marginTop: 12 }}>
        <TextField label="Summary" required multiline value={e.summary} onCommit={(v) => v.trim() && upd('evidence', id, { summary: v.trim() })} />
        {e.path !== undefined && <dl className="kv"><dt>File</dt><dd className="mono">{e.path}{e.lineStart ? `:${e.lineStart}${e.lineEnd && e.lineEnd !== e.lineStart ? `-${e.lineEnd}` : ''}` : ''}</dd><dt>Revision</dt><dd className="mono">{e.revision ?? 'unknown'}</dd><dt>Source</dt><dd>{src ? src.label : 'none'}</dd></dl>}
        {e.quote && <blockquote style={{ margin: '8px 0', padding: '6px 10px', borderLeft: '3px solid var(--line-strong)', background: 'var(--surface-2)', fontFamily: 'var(--mono)', fontSize: 12, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{e.quote}</blockquote>}
      </div>
      <Section title="Cited by" count={citedBy.length}>
        {citedBy.length === 0 && <p className="hint">Nothing cites this yet.</p>}
        <ul className="kvlist">{citedBy.map((c) => <li key={`${c.type}${c.id}`}><button className="ghost small" style={{ padding: 0 }} onClick={() => open({ type: c.type, id: c.id })}>{c.type}: {c.label}</button></li>)}</ul>
      </Section>
      <Provenance p={e.provenance} />
      <History id={id} />
      <DeleteBtn what="evidence" onDelete={() => del('evidence', id)} />
    </div>
  );
}

function ReviewInspector({ id }: { id: string }) {
  const { model, open } = useWs();
  const r = model.reviewItems.find((x) => x.id === id);
  if (!r) return <Gone />;
  return (
    <div>
      <h2>Review item</h2>
      <div className="row wrap"><Mark kind={r.status === 'open' ? 'review' : 'plain'}>{r.status === 'open' ? '◆ Open' : r.status}</Mark><Mark>{r.deterministic ? 'Deterministic' : 'Interpretation'}</Mark></div>
      <p style={{ marginTop: 8 }}>{r.reason}</p>
      <Section title="Trace from the change"><ol className="kvlist">{r.trace.map((t, i) => <li key={i}>{t}</li>)}</ol></Section>
      <p><button onClick={() => open({ type: r.target.type, id: r.target.id })}>Open {r.target.type}: {labelOf(model, r.target)}</button></p>
      <ReviewHere type={r.target.type} id={r.target.id} />
      <History id={id} />
    </div>
  );
}

const Gone = () => <p className="hint">This item no longer exists.</p>;

function Overview() {
  const { model, go } = useWs();
  const open = model.reviewItems.filter((r) => r.status === 'open').length;
  const pending = model.proposals.filter((p) => p.status === 'pending').length;
  const stale = model.evidence.filter((e) => e.stale).length;
  return (
    <div>
      <h2>Nothing selected</h2>
      <p className="hint">Select a component, flow, threat or any list row to inspect and edit it here. Selecting a threat highlights what it affects on the diagram.</p>
      <dl className="kv" style={{ marginTop: 12 }}>
        <dt>Needs review</dt><dd>{open > 0 ? <button className="small" onClick={() => go('review')}>◆ {open} open</button> : 'Nothing open'}</dd>
        <dt>Proposals</dt><dd>{pending > 0 ? <button className="small" onClick={() => go('review')}>{pending} awaiting your decision</button> : 'None pending'}</dd>
        <dt>Stale evidence</dt><dd>{stale || 'None'}</dd>
        <dt>Threats</dt><dd>{model.threats.length} ({model.threats.filter((t) => t.status === 'open').length} open)</dd>
        <dt>Mitigations</dt><dd>{model.mitigations.filter((m) => m.status === 'verified').length} verified, {model.mitigations.filter((m) => m.status === 'implemented').length} implemented, {model.mitigations.filter((m) => m.status === 'proposed' || m.status === 'planned' || m.status === 'in-progress').length} not yet</dd>
      </dl>
      <h3 style={{ margin: '18px 0 6px' }}>Keyboard</h3>
      <ul className="kvlist hint"><li><code>Ctrl/⌘ Z</code> undo, <code>Ctrl/⌘ Shift Z</code> redo</li><li><code>Alt 1…8</code> switch section</li><li><code>?</code> all shortcuts</li><li>Canvas nodes are focusable; the Table view offers every canvas operation.</li></ul>
    </div>
  );
}

export function Inspector() {
  const { selection } = useWs();
  if (!selection) return <Overview />;
  switch (selection.type) {
    case 'element': return <ElementInspector id={selection.id} />;
    case 'flow': return <FlowInspector id={selection.id} />;
    case 'boundary': return <BoundaryInspector id={selection.id} />;
    case 'asset': return <AssetInspector id={selection.id} />;
    case 'threat': return <ThreatInspector id={selection.id} />;
    case 'mitigation': return <MitigationInspector id={selection.id} />;
    case 'assumption': return <AssumptionInspector id={selection.id} />;
    case 'evidence': return <EvidenceInspector id={selection.id} />;
    case 'review': return <ReviewInspector id={selection.id} />;
    default: return <Overview />;
  }
}
void TAB_OF; void LEVEL_TEXT;
