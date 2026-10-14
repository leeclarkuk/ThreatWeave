/**
 * Change-aware review. Given two model revisions and their diff, raise review items for
 * entities connected to the change through EXPLICIT relationships only. This is a
 * traceable heuristic, not an attack-path analysis, and makes no claim of full coverage.
 */
import type { Model, Ref, ReviewItem } from './model.js';
import { labelOf } from './ops.js';
import type { Change } from './diff.js';
import { nowIso, shortHash } from './util.js';

const item = (code: string, target: Ref, change: Change, reason: string, trace: string[]): ReviewItem => ({
  id: `rvw_${shortHash([code, target.type, target.id, change.id].join('|'))}`,
  target, code, reason, trace, change: change.summary.slice(0, 500), deterministic: true, status: 'open', raisedAt: nowIso(),
});

function boundariesOf(m: Model, elId: string) {
  return m.boundaries.filter((b) => b.memberIds.includes(elId));
}

/** Everything explicitly connected to an element: its flows, containing boundaries, and reasoning that references them. */
function neighbourhood(m: Model, elId: string) {
  const flows = m.flows.filter((f) => f.from === elId || f.to === elId);
  const flowIds = new Set(flows.map((f) => f.id));
  const boundaries = boundariesOf(m, elId);
  const hits = (refs: Ref[]) => refs.filter((r) =>
    (r.type === 'element' && r.id === elId) || (r.type === 'flow' && flowIds.has(r.id)) || (r.type === 'boundary' && boundaries.some((b) => b.id === r.id)));
  const threats = m.threats.map((t) => ({ t, via: hits(t.targets) })).filter((x) => x.via.length);
  const assumptions = m.assumptions.map((a) => ({ a, via: hits(a.relatesTo) })).filter((x) => x.via.length);
  return { flows, boundaries, threats, assumptions };
}

const via = (m: Model, refs: Ref[]) => refs.map((r) => `${r.type} "${labelOf(m, r)}"`).join(', ');

function reasoningFor(m: Model, change: Change, elId: string, headline: string, code: string, opts: { mitigations: boolean } = { mitigations: true }) {
  const out: ReviewItem[] = [];
  const el = m.elements.find((e) => e.id === elId);
  if (!el) return { items: out, nb: undefined };
  const nb = neighbourhood(m, elId);
  for (const { t, via: v } of nb.threats) {
    out.push(item(`${code}:threat`, { type: 'threat', id: t.id }, change,
      `${headline} Threat "${t.title}" targets ${via(m, v)}. Its likelihood rationale, preconditions and actor assumptions may no longer hold.`,
      [change.summary, `threat "${t.title}" targets ${via(m, v)}`]));
    if (opts.mitigations)
      for (const mit of m.mitigations.filter((x) => x.threatIds.includes(t.id) && (x.status === 'implemented' || x.status === 'verified'))) {
        out.push(item(`${code}:mitigation`, { type: 'mitigation', id: mit.id }, change,
          `${headline} Mitigation "${mit.title}" is recorded as ${mit.status} for threat "${t.title}". Confirm it still applies after this change.`,
          [change.summary, `threat "${t.title}" targets ${via(m, v)}`, `mitigation "${mit.title}" is linked to that threat (${mit.status})`]));
      }
  }
  for (const { a, via: v } of nb.assumptions)
    out.push(item(`${code}:assumption`, { type: 'assumption', id: a.id }, change,
      `${headline} Assumption "${a.text.slice(0, 160)}" relates to ${via(m, v)} and may be invalidated.`,
      [change.summary, `assumption "${a.text.slice(0, 80)}" relates to ${via(m, v)}`]));
  return { items: out, nb };
}

export function deriveReviewItems(before: Model, after: Model, changes: Change[]): ReviewItem[] {
  const out: ReviewItem[] = [];
  const nameOf = (id: string) => after.elements.find((e) => e.id === id)?.name ?? before.elements.find((e) => e.id === id)?.name ?? id;
  for (const c of changes) {
    switch (c.kind) {
      case 'element-exposure-changed':
      case 'element-added': {
        const el = after.elements.find((e) => e.id === c.entity.id)!;
        if (c.kind === 'element-added' && el.exposure !== 'external') break;
        if (c.kind === 'element-exposure-changed' && !(c.after === 'external' && c.before !== 'external')) break;
        const headline = `"${el.name}" is externally reachable${c.kind === 'element-exposure-changed' ? ` (was ${c.before})` : ' (new component)'}.`;
        out.push(item('exposure-increased', c.entity, c,
          `${headline}${el.properties['exposure.reason'] ? ` Reason: ${el.properties['exposure.reason']}.` : ''} Review its authentication, authorisation, hardening and monitoring, which may have assumed an internal-only caller.`,
          [c.summary]));
        const r = reasoningFor(after, c, el.id, headline, 'exposure-increased');
        out.push(...r.items);
        const nb = r.nb;
        // Only flows INTO the component: those are what a newly reachable caller can use. Outbound flows are not flagged here.
        for (const f of (nb?.flows ?? []).filter((x) => x.to === el.id))
          if (f.authenticated !== 'yes')
            out.push(item('exposure-increased:flow', { type: 'flow', id: f.id }, c,
              `${headline} Data flow ${labelOf(after, { type: 'flow', id: f.id })} reaches it with authentication "${f.authenticated}" and encryption "${f.encrypted}".`,
              [c.summary, `flow ${labelOf(after, { type: 'flow', id: f.id })} is attached to "${el.name}"`]));
        for (const b of nb?.boundaries ?? [])
          out.push(item('exposure-increased:boundary', { type: 'boundary', id: b.id }, c,
            `${headline} It is a member of boundary "${b.name}" (trust: ${b.trust}). Re-check whether that boundary still separates what you assumed.`,
            [c.summary, `"${el.name}" is a member of boundary "${b.name}"`]));
        break;
      }
      case 'flow-added':
      case 'flow-changed': {
        const f = after.flows.find((x) => x.id === c.entity.id);
        if (!f) break;
        if (c.kind === 'flow-changed' && !['authenticated', 'encrypted', 'from', 'to'].includes(c.field ?? '')) break;
        if (c.kind === 'flow-changed' && (c.field === 'authenticated' || c.field === 'encrypted') && c.after === 'yes') break;
        const fb = boundariesOf(after, f.from).map((b) => b.id), tb = boundariesOf(after, f.to).map((b) => b.id);
        const crossing = fb.some((b) => !tb.includes(b)) || tb.some((b) => !fb.includes(b));
        const fromEl = after.elements.find((e) => e.id === f.from);
        const untrustedSource = fromEl?.exposure === 'external';
        if (c.kind === 'flow-added' && !crossing && !untrustedSource) break;
        const headline = `Data flow ${labelOf(after, { type: 'flow', id: f.id })} ${c.kind === 'flow-added' ? 'is new' : 'changed'}${crossing ? ' and crosses a trust boundary' : ''}.`;
        out.push(item('flow-boundary', c.entity, c, `${headline} Check authentication (${f.authenticated}), encryption (${f.encrypted}) and what data it carries.`, [c.summary]));
        out.push(...reasoningFor(after, c, f.to, headline, 'flow-boundary').items);
        break;
      }
      case 'boundary-membership-changed': {
        const b = after.boundaries.find((x) => x.id === c.entity.id)!;
        const headline = `Boundary "${b.name}" membership changed.`;
        out.push(item('boundary-membership', c.entity, c, `${headline} ${c.summary}`, [c.summary]));
        for (const t of after.threats.filter((x) => x.targets.some((r) => r.type === 'boundary' && r.id === b.id)))
          out.push(item('boundary-membership:threat', { type: 'threat', id: t.id }, c, `${headline} Threat "${t.title}" targets this boundary.`, [c.summary, `threat "${t.title}" targets boundary "${b.name}"`]));
        for (const a of after.assumptions.filter((x) => x.relatesTo.some((r) => r.type === 'boundary' && r.id === b.id)))
          out.push(item('boundary-membership:assumption', { type: 'assumption', id: a.id }, c, `${headline} Assumption "${a.text.slice(0, 160)}" relates to this boundary.`, [c.summary, `assumption "${a.text.slice(0, 80)}" relates to boundary "${b.name}"`]));
        for (const mid of b.memberIds) {
          const el = after.elements.find((e) => e.id === mid);
          if (el && c.summary.includes(el.name)) out.push(...reasoningFor(after, c, mid, `${headline}`, 'boundary-membership').items);
        }
        break;
      }
      case 'evidence-stale': {
        const id = c.entity.id;
        const ev = after.evidence.find((e) => e.id === id)!;
        const headline = `Evidence "${ev.summary.slice(0, 80)}" is stale (${ev.staleReason ?? 'source changed'}).`;
        const citing: Array<[Ref, string, string[]]> = [];
        for (const e of after.elements) if (e.evidenceIds.includes(id)) citing.push([{ type: 'element', id: e.id }, e.name, e.evidenceIds]);
        for (const f of after.flows) if (f.evidenceIds.includes(id)) citing.push([{ type: 'flow', id: f.id }, labelOf(after, { type: 'flow', id: f.id }), f.evidenceIds]);
        for (const b of after.boundaries) if (b.evidenceIds.includes(id)) citing.push([{ type: 'boundary', id: b.id }, b.name, b.evidenceIds]);
        for (const t of after.threats) if (t.evidenceIds.includes(id)) citing.push([{ type: 'threat', id: t.id }, t.title, t.evidenceIds]);
        for (const a of after.assumptions) if (a.evidenceIds.includes(id)) citing.push([{ type: 'assumption', id: a.id }, a.text.slice(0, 80), a.evidenceIds]);
        for (const [r, label] of citing.map(([r, l]) => [r, l] as const))
          out.push(item('evidence-stale', r, c, `${headline} ${r.type} "${label}" cites it, so the supporting reasoning may be out of date.`, [c.summary, `${r.type} "${label}" cites this evidence`]));
        for (const m of after.mitigations) {
          const impl = m.evidenceIds.includes(id), ver = m.verification.evidenceIds.includes(id);
          if (impl || ver)
            out.push(item(ver ? 'verification-stale' : 'evidence-stale', { type: 'mitigation', id: m.id }, c,
              `${headline} Mitigation "${m.title}" ${ver ? `uses it as verification evidence (status ${m.status}); re-verify before relying on "${m.status}"` : 'cites it as implementation evidence'}.`,
              [c.summary, `mitigation "${m.title}" ${ver ? 'verification' : 'implementation'} cites this evidence`]));
        }
        break;
      }
      case 'element-removed':
      case 'element-missing-from-source': {
        const gone = c.kind === 'element-removed' ? before : after;
        const nb = neighbourhood(gone, c.entity.id);
        const headline = `"${nameOf(c.entity.id)}" ${c.kind === 'element-removed' ? 'was removed' : 'is no longer in the source'}.`;
        for (const { t, via: v } of nb.threats)
          out.push(item('element-removed:threat', { type: 'threat', id: t.id }, c, `${headline} Threat "${t.title}" targeted ${via(gone, v)}. Confirm it still applies, retarget it, or retire it.`, [c.summary, `threat "${t.title}" targeted ${via(gone, v)}`]));
        for (const { a, via: v } of nb.assumptions)
          out.push(item('element-removed:assumption', { type: 'assumption', id: a.id }, c, `${headline} Assumption "${a.text.slice(0, 160)}" related to ${via(gone, v)}.`, [c.summary, `assumption "${a.text.slice(0, 80)}" related to ${via(gone, v)}`]));
        break;
      }
      default:
        break;
    }
  }
  // De-duplicate by deterministic id.
  const seen = new Map<string, ReviewItem>();
  for (const r of out) if (!seen.has(r.id)) seen.set(r.id, r);
  return [...seen.values()];
}

/** Merge new review items without reopening anything a person already closed. */
export function mergeReviewItems(model: Model, items: ReviewItem[]): { model: Model; added: ReviewItem[] } {
  const next = structuredClone(model);
  const existing = new Set(next.reviewItems.map((r) => r.id));
  const added = items.filter((r) => !existing.has(r.id));
  next.reviewItems.push(...added);
  return { model: next, added };
}

export function openReviewFor(model: Model, ref: Ref): ReviewItem[] {
  return model.reviewItems.filter((r) => r.status === 'open' && r.target.type === ref.type && r.target.id === ref.id);
}
