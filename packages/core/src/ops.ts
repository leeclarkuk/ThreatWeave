import {
  Asset, Assumption, Boundary, Element, Evidence, Flow, MODEL_FORMAT, Mitigation, SCHEMA_VERSION, Threat,
  type Decision, type EntityType, type MitigationStatus, type Model, type Ref,
} from './model.js';
import { newEventId, newId, nowIso, slug } from './util.js';

export type Actor = string;
export const clone = <T>(x: T): T => structuredClone(x);

export function emptyModel(name: string, description = ''): Model {
  const id = `${slug(name, 40)}-${newId('system').split('-').pop()}`;
  return {
    format: MODEL_FORMAT, schemaVersion: SCHEMA_VERSION, id: id.length >= 3 ? id : `model-${id}`,
    name, description, example: false,
    systems: [{ id: newId('system', name), name, description: '', notes: '' }],
    elements: [], flows: [], boundaries: [], assets: [], assumptions: [], threats: [], mitigations: [],
    evidence: [], sources: [], proposals: [], reviewItems: [], decisions: [], runs: [],
    view: { layout: {} },
  };
}

const human = (actor: Actor) => ({ origin: 'human' as const, actor, at: nowIso() });

const COLLECTION_OF: Record<string, keyof Model> = {
  system: 'systems', element: 'elements', flow: 'flows', boundary: 'boundaries', asset: 'assets',
  assumption: 'assumptions', threat: 'threats', mitigation: 'mitigations', evidence: 'evidence',
};

type Addable = 'element' | 'flow' | 'boundary' | 'asset' | 'assumption' | 'threat' | 'mitigation' | 'evidence';
const SCHEMAS = { element: Element, flow: Flow, boundary: Boundary, asset: Asset, assumption: Assumption, threat: Threat, mitigation: Mitigation, evidence: Evidence };

/** Add a human-authored entity. The result is schema-parsed so defaults are filled and bad input throws. */
export function addEntity(model: Model, type: Addable, input: Record<string, unknown>, actor: Actor): { model: Model; id: string } {
  const next = clone(model);
  const id = (input.id as string | undefined) ?? newId(type as EntityType, String(input.name ?? input.title ?? input.text ?? input.summary ?? type));
  const raw = { ...input, id, provenance: input.provenance ?? human(actor) };
  if (type === 'mitigation' && !('status' in input)) (raw as Record<string, unknown>).status = 'planned';
  const parsed = SCHEMAS[type].parse(raw) as { id: string };
  (next[COLLECTION_OF[type] as 'elements'] as unknown as Array<{ id: string }>).push(parsed);
  return { model: next, id: parsed.id };
}

/** Patch an entity. Identity and provenance are immutable here; mitigation status goes through setMitigationStatus. */
export function updateEntity(model: Model, type: Addable, id: string, patch: Record<string, unknown>): Model {
  const next = clone(model);
  const list = next[COLLECTION_OF[type] as 'elements'] as unknown as Array<Record<string, unknown>>;
  const idx = list.findIndex((e) => e.id === id);
  if (idx < 0) throw new Error(`${type} ${id} not found`);
  const { id: _i, provenance: _p, ...safe } = patch;
  if (type === 'mitigation' && 'status' in safe) throw new Error('Use setMitigationStatus to change mitigation status');
  list[idx] = SCHEMAS[type].parse({ ...list[idx], ...safe });
  return next;
}

export function removeEntity(model: Model, type: Addable, id: string): Model {
  const next = clone(model);
  const col = COLLECTION_OF[type] as 'elements';
  (next[col] as unknown as Array<{ id: string }>) = (next[col] as unknown as Array<{ id: string }>).filter((e) => e.id !== id);
  const dropRef = (r: Ref) => !(r.type === type && r.id === id);
  if (type === 'element') {
    next.flows = next.flows.filter((f) => f.from !== id && f.to !== id);
    next.boundaries.forEach((b) => (b.memberIds = b.memberIds.filter((m) => m !== id)));
    next.assets.forEach((a) => (a.storedIn = a.storedIn.filter((m) => m !== id)));
    delete next.view.layout[id];
  }
  if (type === 'flow' || type === 'element') {
    const gone = new Set(next.flows.map((f) => f.id));
    // flows removed above must also disappear from references
    next.threats.forEach((t) => (t.targets = t.targets.filter((r) => r.type !== 'flow' || gone.has(r.id))));
    next.assumptions.forEach((a) => (a.relatesTo = a.relatesTo.filter((r) => r.type !== 'flow' || gone.has(r.id))));
  }
  next.threats.forEach((t) => {
    t.targets = t.targets.filter(dropRef);
    t.evidenceIds = type === 'evidence' ? t.evidenceIds.filter((e) => e !== id) : t.evidenceIds;
  });
  next.assumptions.forEach((a) => {
    a.relatesTo = a.relatesTo.filter(dropRef);
    if (type === 'evidence') a.evidenceIds = a.evidenceIds.filter((e) => e !== id);
  });
  if (type === 'threat') next.mitigations.forEach((m) => (m.threatIds = m.threatIds.filter((t) => t !== id)));
  if (type === 'assumption') next.mitigations.forEach((m) => (m.assumptionIds = m.assumptionIds.filter((t) => t !== id)));
  if (type === 'asset') next.flows.forEach((f) => (f.assetIds = f.assetIds.filter((a) => a !== id)));
  if (type === 'evidence') {
    for (const list of [next.elements, next.flows, next.boundaries, next.assets] as Array<Array<{ evidenceIds: string[] }>>)
      list.forEach((x) => (x.evidenceIds = x.evidenceIds.filter((e) => e !== id)));
    next.mitigations.forEach((m) => {
      m.evidenceIds = m.evidenceIds.filter((e) => e !== id);
      m.verification.evidenceIds = m.verification.evidenceIds.filter((e) => e !== id);
      // Removing the evidence behind a verification must not leave a verified claim standing.
      if (m.status === 'verified' && m.verification.evidenceIds.length === 0) m.status = 'implemented';
    });
  }
  return next;
}

export function recordDecision(model: Model, d: Omit<Decision, 'id' | 'at'> & { at?: string }): { model: Model; decision: Decision } {
  const decision: Decision = { id: newEventId('decision'), at: d.at ?? nowIso(), ...d, detail: d.detail ?? '' };
  const next = clone(model);
  next.decisions.push(decision);
  return { model: next, decision };
}

/**
 * Change a mitigation's status. Only a named person (or an import) can move it to
 * implemented or verified; verified additionally needs evidence. Records a decision.
 */
export function setMitigationStatus(
  model: Model,
  id: string,
  status: MitigationStatus,
  by: { actor: Actor; actorKind?: 'human' | 'import' },
  opts: { rationale?: string; verificationEvidenceIds?: string[]; verificationNote?: string } = {},
): Model {
  const next = clone(model);
  const m = next.mitigations.find((x) => x.id === id);
  if (!m) throw new Error(`mitigation ${id} not found`);
  if (!by.actor.trim()) throw new Error('A named actor is required to change mitigation status');
  m.status = status;
  if (status === 'implemented' || status === 'verified')
    m.statusSetBy = { actorKind: by.actorKind ?? 'human', actor: by.actor, at: nowIso() };
  else delete m.statusSetBy;
  if (status === 'verified') {
    const ev = opts.verificationEvidenceIds ?? m.verification.evidenceIds;
    if (!ev.length) throw new Error('Verified status needs at least one piece of verification evidence');
    m.verification.evidenceIds = [...new Set(ev)];
    if (opts.verificationNote !== undefined) m.verification.note = opts.verificationNote;
  }
  const rec = recordDecision(next, {
    subject: { type: 'mitigation', id }, action: status === 'verified' ? 'verify' : 'set-status',
    rationale: opts.rationale ?? '', actor: by.actor, detail: `status -> ${status}`,
  });
  return rec.model;
}

export function setThreatStatus(model: Model, id: string, status: Threat['status'], actor: Actor, rationale = ''): Model {
  const next = clone(model);
  const t = next.threats.find((x) => x.id === id);
  if (!t) throw new Error(`threat ${id} not found`);
  if ((status === 'accepted-risk' || status === 'not-applicable') && !rationale.trim())
    throw new Error(`A rationale is required to mark a threat ${status}`);
  t.status = status;
  return recordDecision(next, {
    subject: { type: 'threat', id }, action: status === 'accepted-risk' ? 'accept-risk' : 'set-status',
    rationale, actor, detail: `status -> ${status}`,
  }).model;
}

export function resolveReviewItem(model: Model, id: string, action: 'resolve' | 'dismiss', actor: Actor, rationale: string): Model {
  if (!rationale.trim()) throw new Error('A rationale is required to close a review item');
  const next = clone(model);
  const r = next.reviewItems.find((x) => x.id === id);
  if (!r) throw new Error(`review item ${id} not found`);
  const rec = recordDecision(next, { subject: { type: 'review', id }, action, rationale, actor, detail: r.reason.slice(0, 200) });
  const item = rec.model.reviewItems.find((x) => x.id === id)!;
  item.status = action === 'resolve' ? 'resolved' : 'dismissed';
  item.decisionId = rec.decision.id;
  return rec.model;
}

export function setLayout(model: Model, positions: Record<string, { x: number; y: number }>): Model {
  const next = clone(model);
  Object.assign(next.view.layout, positions);
  return next;
}

/** Name lookups used by UI and reports. */
export function labelOf(model: Model, ref: { type: string; id: string }): string {
  const pools: Record<string, Array<{ id: string; name?: string; title?: string; text?: string; summary?: string }>> = {
    system: model.systems, element: model.elements, boundary: model.boundaries, asset: model.assets,
    assumption: model.assumptions, threat: model.threats, mitigation: model.mitigations, evidence: model.evidence,
  };
  if (ref.type === 'flow') {
    const f = model.flows.find((x) => x.id === ref.id);
    if (!f) return ref.id;
    const n = (id: string) => model.elements.find((e) => e.id === id)?.name ?? id;
    return `${n(f.from)} → ${n(f.to)}${f.label ? ` (${f.label})` : ''}`;
  }
  const hit = pools[ref.type]?.find((x) => x.id === ref.id);
  return hit ? (hit.name ?? hit.title ?? hit.text ?? hit.summary ?? ref.id).slice(0, 120) : `${ref.id} (missing)`;
}

/** Entities that reference an element, used to show "related reasoning" for a selection. */
export function relatedTo(model: Model, ref: Ref) {
  const hits = (refs: Ref[]) => refs.some((r) => r.type === ref.type && r.id === ref.id);
  const flowIds = ref.type === 'element' ? model.flows.filter((f) => f.from === ref.id || f.to === ref.id).map((f) => f.id) : [];
  const touches = (refs: Ref[]) => hits(refs) || refs.some((r) => r.type === 'flow' && flowIds.includes(r.id));
  const threats = model.threats.filter((t) => touches(t.targets) || (ref.type === 'threat' && t.id === ref.id));
  const threatIds = new Set(threats.map((t) => t.id));
  const assumptions = model.assumptions.filter((a) => touches(a.relatesTo));
  const mitigations = model.mitigations.filter((m) => m.threatIds.some((t) => threatIds.has(t)));
  return { threats, assumptions, mitigations, flows: model.flows.filter((f) => flowIds.includes(f.id)) };
}
