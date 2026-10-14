import { z } from 'zod';
import {
  ProposalPayload, ProposalEvidence, type Model, type Proposal, type ProposalKind, type Ref, type RefType, type Run,
} from './model.js';
import { addEntity, clone, recordDecision } from './ops.js';
import { fingerprintPayload, mergeProposals, similarThreatExists } from './packs.js';
import { newEventId, nowIso } from './util.js';

/* ------------------------------------------------------------------ */
/* Shape the model provider must return. Strict: unknown fields fail.   */
/* ------------------------------------------------------------------ */
const AiEvidence = z.strictObject({
  path: z.string().max(500),
  lineStart: z.number().int().min(1),
  lineEnd: z.number().int().min(1),
  quote: z.string().min(1).max(600),
});
export const AiProposalItem = z.strictObject({
  key: z.string().max(100).optional(),
  reasoning: z.string().min(1).max(4000),
  basis: z.enum(['inferred', 'hypothesis']),
  evidence: z.array(AiEvidence).max(6).default([]),
  missingInformation: z.array(z.string().max(500)).max(8).default([]),
  payload: ProposalPayload,
});
export const AiOutput = z.strictObject({
  summary: z.string().max(2000).default(''),
  proposals: z.array(z.unknown()).max(200),
});
export const AI_OUTPUT_JSON_SCHEMA = z.toJSONSchema(
  z.strictObject({ summary: z.string(), proposals: z.array(AiProposalItem).max(40) }),
  { io: 'input' },
) as Record<string, unknown>;

export const MAX_PROPOSALS_PER_RUN = 40;

export interface Discard {
  index: number;
  reason: string;
}
export interface IngestResult {
  proposals: Proposal[];
  discarded: Discard[];
  summary: string;
  skippedDuplicates: Array<{ title: string; reason: string }>;
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim();
const stripCtl = (s: string) => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');

/** Verify one claimed citation against the exact text that was sent. Returns a corrected citation or null. */
export function verifyEvidence(
  ev: { path: string; lineStart: number; lineEnd: number; quote: string },
  files: ReadonlyMap<string, string>,
): ProposalEvidence | null {
  const text = files.get(ev.path);
  if (text === undefined) return null;
  const lines = text.split('\n');
  const q = norm(ev.quote);
  if (!q) return null;
  const window = (a: number, b: number) => norm(lines.slice(Math.max(0, a - 1), Math.min(lines.length, b)).join('\n'));
  const lo = Math.max(1, ev.lineStart - 2), hi = Math.min(lines.length, ev.lineEnd + 2);
  if (ev.lineStart <= lines.length && window(lo, hi).includes(q))
    return { path: ev.path, lineStart: Math.min(ev.lineStart, lines.length), lineEnd: Math.min(Math.max(ev.lineEnd, ev.lineStart), lines.length), quote: ev.quote, verified: true };
  // Not where claimed: accept only if the quote exists verbatim elsewhere, and correct the location.
  for (let i = 0; i < lines.length; i++) {
    const span = Math.max(1, ev.lineEnd - ev.lineStart + 1);
    if (window(i + 1, i + span).includes(q)) return { path: ev.path, lineStart: i + 1, lineEnd: i + span, quote: ev.quote, verified: true };
  }
  return null;
}

function resolvable(model: Model, batchKeys: Set<string>, ref: string): boolean {
  if (batchKeys.has(ref)) return true;
  const all = [...model.elements, ...model.flows, ...model.boundaries, ...model.assets, ...model.threats, ...model.assumptions, ...model.mitigations];
  if (all.some((e) => e.id === ref)) return true;
  return model.elements.some((e) => e.name.toLowerCase() === ref.toLowerCase());
}

const refsOf = (p: ProposalPayload): string[] => {
  switch (p.kind) {
    case 'add-flow': return [p.from, p.to];
    case 'add-boundary': return p.members;
    case 'add-asset': return p.storedIn;
    case 'add-threat': return p.targets.map((t) => t.ref);
    case 'add-mitigation': return p.threats;
    case 'add-assumption': case 'add-question': return p.relatesTo.map((t) => t.ref);
    default: return [];
  }
};
const titleOf = (p: ProposalPayload): string => ('title' in p ? p.title : 'name' in p ? p.name : 'text' in p ? p.text : `${p.kind}`).slice(0, 80);

/**
 * Turn raw provider output into pending proposals, or discard it. Nothing here touches
 * accepted model content. Hard rules:
 *  - unknown fields, wrong types and any attempt to set statuses fail the schema;
 *  - evidence must quote text that exists in a file that was actually sent;
 *  - a threat must reference something that exists in the model or in this batch;
 *  - "inferred" without verified evidence is downgraded to "hypothesis";
 *  - duplicates and previously rejected proposals are skipped.
 */
export function ingestAiOutput(
  model: Model,
  raw: unknown,
  ctx: { runId: string; sourceId?: string; files: ReadonlyMap<string, string>; origin?: 'ai' | 'mcp' },
): IngestResult {
  const result: IngestResult = { proposals: [], discarded: [], summary: '', skippedDuplicates: [] };
  const top = AiOutput.safeParse(raw);
  if (!top.success) {
    result.discarded.push({ index: -1, reason: `Output did not match the required shape: ${top.error.issues[0]?.path.join('.') || '(root)'}: ${top.error.issues[0]?.message}` });
    return result;
  }
  result.summary = stripCtl(top.data.summary);
  const items = top.data.proposals.slice(0, MAX_PROPOSALS_PER_RUN);
  if (top.data.proposals.length > items.length) result.discarded.push({ index: MAX_PROPOSALS_PER_RUN, reason: `${top.data.proposals.length - items.length} proposals beyond the per-run limit of ${MAX_PROPOSALS_PER_RUN} were ignored` });

  const parsed: Array<{ index: number; item: z.infer<typeof AiProposalItem> }> = [];
  items.forEach((raw, index) => {
    const r = AiProposalItem.safeParse(raw);
    if (!r.success) result.discarded.push({ index, reason: `Invalid proposal: ${r.error.issues[0]?.path.join('.') || '(root)'}: ${r.error.issues[0]?.message}` });
    else parsed.push({ index, item: r.data });
  });
  const keys = new Set(parsed.map((p) => p.item.key).filter((k): k is string => !!k));

  for (const { index, item } of parsed) {
    const notes: string[] = [];
    const p = item.payload;
    const missing = refsOf(p).filter((r) => !resolvable(model, keys, r));
    if (missing.length) { result.discarded.push({ index, reason: `"${titleOf(p)}" references unknown ${missing.slice(0, 3).map((m) => `"${m}"`).join(', ')}; not tied to this system` }); continue; }
    if ((p.kind === 'add-threat') && p.targets.length === 0) { result.discarded.push({ index, reason: `"${titleOf(p)}" is a threat with no target in this system (generic)` }); continue; }

    const evidence: ProposalEvidence[] = [];
    for (const e of item.evidence) {
      const v = verifyEvidence(e, ctx.files);
      if (v) evidence.push(v);
      else notes.push(`Dropped unverifiable evidence: ${e.path}:${e.lineStart}-${e.lineEnd} (${ctx.files.has(e.path) ? 'quote not found in that file' : 'file was not part of the analysed input'}).`);
    }
    let basis = item.basis;
    if (basis === 'inferred' && evidence.length === 0) { basis = 'hypothesis'; notes.push('Downgraded from inferred to hypothesis: no verifiable evidence was supplied.'); }
    const evidenceStrength = p.kind === 'add-threat' ? p.evidenceStrength : undefined;
    if (p.kind === 'add-threat' && evidence.length === 0 && (evidenceStrength === 'moderate' || evidenceStrength === 'strong')) {
      p.evidenceStrength = 'weak';
      notes.push(`Evidence strength lowered from ${evidenceStrength} to weak: no verifiable citation.`);
    }
    const proposal: Proposal = {
      id: newEventId('proposal'), ...(item.key ? { key: item.key } : {}), origin: ctx.origin ?? 'ai', runId: ctx.runId,
      ...(ctx.sourceId ? { sourceId: ctx.sourceId } : {}), payload: p, reasoning: stripCtl(item.reasoning), basis, evidence,
      missingInformation: item.missingInformation.map(stripCtl), fingerprint: fingerprintPayload(p), status: 'pending', validationNotes: notes, createdAt: nowIso(),
    };
    result.proposals.push(proposal);
  }
  return result;
}

/** Add ingested proposals to the model, skipping duplicates and anything previously rejected. */
export function addIngested(model: Model, ing: IngestResult): { model: Model; added: Proposal[]; skipped: Array<{ title: string; reason: string }> } {
  const m = mergeProposals(model, ing.proposals);
  return { model: m.model, added: m.added, skipped: m.skipped.map((s) => ({ title: titleOf(s.proposal.payload), reason: s.reason })) };
}

/* ------------------------------------------------------------------ */
/* Accept / reject                                                      */
/* ------------------------------------------------------------------ */

export class ProposalError extends Error {}

const TYPE_FOR_KIND: Record<ProposalKind, RefType | null> = {
  'add-element': 'element', 'add-flow': 'flow', 'add-boundary': 'boundary', 'add-asset': 'asset', 'add-threat': 'threat',
  'add-mitigation': 'mitigation', 'add-assumption': 'assumption', 'add-question': 'assumption',
};

/** Resolve an id, a draft key from the same batch, or an exact element name to a real model id. */
function resolve(model: Model, p: Proposal, ref: string, wantTypes: RefType[]): string {
  const pools: Record<string, Array<{ id: string; name?: string }>> = {
    element: model.elements, flow: model.flows, boundary: model.boundaries, asset: model.assets,
    threat: model.threats, assumption: model.assumptions, mitigation: model.mitigations,
  };
  for (const t of wantTypes) if (pools[t]?.some((e) => e.id === ref)) return ref;
  const sibling = model.proposals.find((x) => x.key === ref && x.runId === p.runId && x.id !== p.id);
  if (sibling) {
    if (sibling.status === 'accepted' && sibling.createdEntity) return sibling.createdEntity.id;
    throw new ProposalError(`This depends on "${sibling.key}" (${titleOf(sibling.payload)}). Accept that proposal first.`);
  }
  if (wantTypes.includes('element')) {
    const byName = model.elements.find((e) => e.name.toLowerCase() === ref.toLowerCase());
    if (byName) return byName.id;
  }
  throw new ProposalError(`Cannot resolve reference "${ref}" to anything in the model.`);
}

function resolveTarget(model: Model, p: Proposal, t: { type: RefType; ref: string }): Ref {
  return { type: t.type, id: resolve(model, p, t.ref, [t.type]) };
}

function runActor(model: Model, p: Proposal): string {
  const run = model.runs.find((r) => r.id === p.runId);
  if (p.origin === 'pack-rule') return 'rule-pack:generic-1';
  if (p.origin === 'mcp') return 'mcp-client';
  return run?.adapter ? `${run.adapter}${run.modelId ? `:${run.modelId}` : ''}` : 'ai';
}

/**
 * Accept a pending proposal, optionally with edits. Creates the entity with AI provenance,
 * records the human decision, and keeps new mitigations at status "proposed".
 */
export function acceptProposal(
  model: Model,
  id: string,
  by: { actor: string; rationale?: string; edited?: unknown },
): Model {
  if (!by.actor.trim()) throw new ProposalError('A named person must accept proposals');
  const src = model.proposals.find((x) => x.id === id);
  if (!src) throw new ProposalError(`Proposal ${id} not found`);
  if (src.status !== 'pending') throw new ProposalError(`Proposal is already ${src.status}`);
  let payload = src.payload;
  let edited = false;
  if (by.edited !== undefined) {
    const r = ProposalPayload.safeParse(by.edited);
    if (!r.success) throw new ProposalError(`Edited proposal is invalid: ${r.error.issues[0]?.path.join('.')}: ${r.error.issues[0]?.message}`);
    if (r.data.kind !== src.payload.kind) throw new ProposalError('An edit cannot change the kind of proposal');
    payload = r.data;
    edited = JSON.stringify(payload) !== JSON.stringify(src.payload);
  }
  let next = clone(model);
  const p = next.proposals.find((x) => x.id === id)!;
  const prov = { origin: (src.origin === 'pack-rule' ? 'pack-rule' : 'ai') as 'ai' | 'pack-rule', actor: runActor(model, src), ...(src.runId ? { runId: src.runId } : {}), proposalId: id, at: nowIso() };
  const basis = src.basis;
  const evidenceIds: string[] = [];
  const srcRec = next.sources.find((s) => s.id === src.sourceId);
  for (const e of src.evidence.filter((x) => x.verified)) {
    const file = srcRec?.files.find((f) => f.path === e.path);
    const r = addEntity(next, 'evidence', {
      kind: 'source-file', summary: `Cited by proposal: ${e.path}:${e.lineStart}`, ...(src.sourceId ? { sourceId: src.sourceId } : {}),
      path: e.path, lineStart: e.lineStart, lineEnd: e.lineEnd, quote: e.quote.slice(0, 600), ...(srcRec ? { revision: srcRec.revision } : {}),
      ...(file ? { contentHash: file.hash } : {}), provenance: prov,
    }, by.actor);
    next = r.model;
    evidenceIds.push(r.id);
  }
  let created: { type: RefType; id: string };
  switch (payload.kind) {
    case 'add-element': {
      const r = addEntity(next, 'element', { kind: payload.elementKind, name: payload.name, description: payload.description, technology: payload.technology, exposure: payload.exposure, basis, evidenceIds, provenance: prov }, by.actor);
      next = r.model; created = { type: 'element', id: r.id }; break;
    }
    case 'add-flow': {
      const r = addEntity(next, 'flow', { from: resolve(next, p, payload.from, ['element']), to: resolve(next, p, payload.to, ['element']), label: payload.label, protocol: payload.protocol, authenticated: payload.authenticated, encrypted: payload.encrypted, basis, evidenceIds, provenance: prov }, by.actor);
      next = r.model; created = { type: 'flow', id: r.id }; break;
    }
    case 'add-boundary': {
      const r = addEntity(next, 'boundary', { name: payload.name, kind: payload.boundaryKind, description: payload.description, memberIds: payload.members.map((m) => resolve(next, p, m, ['element'])), basis, evidenceIds, provenance: prov }, by.actor);
      next = r.model; created = { type: 'boundary', id: r.id }; break;
    }
    case 'add-asset': {
      const r = addEntity(next, 'asset', { name: payload.name, description: payload.description, classification: payload.classification, storedIn: payload.storedIn.map((m) => resolve(next, p, m, ['element'])), basis, evidenceIds, provenance: prov }, by.actor);
      next = r.model; created = { type: 'asset', id: r.id }; break;
    }
    case 'add-threat': {
      const r = addEntity(next, 'threat', {
        title: payload.title, source: payload.source, preconditions: payload.preconditions, action: payload.action, consequence: payload.consequence,
        goals: payload.goals, stride: payload.stride, targets: payload.targets.map((t) => resolveTarget(next, p, t)), likelihood: payload.likelihood, impact: payload.impact,
        evidenceStrength: payload.evidenceStrength, evidenceRationale: src.validationNotes.join(' ').slice(0, 2000), status: 'open', basis, evidenceIds, provenance: prov,
        notes: src.missingInformation.length ? `Open information needs:\n- ${src.missingInformation.join('\n- ')}` : '',
      }, by.actor);
      next = r.model; created = { type: 'threat', id: r.id }; break;
    }
    case 'add-mitigation': {
      const r = addEntity(next, 'mitigation', {
        title: payload.title, description: payload.description, status: 'proposed', evidenceIds: [],
        threatIds: payload.threats.map((t) => resolve(next, p, t, ['threat'])), verification: { plan: payload.verificationSteps, evidenceIds: [], note: '' }, provenance: prov,
      }, by.actor);
      next = r.model; created = { type: 'mitigation', id: r.id }; break;
    }
    case 'add-assumption':
    case 'add-question': {
      const r = addEntity(next, 'assumption', {
        kind: payload.kind === 'add-question' ? 'question' : 'assumption', text: payload.text, status: 'open', basis: 'hypothesis',
        relatesTo: payload.relatesTo.map((t) => resolveTarget(next, p, t)), rationale: src.reasoning.slice(0, 2000), evidenceIds, provenance: prov,
      }, by.actor);
      next = r.model; created = { type: 'assumption', id: r.id }; break;
    }
  }
  void TYPE_FOR_KIND;
  const rec = recordDecision(next, {
    subject: { type: 'proposal', id }, action: edited ? 'edit-accept' : 'accept', rationale: by.rationale ?? '', actor: by.actor,
    detail: `${titleOf(payload)} -> ${created.type} ${created.id}`,
  });
  const pp = rec.model.proposals.find((x) => x.id === id)!;
  pp.status = 'accepted'; pp.createdEntity = created; pp.decisionId = rec.decision.id;
  if (edited) pp.payload = payload;
  return rec.model;
}

export function rejectProposal(model: Model, id: string, by: { actor: string; rationale: string }): Model {
  if (!by.actor.trim()) throw new ProposalError('A named person must reject proposals');
  if (!by.rationale.trim()) throw new ProposalError('A reason is required to reject a proposal');
  const next = clone(model);
  const p = next.proposals.find((x) => x.id === id);
  if (!p) throw new ProposalError(`Proposal ${id} not found`);
  if (p.status !== 'pending') throw new ProposalError(`Proposal is already ${p.status}`);
  const rec = recordDecision(next, { subject: { type: 'proposal', id }, action: 'reject', rationale: by.rationale, actor: by.actor, detail: titleOf(p.payload) });
  const pp = rec.model.proposals.find((x) => x.id === id)!;
  pp.status = 'rejected'; pp.decisionId = rec.decision.id;
  return rec.model;
}

export function startRun(model: Model, run: Omit<Run, 'id' | 'startedAt' | 'status'> & { id?: string }): { model: Model; run: Run } {
  const r: Run = { id: run.id ?? newEventId('run'), startedAt: nowIso(), status: 'running', ...run };
  const next = clone(model);
  next.runs.push(r);
  return { model: next, run: r };
}

export function finishRun(model: Model, id: string, patch: Partial<Run>): Model {
  const next = clone(model);
  const r = next.runs.find((x) => x.id === id);
  if (!r) return next;
  Object.assign(r, patch, { finishedAt: nowIso() });
  return next;
}

export { similarThreatExists };
