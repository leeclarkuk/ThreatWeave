import { Model, type Ref } from './model.js';

export interface Issue {
  severity: 'error' | 'warning';
  code: string;
  path: string;
  message: string;
}
export interface ValidationResult {
  ok: boolean;
  model?: Model;
  issues: Issue[];
}

const err = (code: string, path: string, message: string): Issue => ({ severity: 'error', code, path, message });
const warn = (code: string, path: string, message: string): Issue => ({ severity: 'warning', code, path, message });

export function refExists(model: Model, ref: { type: string; id: string }): boolean {
  const pool: Record<string, Array<{ id: string }>> = {
    system: model.systems, element: model.elements, flow: model.flows, boundary: model.boundaries,
    asset: model.assets, assumption: model.assumptions, threat: model.threats, mitigation: model.mitigations,
    evidence: model.evidence,
  };
  return (pool[ref.type] ?? []).some((e) => e.id === ref.id);
}

/** Cross-reference and invariant checks on an already schema-valid model. */
export function checkIntegrity(model: Model): Issue[] {
  const issues: Issue[] = [];
  const seen = new Map<string, string>();
  const collections = {
    systems: model.systems, elements: model.elements, flows: model.flows, boundaries: model.boundaries,
    assets: model.assets, assumptions: model.assumptions, threats: model.threats, mitigations: model.mitigations,
    evidence: model.evidence, sources: model.sources, proposals: model.proposals, reviewItems: model.reviewItems,
    decisions: model.decisions, runs: model.runs,
  };
  for (const [name, items] of Object.entries(collections)) {
    items.forEach((it, i) => {
      const where = `${name}[${i}]`;
      const prior = seen.get(it.id);
      if (prior) issues.push(err('duplicate-id', where, `id ${it.id} also used at ${prior}`));
      else seen.set(it.id, where);
    });
  }
  const has = (set: Array<{ id: string }>) => {
    const ids = new Set(set.map((x) => x.id));
    return (id: string) => ids.has(id);
  };
  const hasEl = has(model.elements), hasAsset = has(model.assets), hasEv = has(model.evidence);
  const hasThreat = has(model.threats), hasAsm = has(model.assumptions), hasSrc = has(model.sources);
  const hasSys = has(model.systems);

  const checkEv = (ids: string[], path: string) =>
    ids.forEach((id) => !hasEv(id) && issues.push(err('dangling-evidence', path, `evidence ${id} does not exist`)));
  const checkRef = (r: Ref, path: string) =>
    !refExists(model, r) && issues.push(err('dangling-ref', path, `${r.type} ${r.id} does not exist`));

  model.elements.forEach((e, i) => {
    checkEv(e.evidenceIds, `elements[${i}].evidenceIds`);
    if (e.systemId && !hasSys(e.systemId)) issues.push(err('dangling-ref', `elements[${i}].systemId`, `system ${e.systemId} does not exist`));
  });
  model.flows.forEach((f, i) => {
    if (!hasEl(f.from)) issues.push(err('dangling-ref', `flows[${i}].from`, `element ${f.from} does not exist`));
    if (!hasEl(f.to)) issues.push(err('dangling-ref', `flows[${i}].to`, `element ${f.to} does not exist`));
    f.assetIds.forEach((a) => !hasAsset(a) && issues.push(err('dangling-ref', `flows[${i}].assetIds`, `asset ${a} does not exist`)));
    checkEv(f.evidenceIds, `flows[${i}].evidenceIds`);
  });
  model.boundaries.forEach((b, i) => {
    b.memberIds.forEach((m) => !hasEl(m) && issues.push(err('dangling-ref', `boundaries[${i}].memberIds`, `element ${m} does not exist`)));
    checkEv(b.evidenceIds, `boundaries[${i}].evidenceIds`);
  });
  model.assets.forEach((a, i) => {
    a.storedIn.forEach((m) => !hasEl(m) && issues.push(err('dangling-ref', `assets[${i}].storedIn`, `element ${m} does not exist`)));
    checkEv(a.evidenceIds, `assets[${i}].evidenceIds`);
  });
  model.assumptions.forEach((a, i) => {
    a.relatesTo.forEach((r) => checkRef(r, `assumptions[${i}].relatesTo`));
    checkEv(a.evidenceIds, `assumptions[${i}].evidenceIds`);
  });
  model.threats.forEach((t, i) => {
    t.targets.forEach((r) => checkRef(r, `threats[${i}].targets`));
    checkEv(t.evidenceIds, `threats[${i}].evidenceIds`);
    if (t.targets.length === 0) issues.push(warn('threat-no-target', `threats[${i}]`, `threat ${t.id} affects no element, flow, boundary or asset`));
    if (t.status === 'mitigated') {
      const ok = model.mitigations.some((m) => m.threatIds.includes(t.id) && (m.status === 'implemented' || m.status === 'verified'));
      if (!ok) issues.push(warn('mitigated-without-control', `threats[${i}]`, `threat ${t.id} is marked mitigated but no linked mitigation is implemented or verified`));
    }
  });
  model.mitigations.forEach((m, i) => {
    m.threatIds.forEach((t) => !hasThreat(t) && issues.push(err('dangling-ref', `mitigations[${i}].threatIds`, `threat ${t} does not exist`)));
    m.assumptionIds.forEach((a) => !hasAsm(a) && issues.push(err('dangling-ref', `mitigations[${i}].assumptionIds`, `assumption ${a} does not exist`)));
    checkEv(m.evidenceIds, `mitigations[${i}].evidenceIds`);
    checkEv(m.verification.evidenceIds, `mitigations[${i}].verification.evidenceIds`);
    if ((m.status === 'implemented' || m.status === 'verified') && !m.statusSetBy)
      issues.push(err('status-unattributed', `mitigations[${i}].statusSetBy`, `mitigation ${m.id} is ${m.status} but no person or import attested it`));
    if (m.status === 'verified' && m.verification.evidenceIds.length === 0)
      issues.push(err('verified-without-evidence', `mitigations[${i}].verification`, `mitigation ${m.id} is verified but cites no verification evidence`));
    if (m.status === 'verified') {
      const stale = m.verification.evidenceIds.filter((id) => model.evidence.find((e) => e.id === id)?.stale);
      if (stale.length) issues.push(warn('verification-stale', `mitigations[${i}].verification`, `verification evidence ${stale.join(', ')} is stale`));
    }
  });
  model.evidence.forEach((e, i) => {
    if (e.sourceId && !hasSrc(e.sourceId)) issues.push(err('dangling-ref', `evidence[${i}].sourceId`, `source ${e.sourceId} does not exist`));
    if (e.lineStart && e.lineEnd && e.lineEnd < e.lineStart) issues.push(err('bad-range', `evidence[${i}]`, 'lineEnd precedes lineStart'));
  });
  const provChecks: Array<[string, Array<{ id: string; provenance: { origin: string; actor?: string | undefined } }>]> = [
    ['elements', model.elements], ['flows', model.flows], ['boundaries', model.boundaries], ['assets', model.assets],
    ['assumptions', model.assumptions], ['threats', model.threats], ['mitigations', model.mitigations], ['evidence', model.evidence],
  ];
  for (const [name, items] of provChecks)
    items.forEach((it, i) => {
      if (it.provenance.origin === 'human' && !it.provenance.actor?.trim())
        issues.push(err('unattributed-human-input', `${name}[${i}].provenance`, `${it.id} is human-provided but names no author`));
    });
  model.reviewItems.forEach((r, i) => {
    if (!refExists(model, r.target) && r.status === 'open')
      issues.push(warn('review-target-missing', `reviewItems[${i}]`, `review target ${r.target.type} ${r.target.id} no longer exists`));
  });
  return issues;
}

export function validateModel(input: unknown): ValidationResult {
  const parsed = Model.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map((i) => err('schema', i.path.join('.') || '(root)', i.message)),
    };
  }
  const issues = checkIntegrity(parsed.data);
  return { ok: !issues.some((i) => i.severity === 'error'), model: parsed.data, issues };
}

export function assertValid(input: unknown): Model {
  const r = validateModel(input);
  if (!r.ok || !r.model) {
    const first = r.issues.filter((i) => i.severity === 'error').slice(0, 5).map((i) => `${i.path}: ${i.message}`);
    throw new ModelValidationError(`Model is invalid: ${first.join('; ')}`, r.issues);
  }
  return r.model;
}

export class ModelValidationError extends Error {
  constructor(message: string, public issues: Issue[]) {
    super(message);
    this.name = 'ModelValidationError';
  }
}
