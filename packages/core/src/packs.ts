/**
 * Built-in generic rule pack ("generic-1"). Rules fire on explicit model facts or changes and
 * produce PROPOSALS (hypotheses awaiting a human decision), never accepted content.
 * They are templates: each proposal states which rule fired and why, so it cannot
 * pass as a system-specific finding. Provider-specific knowledge belongs in optional packs.
 */
import type { Model, Proposal, ProposalPayload } from './model.js';
import type { Change } from './diff.js';
import { labelOf } from './ops.js';
import { nowIso, shortHash, newEventId, slug } from './util.js';

export const PACK_ID = 'generic-1';

export function fingerprintPayload(p: ProposalPayload, model?: Model): string {
  const n = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  switch (p.kind) {
    case 'add-element': return shortHash(`el|${p.elementKind}|${n(p.name)}`);
    case 'add-flow': return shortHash(`fl|${n(p.from)}|${n(p.to)}|${n(p.label)}`);
    case 'add-boundary': return shortHash(`tb|${n(p.name)}`);
    case 'add-asset': return shortHash(`as|${n(p.name)}`);
    case 'add-threat': return shortHash(`th|${n(p.title)}|${p.targets.map((t) => t.ref).sort().join(',')}`);
    case 'add-mitigation': return shortHash(`mi|${n(p.title)}|${p.threats.slice().sort().join(',')}`);
    case 'add-assumption': return shortHash(`am|${n(p.text)}`);
    case 'add-question': return shortHash(`qu|${n(p.text)}`);
  }
  void model;
}

type Draft = Omit<Proposal, 'id' | 'createdAt' | 'fingerprint' | 'status' | 'validationNotes' | 'evidence' | 'missingInformation'> & { evidence?: Proposal['evidence']; missingInformation?: string[] };

function mk(d: Draft): Proposal {
  return {
    ...d, id: newEventId('proposal'), evidence: d.evidence ?? [], missingInformation: d.missingInformation ?? [], fingerprint: fingerprintPayload(d.payload),
    status: 'pending', validationNotes: [], createdAt: nowIso(),
  };
}

/** Rules that depend on a change. */
export function packProposals(model: Model, changes: Change[]): Proposal[] {
  const out: Proposal[] = [];
  const evOf = (elId: string) => model.elements.find((e) => e.id === elId)?.evidenceIds ?? [];
  for (const c of changes) {
    if (!((c.kind === 'element-exposure-changed' && c.after === 'external' && c.before !== 'external') || (c.kind === 'element-added' && c.after === 'external'))) continue;
    const el = model.elements.find((e) => e.id === c.entity.id);
    if (!el || el.kind === 'actor') continue;
    const key = `${PACK_ID}:${slug(el.name)}`;
    const trigger = `Rule ${PACK_ID}/exposure-increased: ${c.summary}`;
    const tkey = `${key}:t1`;
    const srcEv = model.evidence.filter((e) => evOf(el.id).includes(e.id) && e.path).map((e) => ({ path: e.path!, lineStart: e.lineStart ?? 1, lineEnd: e.lineEnd ?? 1, quote: e.quote ?? '', verified: !e.stale }));
    out.push(mk({
      key: tkey, origin: 'pack-rule', trigger, basis: 'hypothesis', evidence: srcEv.filter((e) => e.quote),
      reasoning: `Template threat from rule ${PACK_ID}/exposure-increased. "${el.name}" is now externally reachable (${el.properties['exposure.reason'] ?? 'exposure set to external'}), and components first built for internal callers commonly rely on network position instead of authenticating callers. Whether that applies here is NOT known from configuration: it is a hypothesis to validate.`,
      missingInformation: [`Does "${el.name}" authenticate and authorise every caller itself?`, 'Who or what can actually reach the published endpoint (internet, VPN, office network)?'],
      payload: {
        kind: 'add-threat', title: `Unauthenticated access to newly exposed ${el.name}`, source: 'external actor with network access to the newly reachable endpoint',
        preconditions: [`"${el.name}" is reachable from outside its previous trust perimeter`, 'the service does not enforce its own authentication or authorisation'],
        action: `call ${el.name}'s interface directly, bypassing the components that used to front it`, consequence: 'unauthorised reads or changes to the data and functions it exposes',
        goals: ['confidentiality', 'integrity'], stride: ['S', 'E', 'I'], targets: [{ type: 'element', ref: el.id }],
        likelihood: { level: 'unknown', rationale: 'Depends on whether the service authenticates callers, which the configuration does not show.' },
        impact: { level: 'unknown', rationale: 'Depends on what the service can read or change; judge against the assets it handles.' },
        evidenceStrength: srcEv.length ? 'moderate' : 'weak',
      },
    }));
    out.push(mk({
      key: `${key}:q1`, origin: 'pack-rule', trigger, basis: 'hypothesis',
      reasoning: `Raised by rule ${PACK_ID}/exposure-increased so the open point is recorded rather than assumed away.`,
      payload: { kind: 'add-question', text: `Is the change that makes "${el.name}" externally reachable intentional, and is there a hardening and monitoring plan for it?`, relatesTo: [{ type: 'element', ref: el.id }] },
    }));
    out.push(mk({
      key: `${key}:m1`, origin: 'pack-rule', trigger, basis: 'hypothesis',
      reasoning: `Candidate control for the template threat above. It starts as a proposal; only a person can mark it implemented or verified.`,
      payload: {
        kind: 'add-mitigation', title: `Remove or restrict the published endpoint for ${el.name}`,
        description: 'Prefer not publishing the port at all. If it must be reachable, bind to loopback or a private interface, restrict by firewall or network policy, and require authentication at the service.',
        threats: [tkey], verificationSteps: [`From outside the intended network, attempt to connect to ${el.name}'s published port and confirm it is refused`, `Confirm unauthenticated requests to ${el.name} are rejected where it must stay reachable`],
      },
    }));
  }
  return out;
}

/** Rules that look at facts currently in the model. Used for the offline "suggest from pack" action. */
export function packProposalsForModel(model: Model): Proposal[] {
  const out: Proposal[] = [];
  for (const el of model.elements) {
    if (el.kind === 'datastore' && el.exposure === 'external')
      out.push(mk({
        key: `${PACK_ID}:${slug(el.name)}:ds`, origin: 'pack-rule', basis: 'hypothesis', trigger: `Rule ${PACK_ID}/datastore-exposed: "${el.name}" is a datastore marked externally reachable.`,
        reasoning: `Template threat from rule ${PACK_ID}/datastore-exposed. Datastores are normally reachable only from their application tier; exposure ("${el.properties['exposure.reason'] ?? 'external'}") widens who can attempt direct access. Unknown whether authentication or network filtering applies.`,
        missingInformation: ['Is authentication enforced and are credentials strong and rotated?', 'Is the port filtered at the host or network level?'],
        payload: { kind: 'add-threat', title: `Direct access to exposed datastore ${el.name}`, source: 'external actor', preconditions: [`"${el.name}" accepts connections from outside the application tier`, 'weak, default or absent credentials'], action: `connect to ${el.name} directly and read or modify data`, consequence: 'loss of confidentiality or integrity of stored data', goals: ['confidentiality', 'integrity'], stride: ['I', 'T'], targets: [{ type: 'element', ref: el.id }], likelihood: { level: 'unknown', rationale: 'Unknown until authentication and filtering are confirmed.' }, impact: { level: 'unknown', rationale: 'Depends on the data stored; see assets.' }, evidenceStrength: 'weak' },
      }));
    if (el.tags.includes('privileged') || el.tags.includes('docker-socket'))
      out.push(mk({
        key: `${PACK_ID}:${slug(el.name)}:priv`, origin: 'pack-rule', basis: 'inferred', trigger: `Rule ${PACK_ID}/privileged-container: "${el.name}" is tagged ${el.tags.filter((t) => t === 'privileged' || t === 'docker-socket').join(', ')}.`,
        reasoning: `Template threat from rule ${PACK_ID}/privileged-container. The source configuration grants "${el.name}" elevated host access, so compromising it may compromise the host.`,
        payload: { kind: 'add-threat', title: `Host compromise through elevated container privileges on ${el.name}`, source: 'attacker who gains code execution in the container', preconditions: ['a vulnerability or misconfiguration lets the attacker run code in the container'], action: 'use the privileged mode or mounted socket to act on the host or other containers', consequence: 'escape from the container boundary to the host', goals: ['confidentiality', 'integrity', 'availability'], stride: ['E'], targets: [{ type: 'element', ref: el.id }], likelihood: { level: 'unknown', rationale: 'Requires a first foothold in the container, which is not assessed here.' }, impact: { level: 'high', rationale: 'Host-level control follows if the escape works.' }, evidenceStrength: 'moderate' },
      }));
  }
  for (const f of model.flows) {
    const from = model.elements.find((e) => e.id === f.from), to = model.elements.find((e) => e.id === f.to);
    if (!from || !to || f.encrypted !== 'no') continue;
    const fb = model.boundaries.filter((b) => b.memberIds.includes(f.from)).map((b) => b.id);
    const tb = model.boundaries.filter((b) => b.memberIds.includes(f.to)).map((b) => b.id);
    const crosses = fb.some((b) => !tb.includes(b)) || tb.some((b) => !fb.includes(b));
    if (!crosses && from.exposure !== 'external') continue;
    out.push(mk({
      key: `${PACK_ID}:${f.id}:enc`, origin: 'pack-rule', basis: 'inferred', trigger: `Rule ${PACK_ID}/cleartext-crossing-flow: ${labelOf(model, { type: 'flow', id: f.id })} is recorded as unencrypted and crosses a boundary or starts outside.`,
      reasoning: `Template threat from rule ${PACK_ID}/cleartext-crossing-flow. The flow is recorded as not encrypted (${f.protocol || 'protocol not recorded'}) and either crosses a trust boundary or originates from an externally reachable element.`,
      payload: { kind: 'add-threat', title: `Interception or tampering of ${from.name} to ${to.name} traffic`, source: 'attacker with a network position between the endpoints', preconditions: ['traffic is not encrypted or integrity protected'], action: 'observe or modify messages in transit', consequence: 'disclosure or alteration of the data this flow carries', goals: ['confidentiality', 'integrity'], stride: ['I', 'T'], targets: [{ type: 'flow', ref: f.id }], likelihood: { level: 'unknown', rationale: 'Depends on the network path and who can reach it.' }, impact: { level: 'unknown', rationale: 'Depends on the data carried.' }, evidenceStrength: 'moderate' },
    }));
  }
  return out;
}

/** Add proposals unless an equivalent one was already seen. Decisions survive: rejected stays rejected. */
export function mergeProposals(model: Model, incoming: Proposal[]): { model: Model; added: Proposal[]; skipped: Array<{ proposal: Proposal; reason: string }> } {
  const next = structuredClone(model);
  const known = new Map(next.proposals.map((p) => [p.fingerprint, p]));
  const entityFps = new Set<string>();
  for (const t of next.threats) entityFps.add(fingerprintPayload({ kind: 'add-threat', title: t.title, source: '', preconditions: [], action: '', consequence: '', goals: [], stride: [], targets: t.targets.map((r) => ({ type: r.type, ref: r.id })), likelihood: { level: 'unknown', rationale: '' }, impact: { level: 'unknown', rationale: '' }, evidenceStrength: 'none' }));
  const added: Proposal[] = [];
  const skipped: Array<{ proposal: Proposal; reason: string }> = [];
  for (const p of incoming) {
    const prior = known.get(p.fingerprint);
    if (prior) { skipped.push({ proposal: p, reason: prior.status === 'rejected' ? 'previously rejected by a person' : prior.status === 'accepted' ? 'already accepted' : 'already pending' }); continue; }
    if (p.payload.kind === 'add-threat' && entityFps.has(p.fingerprint)) { skipped.push({ proposal: p, reason: 'matches an existing threat' }); continue; }
    if (p.payload.kind === 'add-threat' && similarThreatExists(next, p.payload)) { skipped.push({ proposal: p, reason: 'similar to an existing threat on the same target' }); continue; }
    known.set(p.fingerprint, p);
    added.push(p);
  }
  next.proposals.push(...added);
  return { model: next, added, skipped };
}

const tokens = (s: string) => new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2));
function jaccard(a: Set<string>, b: Set<string>) {
  let i = 0;
  for (const x of a) if (b.has(x)) i++;
  return i / Math.max(1, a.size + b.size - i);
}
/** Same target and a near-identical title: treat as a duplicate rather than a new threat. */
export function similarThreatExists(model: Model, p: Extract<ProposalPayload, { kind: 'add-threat' }>): boolean {
  const pt = tokens(p.title);
  const refs = new Set(p.targets.map((t) => t.ref));
  return model.threats.some((t) => t.targets.some((r) => refs.has(r.id)) && jaccard(tokens(t.title), pt) >= 0.7);
}
