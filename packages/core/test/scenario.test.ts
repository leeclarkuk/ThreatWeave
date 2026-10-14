import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  acceptProposal, buildNorthwindExample, diffModels, extractTopology, redactSecrets, rejectProposal, resolveReviewItem,
  serialiseModel, syncSource, validateModel, setMitigationStatus, emptyModel, addEntity, type SourceFileInput, type Model,
} from '../src/index.js';

const read = (dir: string, f: string): SourceFileInput => {
  const content = readFileSync(new URL(`../../../examples/repos/${dir}/${f}`, import.meta.url), 'utf8');
  return { path: f, content, hash: createHash('sha256').update(content).digest('hex') };
};
const v1 = [read('northwind-v1', 'docker-compose.yml')];
const v2 = [read('northwind-v2', 'docker-compose.yml')];
const base = (): Model => buildNorthwindExample(v1, 'rev-v1');
const inv = (m: Model) => m.elements.find((e) => e.name === 'inventory')!;

describe('extraction', () => {
  it('derives components, exposure, boundaries and flows from compose with line evidence', () => {
    const ex = extractTopology(v1);
    expect(ex.elements.map((e) => e.name).sort()).toEqual(['External clients', 'api', 'cache', 'db', 'inventory', 'web']);
    expect(ex.elements.find((e) => e.name === 'web')!.exposure).toBe('external');
    expect(ex.elements.find((e) => e.name === 'inventory')!.exposure).toBe('internal');
    expect(ex.elements.find((e) => e.name === 'db')!.kind).toBe('datastore');
    expect(ex.flows.find((f) => f.label === 'INVENTORY_URL')!.encrypted).toBe('no'); // http:// is observed
    const ev = ex.elements.find((e) => e.name === 'web')!.evidence.find((e) => e.quote.includes('443:8443'))!;
    expect(ev.lineStart).toBeGreaterThan(1);
    expect(ex.boundaries.map((b) => b.name)).toContain('Compose network "backend"');
  });
  it('redacts secrets before they become evidence', () => {
    const ex = extractTopology(v1);
    const all = JSON.stringify(ex);
    expect(all).not.toContain('change-me');
    expect(redactSecrets('PASSWORD=hunter2\nOK=1').text).toBe('PASSWORD=[REDACTED]\nOK=1');
  });
  it('extracts kubernetes exposure from Service and flows from env URLs', () => {
    const content = readFileSync(new URL('../../../examples/repos/k8s-demo/manifests.yaml', import.meta.url), 'utf8');
    const ex = extractTopology([{ path: 'manifests.yaml', content, hash: 'x' }]);
    expect(ex.elements.find((e) => e.name === 'storefront')!.exposure).toBe('external');
    expect(ex.elements.find((e) => e.name === 'orders')!.exposure).toBe('internal');
    expect(ex.flows.some((f) => f.label === 'ORDERS_URL')).toBe(true);
  });
  it('reports unparseable and unrecognised files instead of guessing', () => {
    const ex = extractTopology([{ path: 'a.yml', content: 'a: [unclosed', hash: 'h' }, { path: 'b.yml', content: 'foo: bar', hash: 'h2' }]);
    expect(ex.files.map((f) => f.kind)).toEqual(['unparseable', 'unrecognised']);
  });
});

describe('example baseline', () => {
  it('is a valid, labelled demonstration model', () => {
    const m = base();
    const v = validateModel(m);
    expect(v.issues.filter((i) => i.severity === 'error')).toEqual([]);
    expect(m.example).toBe(true);
    expect(m.mitigations.find((x) => x.status === 'implemented')!.statusSetBy?.actor).toBe('Example author');
  });
});

describe('scenario: an internal service becomes externally reachable', () => {
  it('shows the changed element, the affected boundary and the resulting review proposals', () => {
    const before = base();
    const r = syncSource(before, v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    expect(inv(before).exposure).toBe('internal');
    expect(inv(r.model).exposure).toBe('external');
    expect(inv(r.model).properties['exposure.reason']).toContain('9000:9000');

    const change = r.changes.find((c) => c.kind === 'element-exposure-changed')!;
    expect(change.before).toBe('internal');
    expect(change.after).toBe('external');

    const flagged = (type: string, name: string) => r.reviewItems.filter((x) => x.target.type === type && x.reason.includes(name));
    // assumption, threat, mitigation and boundary all reached through explicit relationships
    expect(r.reviewItems.some((x) => x.target.type === 'assumption' && x.reason.includes('only reachable from the backend network'))).toBe(true);
    expect(r.reviewItems.some((x) => x.target.type === 'threat' && x.reason.includes('Unauthorised stock manipulation'))).toBe(true);
    expect(r.reviewItems.some((x) => x.target.type === 'mitigation' && x.reason.includes('Keep inventory off published ports'))).toBe(true);
    expect(r.reviewItems.some((x) => x.target.type === 'boundary' && x.reason.includes('backend'))).toBe(true);
    expect(flagged('flow', 'inventory').length).toBeGreaterThan(0);
    // every item explains itself with a trace back to the change
    for (const i of r.reviewItems) { expect(i.trace.length).toBeGreaterThan(0); expect(i.deterministic).toBe(true); }
    // unrelated entities are not flagged
    expect(r.reviewItems.some((x) => x.reason.includes('SQL injection'))).toBe(false);

    // stale evidence: the cited service block changed
    expect(r.model.evidence.some((e) => e.stale && e.path === 'docker-compose.yml')).toBe(true);

    // rule-pack proposals are pending hypotheses, labelled, and never accepted automatically
    expect(r.proposals.map((p) => p.payload.kind).sort()).toEqual(['add-mitigation', 'add-question', 'add-threat']);
    expect(r.proposals.every((p) => p.status === 'pending' && p.origin === 'pack-rule' && p.basis === 'hypothesis')).toBe(true);
    expect(r.model.threats.length).toBe(before.threats.length);
    expect(r.model.mitigations.find((m) => m.title.startsWith('Keep inventory'))!.status).toBe('implemented'); // not silently changed
    const v = validateModel(r.model);
    expect(v.issues.filter((i) => i.severity === 'error')).toEqual([]);
  });

  it('is idempotent and never reopens closed review items; decisions survive', () => {
    const first = syncSource(base(), v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    const item = first.reviewItems.find((i) => i.target.type === 'assumption')!;
    let m = resolveReviewItem(first.model, item.id, 'dismiss', 'Lee', 'Port is firewalled at the host; exposure is accepted for the debugging window.');
    const again = syncSource(m, v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    expect(again.reviewItems).toEqual([]);
    expect(again.proposals).toEqual([]);
    expect(again.model.reviewItems.find((r) => r.id === item.id)!.status).toBe('dismissed');
    expect(again.model.decisions.length).toBe(m.decisions.length);
  });

  it('keeps a rejected proposal rejected on re-analysis, and accepts one safely with edits', () => {
    const r = syncSource(base(), v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    const threat = r.proposals.find((p) => p.payload.kind === 'add-threat')!;
    const q = r.proposals.find((p) => p.payload.kind === 'add-question')!;
    const mit = r.proposals.find((p) => p.payload.kind === 'add-mitigation')!;
    let m = r.model;
    expect(() => acceptProposal(m, mit.id, { actor: 'Lee' })).toThrow(/Accept that proposal first/);
    m = rejectProposal(m, q.id, { actor: 'Lee', rationale: 'Already tracked elsewhere' });
    const payload = structuredClone(threat.payload) as any;
    payload.title = 'Unauthenticated access to inventory after port publication';
    m = acceptProposal(m, threat.id, { actor: 'Lee', rationale: 'Agreed', edited: payload });
    const created = m.threats.find((t) => t.title === payload.title)!;
    expect(created.provenance.origin).toBe('pack-rule');
    expect(created.basis).toBe('hypothesis');
    m = acceptProposal(m, mit.id, { actor: 'Lee' });
    const newMit = m.mitigations.find((x) => x.provenance.proposalId === mit.id)!;
    expect(newMit.status).toBe('proposed');           // a generated mitigation starts as a proposal
    expect(newMit.threatIds).toEqual([created.id]);   // dependency resolved to the accepted threat
    expect(validateModel(m).issues.filter((i) => i.severity === 'error')).toEqual([]);
    // re-analysis does not resurrect the rejected question or duplicate the accepted ones
    const again = syncSource(m, v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    expect(again.proposals).toEqual([]);
    expect(m.proposals.find((p) => p.id === q.id)!.status).toBe('rejected');
    expect(m.decisions.filter((d) => d.action === 'reject').length).toBe(1);
  });

  it('flags the removal of a component that threats and assumptions referenced', () => {
    const reduced = [{ ...v1[0]!, content: v1[0]!.content.replace(/  cache:\n    image: redis:7\n    networks: \[backend\]\n/, ''), hash: 'changed' }];
    const r = syncSource(base(), reduced, { label: 'northwind-v3', revision: 'rev-v3', actor: 'tester' });
    expect(r.changes.some((c) => c.kind === 'element-missing-from-source')).toBe(true);
    expect(r.reviewItems.some((i) => i.target.type === 'threat' && i.reason.includes('Poisoned stock cache'))).toBe(true);
  });

  it('respects a human override of source-derived exposure', () => {
    const b = base();
    const e = inv(b);
    e.properties['pin.exposure'] = 'human';
    const r = syncSource(b, v2, { label: 'northwind-v2', revision: 'rev-v2', actor: 'tester' });
    expect(inv(r.model).exposure).toBe('internal');
  });
});

describe('compare two model revisions', () => {
  it('diffs semantic changes only, ignoring layout and ordering', () => {
    const a = base();
    const b = structuredClone(a);
    b.view.layout = { x: { x: 1, y: 2 } };
    b.elements.reverse();
    expect(diffModels(a, b)).toEqual([]);
    inv(b).exposure = 'external';
    const kinds = diffModels(a, b).map((c) => c.kind);
    expect(kinds).toEqual(['element-exposure-changed']);
  });
});

describe('mitigation integrity rules', () => {
  it('cannot be implemented or verified without a named person, nor verified without evidence', () => {
    let m = emptyModel('t');
    m = addEntity(m, 'threat', { title: 'x', targets: [] }, 'Lee').model;
    const tid = m.threats[0]!.id;
    m = addEntity(m, 'mitigation', { title: 'y', threatIds: [tid] }, 'Lee').model;
    const mid = m.mitigations[0]!.id;
    expect(() => setMitigationStatus(m, mid, 'verified', { actor: 'Lee' })).toThrow(/verification evidence/);
    expect(() => setMitigationStatus(m, mid, 'implemented', { actor: ' ' })).toThrow(/named actor/);
    const forged = structuredClone(m);
    forged.mitigations[0]!.status = 'implemented';
    const v = validateModel(forged);
    expect(v.ok).toBe(false);
    expect(v.issues.some((i) => i.code === 'status-unattributed')).toBe(true);
  });
  it('shows verified-with-stale-evidence as needing re-verification', () => {
    const r = syncSource(base(), v2, { label: 'v2', revision: 'r2', actor: 't' });
    expect(r.model.evidence.some((e) => e.stale)).toBe(true);
  });
});

describe('serialisation of a synced model is stable', () => {
  it('byte-identical across repeated saves', () => {
    const m = base();
    const a = serialiseModel(validateModel(m).model!);
    const b = serialiseModel(validateModel(JSON.parse(a)).model!);
    expect(b).toBe(a);
  });
});
