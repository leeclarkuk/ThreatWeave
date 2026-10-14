/**
 * Builds the clearly labelled demonstration model: topology comes from scanning the example
 * repository, reasoning is written by hand ("Example author"). It is demonstration content.
 */
import { addEntity, clone, emptyModel, setMitigationStatus } from './ops.js';
import { syncSource } from './sync.js';
import type { SourceFileInput } from './extract.js';
import type { Model } from './model.js';
import { derivedId } from './util.js';

const AUTHOR = 'Example author';

export function buildNorthwindExample(filesV1: SourceFileInput[], revision: string): Model {
  let m = emptyModel('Northwind Shop (demonstration)', 'Fictional web shop used to demonstrate ThreatWeave. Not an analysis of any real system.');
  m.id = 'northwind-demo';
  m.example = true;
  m.systems[0]!.description = 'A fictional web shop: TLS-terminating web tier, an API, an internal inventory service, Postgres and Redis.';
  m = syncSource(m, filesV1, { label: 'northwind-v1', revision, actor: AUTHOR }).model;
  // The topology was scanned; the proposals/review items from the very first scan are not part of the demo baseline.
  m.proposals = [];
  m.reviewItems = [];
  m.runs = [];

  const key = (n: string) => `compose:docker-compose.yml:${n}`;
  const el = (n: string) => derivedId('element', key(n));
  const flow = (a: string, b: string) => derivedId('flow', `compose:docker-compose.yml:flow:${a}->${b}`);
  const net = (n: string) => derivedId('boundary', `compose:docker-compose.yml:net:${n}`);
  const blockEv = (n: string) => m.elements.find((e) => e.id === el(n))!.evidenceIds[0]!;
  const add = (type: Parameters<typeof addEntity>[1], input: Record<string, unknown>) => {
    const r = addEntity(m, type, input, AUTHOR);
    m = r.model;
    return r.id;
  };

  const aPII = add('asset', { name: 'Customer personal data', classification: 'confidential', description: 'Names, addresses and order history.', storedIn: [el('db')] });
  const aStock = add('asset', { name: 'Stock levels', classification: 'internal', description: 'Drives fulfilment decisions.', storedIn: [el('cache')] });
  m = clone(m);
  m.flows.find((f) => f.id === flow('api', 'db'))?.assetIds.push(aPII);
  m.flows.find((f) => f.id === flow('api', 'inventory'))?.assetIds.push(aStock);

  const a1 = add('assumption', {
    kind: 'assumption', text: 'The inventory service is only reachable from the backend network, so it does not need to authenticate its callers.',
    status: 'validated', rationale: 'compose file shows no published ports for inventory (see cited evidence).', basis: 'observed',
    relatesTo: [{ type: 'element', id: el('inventory') }, { type: 'boundary', id: net('backend') }], evidenceIds: [blockEv('inventory')],
  });
  const a2 = add('assumption', {
    kind: 'assumption', text: 'Only the web service is published to clients; everything else is internal.', status: 'open', basis: 'hypothesis',
    relatesTo: [{ type: 'boundary', id: net('backend') }],
  });
  add('assumption', { kind: 'question', text: 'Is the API rate limited per customer?', status: 'open', basis: 'hypothesis', relatesTo: [{ type: 'element', id: el('api') }] });

  const t1 = add('threat', {
    title: 'Unauthorised stock manipulation through the inventory service', source: 'attacker with a foothold on the backend network',
    preconditions: ['the inventory API accepts unauthenticated requests'], action: 'send stock adjustment requests directly to the inventory service',
    consequence: 'incorrect stock levels, leading to overselling or blocked sales', goals: ['integrity', 'availability'], stride: ['T', 'E'],
    targets: [{ type: 'element', id: el('inventory') }, { type: 'flow', id: flow('api', 'inventory') }],
    likelihood: { level: 'low', rationale: 'The service is not published and the backend network is not reachable from clients (assumption validated).' },
    impact: { level: 'medium', rationale: 'Stock counts drive fulfilment but orders can be reconciled.' },
    evidenceStrength: 'moderate', evidenceRationale: 'Network exposure observed in configuration; absence of service-level authentication is stated by the team, not observed.',
    basis: 'inferred', evidenceIds: [blockEv('inventory')],
  });
  const t2 = add('threat', {
    title: 'SQL injection through order search', source: 'external client', preconditions: ['user input reaches a query without parameterisation'],
    action: 'submit crafted search terms to the API', consequence: 'read or modification of customer and order data', goals: ['confidentiality', 'integrity'], stride: ['T', 'I'],
    targets: [{ type: 'element', id: el('api') }, { type: 'flow', id: flow('api', 'db') }, { type: 'asset', id: aPII }],
    likelihood: { level: 'medium', rationale: 'Search is public and takes free text.' }, impact: { level: 'high', rationale: 'Direct path to personal data.' },
    evidenceStrength: 'weak', evidenceRationale: 'No source code was analysed here; stated from design knowledge.', basis: 'hypothesis',
  });
  const t3 = add('threat', {
    title: 'Poisoned stock cache values', source: 'attacker with write access to the cache', preconditions: ['cache accepts unauthenticated writes'],
    action: 'overwrite cached stock levels', consequence: 'sales proceed on false stock data', goals: ['integrity'], stride: ['T'],
    targets: [{ type: 'element', id: el('cache') }, { type: 'asset', id: aStock }], likelihood: { level: 'unknown', rationale: '' }, impact: { level: 'medium', rationale: 'Same consequence as stock manipulation.' },
    evidenceStrength: 'none', basis: 'hypothesis',
  });
  void t3;

  const m1 = add('mitigation', {
    title: 'Keep inventory off published ports; reachable only on the backend network', description: 'No `ports:` entry for inventory; backend network is internal to the compose project.',
    status: 'planned', threatIds: [t1], assumptionIds: [a1], evidenceIds: [blockEv('inventory')],
    verification: { plan: ['From a host outside the compose network, confirm port 9000 is closed'], evidenceIds: [], note: '' },
  });
  m = setMitigationStatus(m, m1, 'implemented', { actor: AUTHOR }, { rationale: 'Observed in the compose file at the baseline revision.' });
  const evTls = add('evidence', { kind: 'test-result', summary: 'TLS scan of web tier showed TLS 1.2+ only (demonstration data)', provenance: { origin: 'human', actor: AUTHOR, at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') } });
  const m2 = add('mitigation', { title: 'Parameterised queries in the order search', description: '', status: 'planned', threatIds: [t2], evidenceIds: [] });
  m = setMitigationStatus(m, m2, 'in-progress', { actor: AUTHOR }, { rationale: 'Work started.' });
  void a2; void evTls;
  m.view.layout = {};
  return m;
}
