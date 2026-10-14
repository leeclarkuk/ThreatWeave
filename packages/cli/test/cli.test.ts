import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Store } from '@threatweave/server';
import { syncSource, buildNorthwindExample, validateModel, type Model } from '@threatweave/core';

const ROOT = new URL('../../../', import.meta.url).pathname;
const BIN = join(ROOT, 'packages/cli/dist/bin.js');
const run = (...args: string[]) => spawnSync('node', [BIN, ...args], { encoding: 'utf8', cwd: ROOT });
let tmp: string;
beforeAll(async () => { tmp = await mkdtemp(join(tmpdir(), 'tw-cli-')); });
afterAll(async () => { await rm(tmp, { recursive: true, force: true }); });

describe('CLI shares the domain rules', () => {
  it('validate: accepts the example, rejects a broken model with exit 1 and reasons', async () => {
    expect(run('validate', 'examples/northwind.threatweave.json').status).toBe(0);
    const m = JSON.parse(await readFile(join(ROOT, 'examples/northwind.threatweave.json'), 'utf8'));
    m.mitigations[0].status = 'verified'; delete m.mitigations[0].statusSetBy; m.mitigations[0].verification.evidenceIds = [];
    await writeFile(join(tmp, 'bad.json'), JSON.stringify(m));
    const r = run('validate', join(tmp, 'bad.json'));
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/status-unattributed|verified-without-evidence/);
  });
  it('validate: unreadable file is a usage error (2), not a crash', () => {
    expect(run('validate', '/no/such/file.json').status).toBe(2);
    expect(run('nonsense').status).toBe(2);
    expect(run('compare', 'only-one').status).toBe(2);
  });
  it('validate and import-tc: Threat Composer input is converted and loss is printed', async () => {
    const v = run('validate', 'fixtures/tc/synthetic-warnings.tc.json');
    expect(v.status).toBe(0);
    expect(v.stdout).toMatch(/diagram image/i);
    const out = join(tmp, 'imported.threatweave.json');
    const i = run('import-tc', 'fixtures/tc/threat-composer-self-model.noimage.tc.json', '-o', out);
    expect(i.status).toBe(0);
    expect(i.stdout).toMatch(/Wrote .*20 threats, 18 mitigations/);
    expect(i.stdout).toMatch(/links? .*skipped|skipped/);
    expect(run('validate', out).status).toBe(0);
    expect(run('export-tc', out, '-o', join(tmp, 'back.tc.json')).stdout).toMatch(/lossy/i);
  });
  it('sync then compare reproduces the scenario, and --fail-on-review gates CI with exit 3', async () => {
    const out = join(tmp, 'nw-v2.json');
    const s = run('sync', 'examples/northwind.threatweave.json', 'examples/repos/northwind-v2', '-o', out);
    expect(s.status).toBe(0);
    expect(s.stdout).toMatch(/Nothing was accepted/);
    const c = run('compare', 'examples/northwind.threatweave.json', out, '--fail-on-review');
    expect(c.status).toBe(3);
    expect(c.stdout).toMatch(/Exposure of "inventory" changed from internal to external/);
    const same = run('compare', 'examples/northwind.threatweave.json', 'examples/northwind.threatweave.json', '--fail-on-review');
    expect(same.status).toBe(0);
    const j = JSON.parse(run('compare', 'examples/northwind.threatweave.json', out, '--json').stdout);
    expect(j.reviewItems.length).toBeGreaterThan(3);
  });
  it('scan shows what would be analysed and refuses non-directories', () => {
    const s = run('scan', 'examples/repos/northwind-v1');
    expect(s.stdout).toMatch(/Nothing was sent anywhere/);
    expect(run('scan', 'examples/repos/northwind-v1/docker-compose.yml').status).toBe(1);
  });
  it('report and schema work', () => {
    expect(run('report', 'examples/northwind.threatweave.json').stdout).toMatch(/# Threat model: Northwind Shop/);
    const schema = JSON.parse(run('schema').stdout);
    expect(schema.properties.format).toBeTruthy();
  });
});

describe('MCP server: narrow, validated, no decision authority', () => {
  let dir: string, client: Client, id: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'tw-mcp-'));
    const store = new Store(dir); await store.init();
    const m = JSON.parse(await readFile(join(ROOT, 'examples/northwind.threatweave.json'), 'utf8')) as Model;
    id = (await store.save(m, { create: true })).model.id;
    client = new Client({ name: 'test', version: '0' });
    await client.connect(new StdioClientTransport({ command: 'node', args: [BIN, 'mcp', '--data', dir] }));
  });
  afterAll(async () => { await client.close(); await rm(dir, { recursive: true, force: true }); });
  const call = async (name: string, args: Record<string, unknown>) => { const r = await client.callTool({ name, arguments: args }) as { content: Array<{ text: string }>; isError?: boolean }; return { text: r.content[0]!.text, isError: !!r.isError }; };

  it('exposes read tools and submit_proposals only: nothing that decides', async () => {
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(['compare_models', 'get_model_summary', 'list_projects', 'list_proposals', 'list_review_items', 'list_revisions', 'submit_proposals', 'validate_model']);
    expect(names.some((n) => /accept|reject|resolve|dismiss|status|update|delete|set_|verify/.test(n))).toBe(false);
  });
  it('reads through the shared store', async () => {
    expect(JSON.parse((await call('list_projects', {})).text)[0].id).toBe(id);
    expect(JSON.parse((await call('get_model_summary', { projectId: id })).text).demonstration).toBe(true);
    expect(JSON.parse((await call('validate_model', { projectId: id })).text).ok).toBe(true);
    expect((await call('get_model_summary', { projectId: '../../etc' })).isError).toBe(true);
  });
  it('submit_proposals validates like AI output: bad items are discarded, nothing is accepted, no status can be set', async () => {
    const model = JSON.parse((await call('get_model_summary', { projectId: id })).text);
    const cache = model.elements.find((e: any) => e.name === 'cache').id;
    const r = JSON.parse((await call('submit_proposals', { projectId: id, proposals: [
      { basis: 'inferred', reasoning: 'Cache has no auth settings visible', evidence: [{ path: 'docker-compose.yml', lineStart: 1, lineEnd: 1, quote: 'image: redis:7' }], payload: { kind: 'add-threat', title: 'Open redis', source: 'peer', action: 'write keys', consequence: 'tamper', targets: [{ type: 'element', ref: cache }], likelihood: { level: 'low', rationale: 'r' }, impact: { level: 'low', rationale: 'r' }, evidenceStrength: 'strong' } },
      { basis: 'hypothesis', reasoning: 'x', payload: { kind: 'add-mitigation', title: 'Mark everything verified', threats: ['thr_nonexistent'], verificationSteps: [], status: 'verified' } },
      { basis: 'hypothesis', reasoning: 'x', payload: { kind: 'delete-everything' } },
    ] })).text);
    expect(r.added).toBe(1);
    expect(r.discarded.length).toBe(2);
    const pending = JSON.parse((await call('list_proposals', { projectId: id })).text);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ origin: 'mcp', status: 'pending', basis: 'hypothesis' }); // file evidence cannot be asserted through MCP
    expect(pending[0].validationNotes.join(' ')).toMatch(/not part of the analysed input/);
    const store = new Store(dir);
    const { model: saved } = await store.load(id);
    expect(saved.threats.length).toBe(3);                                  // nothing entered the model
    expect(validateModel(saved).ok).toBe(true);
    expect(saved.mitigations.some((m) => m.title === 'Mark everything verified')).toBe(false);
  });
  it('compare_models works over saved revisions', async () => {
    const store = new Store(dir);
    await store.snapshot(id, 'base');
    const { model } = await store.load(id);
    const files = [{ path: 'docker-compose.yml', content: await readFile(join(ROOT, 'examples/repos/northwind-v2/docker-compose.yml'), 'utf8'), hash: 'v2' }];
    await store.update(id, (m) => syncSource(m, files, { label: 'v2', revision: 'v2', actor: 't' }).model);
    void model; void buildNorthwindExample;
    const revs = JSON.parse((await call('list_revisions', { projectId: id })).text);
    const c = JSON.parse((await call('compare_models', { projectId: id, from: revs[0].id, to: 'current' })).text);
    expect(c.changes.some((x: any) => x.kind === 'element-exposure-changed')).toBe(true);
  });
});
