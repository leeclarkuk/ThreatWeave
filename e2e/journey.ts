/**
 * End-to-end verification in a real browser against a real server process.
 * Run: npm run build && npm run e2e
 * Needs Chromium: set CHROMIUM_PATH, or it looks in PLAYWRIGHT_BROWSERS_PATH.
 * The AI steps use a SIMULATED provider server (packages/ai/test/mock-server.ts). They are not live evidence.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium, type Page, type Browser } from 'playwright-core';
import { startMock, json, openaiOk } from '../packages/ai/test/mock-server.js';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const SHOTS = join(ROOT, 'docs/screenshots');
mkdirSync(SHOTS, { recursive: true });
const PORT = 4400 + Math.floor(Math.random() * 400);
const BASE = `http://localhost:${PORT}`;

function chromePath(): string {
  const cands = [process.env.CHROMIUM_PATH, ...(process.env.PLAYWRIGHT_BROWSERS_PATH ? readdirSync(process.env.PLAYWRIGHT_BROWSERS_PATH).filter((d) => d.startsWith('chromium-')).map((d) => join(process.env.PLAYWRIGHT_BROWSERS_PATH!, d, 'chrome-linux/chrome')) : []), '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'].filter(Boolean) as string[];
  const hit = cands.find((c) => existsSync(c));
  if (!hit) throw new Error('No Chromium found. Set CHROMIUM_PATH.');
  return hit;
}

let proc: ChildProcess | undefined;
async function startApp(data: string) {
  proc = spawn('node', [join(ROOT, 'packages/cli/dist/bin.js'), 'serve', '--port', String(PORT), '--data', data], { stdio: 'ignore', env: { ...process.env, ANTHROPIC_API_KEY: '', THREATWEAVE_ANTHROPIC_API_KEY: '' } });
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(`${BASE}/api/health`); if (r.ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('server did not start');
}
async function stopApp() { proc?.kill('SIGTERM'); await new Promise((r) => setTimeout(r, 300)); }

let cleanupPage: Page | undefined;
let currentStep = 'start';
const results: Array<{ step: string; ok: boolean; note?: string }> = [];
async function step(name: string, fn: () => Promise<string | void>) {
  currentStep = name;
  try { const note = await fn(); results.push({ step: name, ok: true, ...(note ? { note } : {}) }); console.log(`PASS  ${name}${note ? `  (${note})` : ''}`); }
  catch (e) {
    results.push({ step: name, ok: false, note: (e as Error).message.split('\n')[0] }); console.log(`FAIL  ${name}\n      ${(e as Error).message.split('\n').slice(0, 4).join('\n      ')}`);
    // keep one failure from cascading: close any open dialog and keep a screenshot for diagnosis
    try { await cleanupPage?.screenshot({ path: join(SHOTS, `fail-${name.slice(0, 2)}.png`) }); await cleanupPage?.keyboard.press('Escape'); } catch { /* ignore */ }
  }
}
const eq = (a: unknown, b: unknown, what: string) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
const ok = (c: unknown, what: string) => { if (!c) throw new Error(`expected: ${what}`); };
const shot = (p: Page, n: string) => p.screenshot({ path: join(SHOTS, `${n}.png`) });
const model = async (id: string) => (await (await fetch(`${BASE}/api/projects/${id}`)).json()).model;
const projectId = (p: Page) => /#\/p\/([a-z0-9-]+)/.exec(p.url())![1]!;
async function waitSaved(p: Page) { await p.waitForFunction(() => /Saved/.test(document.querySelector('.savestate')?.textContent ?? ''), null, { timeout: 8000 }); }
const nav = (p: Page, name: string) => p.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name: new RegExp(`^${name}`) }).click();

async function main() {
  const data = await mkdtemp(join(tmpdir(), 'tw-e2e-'));
  await startApp(data);
  const browser: Browser = await chromium.launch({ executablePath: chromePath(), args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  cleanupPage = page;
  page.setDefaultTimeout(10000);
  const pageErrors: string[] = [];
  page.on('pageerror', (e) => pageErrors.push(`[${currentStep}] ${e.message}`));
  page.on('dialog', (d) => void d.accept());
  const mockOffline: string[] = [];
  // Manual modelling must make no requests beyond our own origin.
  page.on('request', (r) => { const u = new URL(r.url()); if (u.origin !== BASE && !u.protocol.startsWith('data')) mockOffline.push(r.url()); });

  /* ---------- A. keyboard-only start ---------- */
  await page.goto(BASE);
  await step('A1 keyboard only: Tab to the name field, create a model with Enter, no AI credentials', async () => {
    for (let i = 0; i < 25; i++) { await page.keyboard.press('Tab'); if (await page.evaluate(() => (document.activeElement as HTMLInputElement | null)?.placeholder?.startsWith('e.g. Payments'))) break; }
    ok(await page.evaluate(() => (document.activeElement as HTMLInputElement | null)?.placeholder?.startsWith('e.g. Payments')), 'reached the System name field using Tab only');
    const outline = await page.evaluate(() => getComputedStyle(document.activeElement!).outlineStyle);
    ok(outline !== 'none', `visible focus outline on focused field (got ${outline})`);
    await page.keyboard.type('Orders platform');
    await page.keyboard.press('Tab'); // commits on blur
    await page.keyboard.press('Enter'); // "Create and start modelling" button
    await page.waitForURL(/#\/p\//);
    await page.getByRole('heading', { name: 'Draw the system first' }).waitFor();
  });
  const id = projectId(page);
  await step('A2 keyboard only: switch section (Alt+2), focus the add field with "/", add a threat with Enter', async () => {
    await page.keyboard.press('Alt+2');
    await page.getByRole('heading', { name: 'Threats', level: 1 }).waitFor();
    await page.keyboard.press('/');
    await page.keyboard.type('Forged order callbacks');
    await page.keyboard.press('Enter');
    await page.getByRole('heading', { name: 'Threat', exact: true }).waitFor();
    await waitSaved(page);
    eq((await model(id)).threats.map((t: any) => t.title), ['Forged order callbacks'], 'threat saved');
  });

  /* ---------- B. architecture editing ---------- */
  await nav(page, 'Architecture');
  await step('B1 add components on the canvas, rename them in the inspector', async () => {
    await page.getByRole('button', { name: '＋ Service' }).click();
    const rename = async (n: string) => { const f = page.getByLabel(/^Name/).first(); await f.fill(n); await f.press('Enter'); };
    await rename('Storefront');
    await page.getByRole('button', { name: '＋ Service' }).click(); await rename('Orders API');
    await page.getByRole('button', { name: '＋ Data store' }).click(); await rename('Orders DB');
    await page.getByRole('button', { name: '＋ Actor' }).click(); await rename('Customer');
    await waitSaved(page);
    eq((await model(id)).elements.map((e: any) => e.name).sort(), ['Customer', 'Orders API', 'Orders DB', 'Storefront'], 'elements');
  });
  await step('B2 draw a data flow by dragging between handles (canvas)', async () => {
    await page.getByRole('button', { name: 'Auto-arrange' }).click();
    await page.waitForTimeout(500);
    const box = async (name: string) => { const n = page.locator('.react-flow__node').filter({ hasText: name }).first(); return n.boundingBox(); };
    const a = (await box('Customer'))!, b = (await box('Storefront'))!;
    const from = page.locator('.react-flow__node').filter({ hasText: 'Customer' }).locator('.react-flow__handle.source').first();
    const to = page.locator('.react-flow__node').filter({ hasText: 'Storefront' }).locator('.react-flow__handle.target').first();
    const fb = (await from.boundingBox())!, tb = (await to.boundingBox())!;
    await page.mouse.move(fb.x + fb.width / 2, fb.y + fb.height / 2);
    await page.mouse.down();
    await page.mouse.move(tb.x + tb.width / 2 - 20, tb.y + tb.height / 2, { steps: 12 });
    await page.mouse.move(tb.x + tb.width / 2, tb.y + tb.height / 2, { steps: 4 });
    await page.mouse.up();
    await page.waitForTimeout(600);
    await waitSaved(page);
    const m = await model(id);
    if (m.flows.length !== 1) await shot(page, 'fail-B2-drag');
    eq(m.flows.length, 1, 'one flow created');
    void a; void b;
  });
  await step('B3 the table view offers the same operations without a pointer: add flow, add boundary, set membership', async () => {
    await page.getByRole('button', { name: 'Table', exact: true }).click();
    const flows = page.getByRole('region', { name: 'Data flows' });
    await flows.getByLabel('From').selectOption({ label: 'Storefront' });
    await flows.getByLabel('To', { exact: true }).selectOption({ label: 'Orders API' });
    await flows.getByRole('button', { name: 'Add flow' }).click();
    await flows.getByLabel('From').selectOption({ label: 'Orders API' });
    await flows.getByLabel('To', { exact: true }).selectOption({ label: 'Orders DB' });
    await flows.getByRole('button', { name: 'Add flow' }).click();
    await page.getByLabel('New boundary name').fill('Internal network'); await page.getByLabel('New boundary name').press('Enter');
    await page.getByRole('heading', { name: /Trust boundary: Internal network/ }).waitFor();
    for (const n of ['Orders API', 'Orders DB']) await page.getByRole('checkbox', { name: n }).check();
    await page.getByLabel('Trust inside').selectOption('trusted');
    await waitSaved(page);
    const m = await model(id);
    eq(m.flows.length, 3, 'flows'); eq(m.boundaries[0].memberIds.length, 2, 'boundary members'); eq(m.boundaries[0].trust, 'trusted', 'trust');
    await shot(page, '10-architecture-table');
  });
  await step('B4 set exposure and flow properties; relationships stay consistent', async () => {
    await page.getByRole('region', { name: 'Components' }).getByRole('button', { name: 'Storefront', exact: true }).click();
    await page.getByLabel('Reachability').selectOption('external');
    await page.getByRole('button', { name: 'Canvas' }).click();
    await page.waitForSelector('.react-flow__node');
    await waitSaved(page);
    const m = await model(id);
    eq(m.elements.find((e: any) => e.name === 'Storefront').exposure, 'external', 'exposure');
    ok(m.flows.every((f: any) => m.elements.some((e: any) => e.id === f.from) && m.elements.some((e: any) => e.id === f.to)), 'flow endpoints exist');
    await page.waitForTimeout(400);
    await shot(page, '11-architecture-canvas');
  });

  await step('B5 add a trust boundary from the canvas toolbar (no table needed)', async () => {
    await page.getByRole('button', { name: '＋ Boundary' }).click();
    const dlg = page.getByRole('dialog', { name: 'New trust boundary' });
    await dlg.getByLabel(/^Name/).fill('DMZ');
    await dlg.getByRole('button', { name: 'Add boundary' }).click();
    await page.getByRole('heading', { name: /Trust boundary: DMZ/ }).waitFor();
    await page.getByRole('checkbox', { name: 'Storefront' }).check();
    await waitSaved(page);
    const m = await model(id);
    eq(m.boundaries.map((b: any) => b.name).sort(), ['DMZ', 'Internal network'], 'boundaries');
    ok(m.boundaries.find((b: any) => b.name === 'DMZ').memberIds.length === 1, 'membership set from the inspector');
  });

  /* ---------- C. reasoning: threats, assumptions, mitigations ---------- */
  await step('C1 complete a threat: statement fields, targets from the shared model, judgement with reasons', async () => {
    await nav(page, 'Threats');
    await page.getByRole('button', { name: 'Forged order callbacks' }).click();
    await page.getByLabel('Who or what (actor or source)').fill('attacker on the internet'); await page.getByLabel('Who or what (actor or source)').blur();
    await page.getByLabel('Action (what they could do)').fill('post forged callbacks to the API'); await page.getByLabel('Action (what they could do)').blur();
    await page.getByLabel('Consequence').fill('orders marked as paid without payment'); await page.getByLabel('Consequence').blur();
    await page.getByLabel('Add to Affects').selectOption({ label: 'Orders API' });
    await page.getByLabel('Likelihood', { exact: true }).selectOption('medium');
    await page.getByLabel('Why this likelihood').fill('Endpoint is public and the payload format is documented'); await page.getByLabel('Why this likelihood').blur();
    await page.getByLabel('Evidence strength').selectOption('weak');
    await waitSaved(page);
    const t = (await model(id)).threats[0];
    eq(t.targets.length, 1, 'target linked'); eq(t.likelihood.level, 'medium', 'likelihood'); eq(t.evidenceStrength, 'weak', 'evidence strength separate from severity'); eq(t.impact.level, 'unknown', 'impact untouched');
  });
  await step('C2 add a mitigation from the threat; implemented and verified need attestation and evidence', async () => {
    await page.getByRole('button', { name: /New mitigation/ }).click();
    await page.getByLabel(/What would reduce this threat/).fill('Verify callback signatures'); await page.getByRole('button', { name: 'Add as planned' }).click();
    await page.getByRole('heading', { name: 'Mitigation', exact: true }).waitFor();
    // implemented: rationale required
    await page.getByLabel('Actual implementation status').selectOption('implemented');
    const confirmBtn = page.getByRole('button', { name: 'I confirm' });
    ok(await confirmBtn.isDisabled(), 'confirm disabled until a rationale is given');
    await page.getByLabel(/Where is it implemented/).fill('callbacks/verify.ts checks the HMAC');
    await confirmBtn.click();
    await waitSaved(page);
    let m = (await model(id)).mitigations[0];
    eq(m.status, 'implemented', 'status'); eq(m.statusSetBy.actor, 'local-user', 'attested by a named person');
    // verified: needs evidence
    await page.getByLabel('Actual implementation status').selectOption('verified');
    const rec = page.getByRole('button', { name: 'Record as verified' });
    ok(await rec.isDisabled(), 'cannot record verified with no evidence');
    await page.getByLabel(/New evidence: what was checked/).fill('Integration test callbacks.spec.ts rejects an unsigned body (CI run 1423)');
    await page.getByLabel(/^Rationale/).fill('Test added and passing'); await page.getByLabel(/^Rationale/).blur();
    await rec.click();
    await waitSaved(page);
    m = (await model(id)).mitigations[0];
    eq(m.status, 'verified', 'verified'); eq(m.verification.evidenceIds.length, 1, 'evidence attached');
    const ev = (await model(id)).evidence.find((e: any) => e.id === m.verification.evidenceIds[0]);
    eq(ev.provenance.origin, 'human', 'evidence attributed to a person'); ok(ev.provenance.actor, 'evidence has an author');
    await shot(page, '12-mitigation-verified');
  });
  await step('C3 assumptions and questions link to model elements', async () => {
    await nav(page, 'Assumptions');
    await page.getByLabel('Add assumption').fill('Callbacks only arrive from the payment provider IP range'); await page.getByLabel('Add assumption').press('Enter');
    await page.getByLabel('Add to Relates to').selectOption({ label: 'Orders API' });
    await waitSaved(page);
    const a = (await model(id)).assumptions[0];
    eq(a.relatesTo.length, 1, 'linked'); eq(a.status, 'open', 'starts unvalidated');
  });
  await step('C4 undo and redo reverse a core edit', async () => {
    await nav(page, 'Mitigations');
    await page.getByRole('button', { name: 'Verify callback signatures' }).click();
    await page.getByLabel('Title').fill('Verify callback signatures (HMAC)'); await page.getByLabel('Title').press('Enter');
    await page.getByRole('button', { name: 'Undo', exact: true }).click(); await waitSaved(page);
    eq((await model(id)).mitigations[0].title, 'Verify callback signatures', 'undo restored title');
    await page.getByRole('button', { name: 'Redo', exact: true }).click(); await waitSaved(page);
    eq((await model(id)).mitigations[0].title, 'Verify callback signatures (HMAC)', 'redo reapplied');
  });

  /* ---------- D. persistence ---------- */
  await step('D1 data survives a page reload and a server restart', async () => {
    const before = JSON.stringify((await model(id)).elements.map((e: any) => e.id).sort());
    await page.reload(); await page.getByRole('navigation', { name: 'Sections' }).waitFor();
    await stopApp(); await startApp(data);
    await page.reload(); await page.getByRole('navigation', { name: 'Sections' }).waitFor();
    eq(JSON.stringify((await model(id)).elements.map((e: any) => e.id).sort()), before, 'element ids stable across restart');
    await nav(page, 'Threats');
    await page.getByRole('button', { name: 'Forged order callbacks' }).waitFor();
  });
  await step('D2 saved file is deterministic: reloading and saving again changes nothing', async () => {
    const f = join(data, 'projects', id, 'model.json');
    const a = readFileSync(f, 'utf8');
    await page.getByRole('button', { name: 'Forged order callbacks' }).click();
    await page.waitForTimeout(700);
    eq(readFileSync(f, 'utf8'), a, 'file unchanged by a no-op session');
    ok(a.endsWith('\n') && a.indexOf('"elements"') < a.indexOf('"threats"'), 'stable key order');
  });

  await step('D3 a damaged project file is shown (not hidden) and can be restored from its backup', async () => {
    const f = join(data, 'projects', id, 'model.json');
    const good = readFileSync(f, 'utf8');
    ok(existsSync(f + '.bak'), 'a backup of the previous version exists');
    writeFileSync(f, good.slice(0, 40)); // a torn write by some other tool
    await page.goto(BASE);
    await page.getByText(/cannot be opened/i).first().waitFor();
    ok(await page.getByText(/valid backup of the previous version exists/i).isVisible(), 'recovery is explained');
    await page.getByRole('button', { name: 'Restore previous version' }).click();
    await page.getByRole('link', { name: 'Orders platform' }).waitFor();
    ok(existsSync(f + '.damaged'), 'the damaged file was kept, not overwritten');
    eq((await model(id)).elements.length, 4, 'project restored with its components');
    await page.goto(`${BASE}/#/p/${id}/threats`);
    await page.getByRole('button', { name: 'Forged order callbacks' }).waitFor();
  });

  /* ---------- E. export / import ---------- */
  await step('E1 export native JSON and Markdown; the CLI validates the exported file', async () => {
    await nav(page, 'Report');
    const [d1] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download native JSON' }).click()]);
    const jsonPath = join(data, 'export.threatweave.json'); await d1.saveAs(jsonPath);
    const [d2] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download Markdown report' }).click()]);
    const mdPath = join(data, 'export.md'); await d2.saveAs(mdPath);
    const md = readFileSync(mdPath, 'utf8');
    ok(md.includes('# Threat model: Orders platform') && md.includes('Forged order callbacks') && md.includes('verified'), 'markdown has content');
    const { spawnSync } = await import('node:child_process');
    const v = spawnSync('node', [join(ROOT, 'packages/cli/dist/bin.js'), 'validate', jsonPath]);
    eq(v.status, 0, 'cli validate exit code');
    const exported = JSON.parse(readFileSync(jsonPath, 'utf8'));
    eq(exported.elements.map((e: any) => e.id).sort(), (await model(id)).elements.map((e: any) => e.id).sort(), 'stable identifiers in export');
    ok(!JSON.stringify(exported).includes('apiKey'), 'no credentials in export');
    await shot(page, '13-report');
  });
  await step('E2 Threat Composer export is lossy and says so before download', async () => {
    await page.getByRole('button', { name: /Export to Threat Composer/ }).click();
    await page.getByRole('dialog', { name: /What the Threat Composer export loses/ }).waitFor();
    const text = await page.getByRole('dialog').innerText();
    ok(/not representable|flattened|dropped/i.test(text), 'loss warnings visible');
    await page.keyboard.press('Escape');
  });
  await step('E3 import a Threat Composer file: preview shows converted and unsupported content, ids preserved', async () => {
    await page.goto(BASE);
    await page.locator('input[type=file]').setInputFiles(join(ROOT, 'fixtures/tc/synthetic-warnings.tc.json'));
    const dlg = page.getByRole('dialog');
    await dlg.waitFor();
    const text = await dlg.innerText();
    ok(/diagram image/i.test(text) && /brainstorm/i.test(text) && /unknown top-level|somethingNew/i.test(text), 'unsupported fields are listed');
    await shot(page, '14-import-preview');
    await page.getByRole('button', { name: 'Import as a new model' }).click();
    await page.waitForURL(/#\/p\//);
    const m = await model(projectId(page));
    ok(m.threats.some((t: any) => t.id === 'thr_33333333-3333-3333-3333-333333333333'), 'threat id preserved');
  });
  await step('E4 a malformed import is rejected safely', async () => {
    await page.goto(BASE);
    writeFileSync(join(data, 'bad.json'), '{"schema": 7, "threats": 3}');
    await page.locator('input[type=file]').setInputFiles(join(data, 'bad.json'));
    await page.getByRole('dialog').getByText(/Cannot import this file/).waitFor();
    ok((await page.getByRole('button', { name: 'Import as a new model' }).count()) === 0, 'no import button for an invalid file');
    await page.keyboard.press('Escape');
  });

  /* ---------- F. the change-aware scenario ---------- */
  let demoId = '';
  await step('F1 open the demonstration; it is clearly labelled', async () => {
    await page.evaluate(() => localStorage.setItem('tw.archmode', 'canvas'));
    await page.goto(BASE);
    await page.getByRole('button', { name: 'Open a copy of the demonstration' }).click();
    await page.waitForSelector('.react-flow__node');
    ok(await page.getByText('Demonstration', { exact: true }).first().isVisible(), 'demonstration label visible');
    demoId = projectId(page);
    ok((await model(demoId)).reviewItems.length === 0, 'baseline has nothing to review');
    await shot(page, '20-demo-architecture');
  });
  await step('F2 selecting a threat highlights the architecture elements it affects; selecting a component shows its reasoning', async () => {
    await nav(page, 'Threats');
    await page.getByRole('button', { name: /Unauthorised stock manipulation/ }).click();
    await nav(page, 'Architecture');
    await page.waitForSelector('.tw-node.related');
    const related = await page.locator('.tw-node.related, .tw-node.selected').allInnerTexts();
    ok(related.some((t) => t.includes('inventory')), 'inventory highlighted');
    ok((await page.locator('.tw-node.dim').count()) >= 3, 'unrelated components dimmed');
    await shot(page, '21-threat-highlight');
    await page.locator('.tw-node').filter({ hasText: 'inventory' }).first().click();
    await page.getByRole('heading', { name: 'Related security reasoning' }).waitFor();
    ok(await page.getByText('Unauthorised stock manipulation').first().isVisible(), 'component inspector lists its threat');
  });
  await step('F3 scan a newer source revision (preview) and sync it: no provider contacted', async () => {
    await nav(page, 'Source');
    await page.getByRole('button', { name: /revision 2/ }).click();
    await page.getByRole('heading', { name: '2. What would be analysed' }).waitFor();
    ok(await page.getByText(/docker-compose.yml/).first().isVisible(), 'files listed');
    await page.getByRole('button', { name: 'Sync from this folder' }).click();
    await page.getByRole('button', { name: /Review what changed/ }).waitFor();
    await shot(page, '22-sync-result');
    const m = await model(demoId);
    eq(m.elements.find((e: any) => e.name === 'inventory').exposure, 'external', 'inventory now external');
    ok(m.runs.some((r: any) => r.kind === 'source-scan' && r.usage.note.includes('no model provider')), 'run recorded as deterministic');
  });
  await step('F4 review shows the flagged assumption, threat, mitigation and boundary with the reason and trace', async () => {
    await page.getByRole('button', { name: /Review what changed/ }).click();
    await page.locator('#main').getByRole('heading', { name: /Needs review/ }).waitFor();
    for (const t of ['only reachable from the backend network', 'Unauthorised stock manipulation', 'Keep inventory off published ports', 'Compose network "backend"']) ok(await page.getByText(t).first().isVisible(), `flagged: ${t}`);
    await page.getByText('Why was this flagged?').first().click();
    ok(await page.getByText(/Deterministic: raised by comparing/).first().isVisible(), 'trace explains it is deterministic');
    await shot(page, '23-review');
    const m = await model(demoId);
    eq(m.mitigations.find((x: any) => x.title.startsWith('Keep inventory')).status, 'implemented', 'accepted work not silently changed');
  });
  await step('F5 the canvas marks flagged components without relying on colour', async () => {
    await nav(page, 'Architecture');
    await page.waitForSelector('.tw-node .badge-review');
    ok(/needs review/i.test(await page.locator('.tw-node .badge-review').first().innerText()), 'badge carries text');
    await page.waitForTimeout(300);
    await shot(page, '24-canvas-review');
  });
  await step('F6 close a review item with a rationale; it records a decision and stays closed after re-sync', async () => {
    await nav(page, 'Review');
    const card = page.getByRole('article', { name: /Review items for assumption .*Only the web service/ });
    await card.getByRole('button', { name: /Dismiss/ }).first().click();
    const dlg = page.getByRole('dialog');
    ok(await dlg.getByRole('button', { name: /Dismiss/ }).last().isDisabled(), 'rationale required');
    await dlg.getByLabel(/Why is no action needed/).fill('Debug port is firewalled at the host for this sprint');
    await dlg.getByRole('button', { name: /Dismiss/ }).last().click();
    await waitSaved(page);
    const m = await model(demoId);
    const d = m.decisions.find((x: any) => x.action === 'dismiss');
    ok(d && d.rationale.includes('firewalled') && d.actor, 'decision recorded with rationale and actor');
    // re-sync the same revision: nothing reopens, nothing duplicates
    const before = m.reviewItems.length;
    await nav(page, 'Source');
    await page.getByRole('button', { name: /revision 2/ }).click();
    await page.getByRole('button', { name: 'Sync from this folder' }).click();
    await page.getByText(/0 new review item/).waitFor();
    const after = await model(demoId);
    eq(after.reviewItems.length, before, 'no duplicate review items');
    eq(after.reviewItems.find((r: any) => r.id === d.subject.id).status, 'dismissed', 'dismissed item stays dismissed');
  });
  await step('F7 proposals: edit then accept, dependent mitigation, reject with reason; nothing auto-accepted', async () => {
    await nav(page, 'Review');
    const before = await model(demoId);
    eq(before.threats.length, 3, 'no new threat before any decision');
    // dependent first: mitigation cannot be accepted before its threat
    const mitCard = page.getByRole('article', { name: /Proposal: Remove or restrict the published endpoint/ });
    await mitCard.getByRole('button', { name: 'Accept', exact: true }).click();
    await mitCard.getByRole('alert').waitFor();
    ok(/Accept that proposal first/.test(await mitCard.getByRole('alert').innerText()), 'dependency enforced with a clear message');
    const thr = page.getByRole('article', { name: /Proposal: Unauthenticated access to newly exposed inventory/ });
    await thr.getByRole('button', { name: /Edit then accept/ }).click();
    await thr.getByLabel('title').fill('Unauthenticated access to inventory once port 9000 is published'); await thr.getByLabel('title').blur();
    await thr.getByRole('button', { name: 'Accept with edits' }).click();
    await waitSaved(page);
    await mitCard.getByRole('button', { name: 'Accept', exact: true }).click();
    const q = page.getByRole('article', { name: /Proposal: Is the change that makes/ });
    await q.getByRole('button', { name: /Reject/ }).click();
    await page.getByRole('dialog').getByLabel('Why?').fill('Tracked in the sprint board already');
    await page.getByRole('dialog').getByRole('button', { name: 'Reject' }).click();
    await waitSaved(page);
    const m = await model(demoId);
    const t = m.threats.find((x: any) => x.title.startsWith('Unauthenticated access to inventory once'));
    ok(t && t.provenance.origin === 'pack-rule' && t.basis === 'hypothesis', 'accepted with rule-pack provenance, still a hypothesis');
    const mit = m.mitigations.find((x: any) => x.provenance.proposalId);
    eq(mit.status, 'proposed', 'generated mitigation starts as proposed'); ok(!mit.statusSetBy, 'it did not attest itself'); eq(mit.threatIds, [t.id], 'linked to the accepted threat');
    ok(m.proposals.filter((p: any) => p.status === 'rejected').length === 1 && m.decisions.some((d: any) => d.action === 'reject' && d.rationale.includes('sprint')), 'rejection recorded');
    await shot(page, '25-proposals-decided');
  });
  await step('F9 "Show on diagram" leaves Review and highlights the connected components', async () => {
    await nav(page, 'Review');
    await page.getByRole('button', { name: 'Show on diagram' }).first().click();
    await page.waitForURL(/\/architecture/);
    await page.waitForSelector('.tw-node.related, .tw-node.selected');
    ok((await page.locator('.tw-node.dim').count()) >= 1, 'unrelated components dimmed');
  });
  await step('F8 compare two revisions in the UI shows the same deterministic change', async () => {
    await nav(page, 'Review');
    const section = page.locator('section[aria-labelledby="cmp-h"]');
    const cmp = page.getByRole('heading', { name: 'Compare two revisions' });
    await cmp.scrollIntoViewIfNeeded();
    await page.getByLabel('From (earlier)').selectOption({ index: 1 });
    await page.getByLabel('To (later)').selectOption('current');
    await page.getByRole('button', { name: 'Compare', exact: true }).click();
    await section.getByText(/change\(s\)/i).first().waitFor();
    await section.getByText(/Exposure of "inventory" changed from internal to external/).first().waitFor();
  });

  /* ---------- G. AI via a simulated provider ---------- */
  const m1 = await (async () => { const r = await fetch(`${BASE}/api/projects`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-threatweave': '1' }, body: JSON.stringify({ example: 'northwind' }) }); return (await r.json()).id as string; })();
  const mdl = await model(m1);
  const cache = mdl.elements.find((e: any) => e.name === 'cache').id;
  const redisLine = readFileSync(join(ROOT, 'examples/repos/northwind-v1/docker-compose.yml'), 'utf8').split('\n').findIndex((l) => l.includes('image: redis:7')) + 1;
  const okOutput = JSON.stringify({ summary: 'simulated', proposals: [
    { key: 'a', basis: 'inferred', reasoning: 'Observed in docker-compose.yml: cache runs the stock redis image. Assumed: no password is configured.', evidence: [{ path: 'docker-compose.yml', lineStart: redisLine, lineEnd: redisLine, quote: 'image: redis:7' }, { path: 'etc/passwd', lineStart: 1, lineEnd: 1, quote: 'root:x:0:0' }],
      payload: { kind: 'add-threat', title: 'Unauthenticated Redis access from backend peers', source: 'compromised backend container', preconditions: ['no requirepass'], action: 'read and write cache keys', consequence: 'stock tampering', goals: ['integrity'], stride: ['T'], targets: [{ type: 'element', ref: cache }], likelihood: { level: 'unknown', rationale: 'redis.conf not provided' }, impact: { level: 'medium', rationale: 'stock drives fulfilment' }, evidenceStrength: 'moderate' } },
    { basis: 'hypothesis', reasoning: 'Generic.', payload: { kind: 'add-threat', title: 'Generic SQL injection', source: 's', action: 'a', consequence: 'c', targets: [{ type: 'element', ref: 'el_no-such-thing' }], likelihood: { level: 'low', rationale: 'r' }, impact: { level: 'low', rationale: 'r' }, evidenceStrength: 'none' } },
  ] });
  let mode: 'ok' | 'fail' | 'malformed' | 'slow' = 'ok';
  const mock = await startMock([async (_r, res) => {
    if (mode === 'fail') return json(res, 500, { error: 'boom' }, { 'retry-after': '0' });
    if (mode === 'malformed') return openaiOk('definitely not json')(_r, res);
    if (mode === 'slow') return; // never answers; the run is cancelled
    return openaiOk(okOutput, { prompt_tokens: 2100, completion_tokens: 410 })(_r, res);
  }]);
  await step('G1 configure a provider (simulated endpoint); the model identifier is configuration, not code', async () => {
    await page.goto(`${BASE}/#/p/${m1}/source`);
    await page.getByRole('button', { name: 'Settings' }).click();
    const dlg = page.getByRole('dialog', { name: 'Settings' });
    await dlg.getByLabel('Provider adapter').selectOption('openai-compatible');
    await dlg.getByLabel('Base URL (including /v1)').fill(`${mock.url}/v1`);
    await dlg.getByLabel('Model identifier').fill('simulated-model');
    await dlg.getByLabel('Your name').fill('Lee'); await dlg.getByLabel('Your name').blur();
    await dlg.getByRole('button', { name: 'Save settings' }).click();
    await dlg.getByText(/Verified only against the simulated fixture server/).first().waitFor();
    await dlg.getByRole('button', { name: 'Close' }).click();
    const s = await (await fetch(`${BASE}/api/settings`)).json();
    ok(!JSON.stringify(s).includes('sk-'), 'settings payload carries no credential');
  });
  const runAnalysis = async () => {
    await page.goto(`${BASE}/#/p/${m1}/source`); await page.reload();
    await page.getByRole('button', { name: /revision 1/ }).click();
    await page.getByRole('heading', { name: '3b. AI-assisted draft (optional)' }).waitFor();
    const runBtn = page.getByRole('button', { name: 'Run analysis' });
    return runBtn;
  };
  await step('G2 AI analysis: disclosure names the host and files; sending requires explicit confirmation', async () => {
    const runBtn = await runAnalysis();
    ok(await runBtn.isDisabled(), 'run disabled before confirmation');
    ok(await page.getByText(new RegExp(`127\\.0\\.0\\.1:${new URL(mock.url).port}`)).first().isVisible(), 'host disclosed');
    ok(await page.getByText(/secret-looking value/).first().isVisible(), 'redaction disclosed');
    await shot(page, '30-ai-disclosure');
    await page.getByLabel(/I understand this text will be sent/).check();
    await runBtn.click();
    await page.getByText('Analysis finished').waitFor({ timeout: 20000 });
    const m = await model(m1);
    const req = mock.seen.at(-1)!.body;
    ok(JSON.stringify(req).includes('<untrusted_file path=\\"docker-compose.yml\\">'), 'repository text sent inside an untrusted data block');
    ok(!JSON.stringify(req).includes('change-me'), 'secret value was redacted before sending');
    const pend = m.proposals.filter((p: any) => p.status === 'pending');
    eq(pend.length, 1, 'only the grounded proposal survived validation');
    eq(pend[0].evidence.length, 1, 'the fabricated citation (etc/passwd) was dropped');
    ok(pend[0].validationNotes.join(' ').includes('not part of the analysed input'), 'drop is explained');
    eq(m.threats.length, 3, 'accepted work untouched');
    const run = m.runs.find((r: any) => r.kind === 'ai-analysis');
    eq([run.usage.inputTokens, run.usage.outputTokens, run.usage.costUsd], [2100, 410, null], 'usage reported, cost honestly unavailable');
  });
  await step('G3 proposal shows reasoning, verified evidence and the assumed-vs-observed split; accept keeps AI provenance', async () => {
    await nav(page, 'Review');
    const card = page.getByRole('article', { name: /Proposal: Unauthenticated Redis access/ });
    await card.getByText(/quote found in analysed file/i).waitFor();
    await card.getByText(/Assumed: no password/i).waitFor();
    await shot(page, '31-ai-proposal');
    await card.getByRole('button', { name: 'Accept', exact: true }).click();
    await waitSaved(page);
    const m = await model(m1);
    const t = m.threats.find((x: any) => x.title.startsWith('Unauthenticated Redis'));
    eq(t.provenance.origin, 'ai', 'ai provenance'); ok(t.provenance.actor.includes('simulated-model'), 'adapter and model recorded');
    ok(m.evidence.some((e: any) => e.quote === 'image: redis:7' && e.revision), 'evidence has source revision and location');
  });
  await step('G4 reanalysis preserves human decisions: rejected stays rejected, accepted is not duplicated', async () => {
    const m0 = await model(m1);
    const redis = m0.proposals.find((p: any) => p.status === 'accepted');
    ok(redis, 'accepted proposal exists');
    // reject by changing nothing: run again; the same proposal arrives again and must be skipped
    const runBtn = await runAnalysis();
    await page.getByLabel(/I understand this text will be sent/).check();
    await runBtn.click();
    await page.getByText('Analysis finished').waitFor({ timeout: 20000 });
    const m = await model(m1);
    eq(m.proposals.filter((p: any) => p.status === 'pending').length, 0, 'no duplicate pending proposal');
    eq(m.threats.filter((x: any) => x.title.startsWith('Unauthenticated Redis')).length, 1, 'no duplicate threat');
    ok(m.runs.at(-1).notes.some((n: string) => /already accepted/.test(n)), 'run notes say why it was skipped');
  });
  await step('G5 provider failure leaves the project usable and says what happened', async () => {
    mode = 'fail';
    const runBtn = await runAnalysis();
    await page.getByLabel(/I understand this text will be sent/).check();
    const snapshot = JSON.stringify((await model(m1)).threats);
    await runBtn.click();
    await page.getByText('Analysis failed').waitFor({ timeout: 30000 });
    const m = await model(m1);
    eq(m.runs.at(-1).status, 'failed', 'run recorded as failed'); ok(m.runs.at(-1).error, 'error recorded');
    eq(JSON.stringify(m.threats), snapshot, 'threats unchanged');
    await nav(page, 'Threats');
    await page.getByLabel('Add threat').fill('Still editable after failure'); await page.getByLabel('Add threat').press('Enter');
    await waitSaved(page);
    ok((await model(m1)).threats.some((t: any) => t.title === 'Still editable after failure'), 'project still saves edits');
  });
  await step('G6 malformed provider output is rejected safely', async () => {
    mode = 'malformed';
    const runBtn = await runAnalysis();
    await page.getByLabel(/I understand this text will be sent/).check();
    const n = (await model(m1)).threats.length;
    await runBtn.click();
    await page.getByText('Analysis failed').waitFor({ timeout: 30000 });
    const m = await model(m1);
    ok(/valid JSON/i.test(m.runs.at(-1).error), 'reason given'); eq(m.threats.length, n, 'nothing added');
  });
  await step('G7 cancellation stops the run, leaves the project intact, and does not retry', async () => {
    mode = 'slow';
    const seenBefore = mock.seen.length;
    const runBtn = await runAnalysis();
    await page.getByLabel(/I understand this text will be sent/).check();
    await runBtn.click();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByText('Analysis cancelled').waitFor({ timeout: 15000 });
    const m = await model(m1);
    eq(m.runs.at(-1).status, 'cancelled', 'run recorded as cancelled');
    eq(mock.seen.length - seenBefore, 1, 'exactly one provider call, no retry after cancel');
    await shot(page, '32-ai-cancelled');
  });

  /* ---------- H. accessibility ---------- */
  await step('H1 automated accessibility audit (axe-core) of the main views has no serious or critical violations', async () => {
    const axeSrc = readFileSync(join(ROOT, 'node_modules/axe-core/axe.min.js'), 'utf8');
    const bad: string[] = [];
    const audit = async (label: string) => {
      await page.evaluate(axeSrc);
      const r = await page.evaluate(async () => (await (window as any).axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa'], resultTypes: ['violations'] })).violations.map((v: any) => ({ id: v.id, impact: v.impact, n: v.nodes.length, sample: v.nodes[0]?.html?.slice(0, 120) })));
      for (const v of r.filter((x: any) => x.impact === 'serious' || x.impact === 'critical')) bad.push(`${label}: ${v.id} (${v.impact}) x${v.n} e.g. ${v.sample}`);
    };
    await page.goto(BASE); await page.waitForSelector('h1'); await audit('home');
    await page.goto(`${BASE}/#/p/${demoId}/architecture`); await page.waitForSelector('.react-flow__node'); await audit('architecture canvas');
    await page.getByRole('button', { name: 'Table', exact: true }).click(); await audit('architecture table');
    for (const t of ['threats', 'assumptions', 'mitigations', 'evidence', 'review', 'source', 'report']) { await nav(page, t[0]!.toUpperCase() + t.slice(1)); await page.waitForTimeout(250); await audit(t); }
    await page.getByRole('button', { name: 'Settings' }).click(); await audit('settings dialog');
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur()); // focus is not inside the dialog
    await page.keyboard.press('Escape');
    eq(await page.getByRole('dialog').count(), 0, 'Escape closes the dialog even when focus is outside it');
    // dark theme
    await page.emulateMedia({ colorScheme: 'dark' }); await page.goto(`${BASE}/#/p/${demoId}/review`); await page.waitForTimeout(300); await audit('review (dark)'); await shot(page, '40-review-dark');
    await page.emulateMedia({ colorScheme: 'light' });
    if (bad.length) throw new Error(bad.join('\n'));
  });
  await step('H2 responsive: no horizontal page scroll at tablet and phone widths; inspector becomes a drawer', async () => {
    for (const w of [900, 420]) {
      await page.setViewportSize({ width: w, height: 800 });
      await page.goto(`${BASE}/#/p/${demoId}/threats`); await page.waitForTimeout(300);
      const over = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2);
      ok(!over, `no horizontal page scroll at ${w}px`);
    }
    // phone width: nothing selected means no drawer over the content; selecting opens it with a close control
    eq(await page.locator('.inspector').isVisible(), false, 'inspector hidden when nothing is selected at phone width');
    await page.getByRole('button', { name: /Unauthorised stock manipulation/ }).first().click();
    await page.locator('.inspector').waitFor({ state: 'visible' });
    await shot(page, '41-narrow');
    await page.getByRole('button', { name: 'Close inspector' }).click();
    eq(await page.locator('.inspector').isVisible(), false, 'inspector closes');
    await page.setViewportSize({ width: 1440, height: 900 });
  });
  await step('H3 manual modelling made no network requests beyond the local server', async () => { eq(mockOffline.filter((u) => !u.startsWith(`http://127.0.0.1:${new URL(mock.url).port}`)), [], 'external requests'); });
  await step('H4 no uncaught page errors', async () => { eq(pageErrors, [], 'page errors'); });

  await browser.close(); await mock.close(); await stopApp();
  rmSync(data, { recursive: true, force: true });
  const failed = results.filter((r) => !r.ok);
  writeFileSync(join(ROOT, 'e2e/last-run.json'), JSON.stringify({ ran: new Date().toISOString(), note: 'AI steps used a simulated provider server, not a live endpoint.', passed: results.length - failed.length, failed: failed.length, results }, null, 2) + '\n');
  console.log(`\n${results.length - failed.length}/${results.length} steps passed`);
  process.exit(failed.length ? 1 : 0);
}
main().catch(async (e) => { console.error(e); await stopApp(); process.exit(2); });
