import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile, utimes } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { emptyModel, serialiseModel, validateModel } from '@threatweave/core';
import { Store } from '../src/index.js';

const SERVER_DIST = new URL('../dist/index.js', import.meta.url).href;
let dir: string;
beforeAll(async () => { dir = await mkdtemp(join(tmpdir(), 'tw-persist-')); });
afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

const child = (script: string) => new Promise<{ code: number | null; err: string }>((resolve) => {
  const p = spawn('node', ['--input-type=module', '-e', script], { stdio: ['ignore', 'ignore', 'pipe'] });
  let err = ''; p.stderr.on('data', (d) => (err += d));
  p.on('close', (code) => resolve({ code, err }));
});

describe('writes from several processes do not lose updates', () => {
  it('4 processes x 25 read-modify-write cycles on one project all land', async () => {
    const store = new Store(dir); await store.init();
    const m = emptyModel('Concurrent'); m.description = '0';
    const id = (await store.save(m, { create: true })).model.id;
    const script = `import { Store } from ${JSON.stringify(SERVER_DIST)};
      const s = new Store(${JSON.stringify(dir)});
      for (let i = 0; i < 25; i++) await s.update(${JSON.stringify(id)}, (m) => ({ ...m, description: String(Number(m.description) + 1) }));`;
    const results = await Promise.all([1, 2, 3, 4].map(() => child(script)));
    for (const r of results) expect(r.err).toBe('');
    expect((await store.load(id)).model.description).toBe('100');
  }, 60000);

  it('a lock left by a dead process does not block writers', async () => {
    const store = new Store(dir);
    const id = (await store.save(emptyModel('Stale lock'), { create: true })).model.id;
    await writeFile(join(dir, 'projects', id, '.lock'), JSON.stringify({ pid: 999999, at: Date.now() }));
    await store.update(id, (m) => ({ ...m, description: 'ok' }));
    expect((await store.load(id)).model.description).toBe('ok');
  });
});

describe('crash and corruption handling', () => {
  it('keeps the previous version as a backup and restores it when the file is damaged', async () => {
    const store = new Store(dir);
    const m = emptyModel('Damaged'); m.description = 'first';
    const id = (await store.save(m, { create: true })).model.id;
    await store.update(id, (x) => ({ ...x, description: 'second' }));
    const file = join(dir, 'projects', id, 'model.json');
    expect(validateModel(JSON.parse(await readFile(join(dir, 'projects', id, 'model.json.bak'), 'utf8'))).model!.description).toBe('first');
    await writeFile(file, '{"format": "threatweave/model", "trunc'); // simulate a torn write from another tool
    await expect(store.load(id)).rejects.toThrow();
    const listed = (await store.list()).find((p) => p.id === id)!;
    expect(listed.broken?.hasBackup).toBe(true);           // surfaced, not silently dropped
    await store.restoreBackup(id);
    expect((await store.load(id)).model.description).toBe('first');
  });
  it('refuses to restore a backup that does not validate, and says why', async () => {
    const store = new Store(dir);
    const id = (await store.save(emptyModel('Bad backup'), { create: true })).model.id;
    await store.update(id, (x) => ({ ...x, description: 'x' }));
    await writeFile(join(dir, 'projects', id, 'model.json.bak'), '{not json');
    await expect(store.restoreBackup(id)).rejects.toThrow(/backup/i);
  });
  it('cleans up temp files left behind by an interrupted write, but not fresh ones', async () => {
    const store = new Store(dir);
    const id = (await store.save(emptyModel('Tmp'), { create: true })).model.id;
    const pdir = join(dir, 'projects', id);
    const old = join(pdir, 'model.json.123.old.tmp'), fresh = join(pdir, 'model.json.456.fresh.tmp');
    await writeFile(old, 'x'); await writeFile(fresh, 'x');
    const past = new Date(Date.now() - 10 * 60_000); await utimes(old, past, past);
    await new Store(dir).init();
    const files = await readdir(pdir);
    expect(files).not.toContain('model.json.123.old.tmp');
    expect(files).toContain('model.json.456.fresh.tmp');
  });
  it('writes revision snapshots atomically with stable numbering under concurrent snapshots', async () => {
    const store = new Store(dir);
    const id = (await store.save(emptyModel('Revs'), { create: true })).model.id;
    await Promise.all([1, 2, 3, 4, 5].map((i) => store.snapshot(id, `s${i}`)));
    const revs = (await store.revisions(id)).map((r) => r.id.slice(0, 4));
    expect(revs).toEqual(['0001', '0002', '0003', '0004', '0005']);
    for (const r of await store.revisions(id)) expect(serialiseModel((await store.revision(id, r.id)))).toContain('"format"');
  });
});
