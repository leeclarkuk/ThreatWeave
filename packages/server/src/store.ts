import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, open, readFile, readdir, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ModelValidationError, assertValid, serialiseModel, validateModel, type Issue, type Model } from '@threatweave/core';

export const PROJECT_ID = /^[a-z0-9][a-z0-9-]{2,60}$/;
const REVISION_ID = /^\d{4}-[a-z0-9-]{1,40}$/;

export class NotFound extends Error {}
export class Conflict extends Error {}
/** A request the caller can fix (bad input, missing confirmation). Rendered as HTTP 400, never as a server fault. */
export class UserError extends Error {}

export interface ProjectSummary {
  id: string; name: string; example: boolean; updatedAt: string;
  counts: { elements: number; threats: number; mitigations: number; openReview: number; pendingProposals: number };
  /** Present when the stored file cannot be loaded. The project is shown, never silently dropped. */
  broken?: { reason: string; hasBackup: boolean };
}

const etagOf = (text: string) => createHash('sha256').update(text).digest('hex').slice(0, 24);


const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 15_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const pidAlive = (pid: number) => { try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === 'EPERM'; } };

/** Write, flush to disk, then atomically replace. A crash leaves either the old file or the new one, never half of each. */
export async function atomicWrite(path: string, text: string) {
  const tmp = `${path}.${process.pid}.${Math.random().toString(36).slice(2, 8)}.tmp`;
  const fh = await open(tmp, 'w', 0o600);
  try { await fh.writeFile(text); await fh.sync(); } finally { await fh.close(); }
  await rename(tmp, path);
  try { const d = await open(dirname(path), 'r'); try { await d.sync(); } finally { await d.close(); } } catch { /* directory fsync is best effort (not supported on every platform) */ }
}

/**
 * Cross-process advisory lock (exclusive-create lock file). Needed because the web server, the CLI and the MCP
 * server may all write the same project. A lock whose owner has died, or that is older than 30 s, is taken over.
 */
async function withFileLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fh = await open(lockPath, 'wx', 0o600);
      try { await fh.writeFile(JSON.stringify({ pid: process.pid, at: Date.now() })); } finally { await fh.close(); }
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      try {
        const held = JSON.parse(await readFile(lockPath, 'utf8')) as { pid: number; at: number };
        if (!pidAlive(held.pid) || Date.now() - held.at > LOCK_STALE_MS) { await unlink(lockPath).catch(() => undefined); continue; }
      } catch { /* unreadable or just released: retry */ }
      if (Date.now() > deadline) throw new Error('The project is locked by another process. Try again in a moment.');
      await sleep(15 + Math.random() * 25);
    }
  }
  try { return await fn(); } finally { await unlink(lockPath).catch(() => undefined); }
}

/** One JSON file per project (readable Git diffs), atomic writes, per-project write lock. */
export class Store {
  private locks = new Map<string, Promise<unknown>>();
  constructor(public dir: string) {}

  private projectDir(id: string) {
    if (!PROJECT_ID.test(id)) throw new NotFound(`Invalid project id`);
    return join(this.dir, 'projects', id);
  }
  private file(id: string) { return join(this.projectDir(id), 'model.json'); }

  async init() {
    await mkdir(join(this.dir, 'projects'), { recursive: true, mode: 0o700 });
    // Remove temp files from interrupted writes (older than a minute, so a write in progress elsewhere is untouched).
    for (const id of await readdir(join(this.dir, 'projects')).catch(() => [] as string[])) {
      if (!PROJECT_ID.test(id)) continue;
      for (const dirp of [join(this.dir, 'projects', id), join(this.dir, 'projects', id, 'revisions')])
        for (const f of await readdir(dirp).catch(() => [] as string[]))
          if (f.endsWith('.tmp')) { const st = await stat(join(dirp, f)).catch(() => null); if (st && Date.now() - st.mtimeMs > 60_000) await unlink(join(dirp, f)).catch(() => undefined); }
    }
  }

  /** Serialise writers per project so a finishing analysis run and a user edit cannot interleave. */
  async withLock<T>(id: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(id) ?? Promise.resolve();
    const run = async () => { await mkdir(this.projectDir(id), { recursive: true, mode: 0o700 }); return withFileLock(join(this.projectDir(id), '.lock'), fn); };
    const next = prev.catch(() => undefined).then(run);
    this.locks.set(id, next);
    try { return await next; } finally { if (this.locks.get(id) === next) this.locks.delete(id); }
  }

  async list(): Promise<ProjectSummary[]> {
    await this.init();
    const out: ProjectSummary[] = [];
    for (const id of await readdir(join(this.dir, 'projects'))) {
      if (!PROJECT_ID.test(id)) continue;
      try {
        const { model } = await this.load(id);
        const st = await stat(this.file(id));
        out.push({
          id, name: model.name, example: model.example, updatedAt: st.mtime.toISOString(),
          counts: {
            elements: model.elements.length, threats: model.threats.length, mitigations: model.mitigations.length,
            openReview: model.reviewItems.filter((r) => r.status === 'open').length, pendingProposals: model.proposals.filter((p) => p.status === 'pending').length,
          },
        });
      } catch (e) {
        const hasBackup = await this.backupValid(id);
        const st = await stat(this.file(id)).catch(() => null);
        if (!st) continue; // a directory with no model file is not a project
        out.push({ id, name: id, example: false, updatedAt: st.mtime.toISOString(), counts: { elements: 0, threats: 0, mitigations: 0, openReview: 0, pendingProposals: 0 }, broken: { reason: (e as Error).message.slice(0, 300), hasBackup } });
      }
    }
    return out.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  async load(id: string): Promise<{ model: Model; etag: string; issues: Issue[] }> {
    let text: string;
    try { text = await readFile(this.file(id), 'utf8'); } catch { throw new NotFound(`Project ${id} not found`); }
    const v = validateModel(JSON.parse(text));
    if (!v.model) throw new ModelValidationError(`Stored project ${id} no longer validates`, v.issues);
    return { model: v.model, etag: etagOf(text), issues: v.issues };
  }

  /** Validate with the shared domain rules, then write atomically. Optionally enforce optimistic concurrency. */
  async save(model: Model | unknown, opts: { ifMatch?: string | undefined; create?: boolean } = {}): Promise<{ model: Model; etag: string; issues: Issue[] }> {
    const v = validateModel(model);
    if (!v.ok || !v.model) throw new ModelValidationError('Model failed validation', v.issues);
    const m = v.model;
    return this.withLock(m.id, async () => {
      const f = this.file(m.id);
      let existing: string | null = null;
      try { existing = await readFile(f, 'utf8'); } catch { /* new project */ }
      if (existing === null && !opts.create && opts.ifMatch !== undefined) throw new NotFound(`Project ${m.id} not found`);
      if (existing !== null && opts.create) throw new Conflict(`Project ${m.id} already exists`);
      if (existing !== null && opts.ifMatch !== undefined && etagOf(existing) !== opts.ifMatch) throw new Conflict('The project changed on disk since you loaded it');
      const text = serialiseModel(m);
      if (existing === text) return { model: m, etag: etagOf(text), issues: v.issues };
      await this.writeWithBackup(f, existing, text);
      return { model: m, etag: etagOf(text), issues: v.issues };
    });
  }

  /** Read-modify-write under the lock, for server-originated changes (analysis runs, source sync). */
  async update(id: string, fn: (m: Model) => Model | Promise<Model>): Promise<{ model: Model; etag: string }> {
    return this.withLock(id, async () => {
      const { model } = await this.load(id);
      const next = assertValid(await fn(model));
      const text = serialiseModel(next);
      const f = this.file(id);
      const existing = await readFile(f, 'utf8').catch(() => null);
      if (existing !== text) await this.writeWithBackup(f, existing, text);
      return { model: next, etag: etagOf(text) };
    });
  }

  async delete(id: string) {
    await this.withLock(id, async () => { await rm(this.projectDir(id), { recursive: true, force: true }); });
  }


  /** Keep the previous good version next to the file so a damaged write (by any tool) can be undone. */
  private async writeWithBackup(file: string, previous: string | null, next: string) {
    if (previous !== null) await atomicWrite(`${file}.bak`, previous);
    await atomicWrite(file, next);
  }

  private async backupValid(id: string): Promise<boolean> {
    try { return validateModel(JSON.parse(await readFile(`${this.file(id)}.bak`, 'utf8'))).ok; } catch { return false; }
  }

  /** Replace a damaged model file with its last good backup. The damaged file is kept as model.json.damaged. */
  async restoreBackup(id: string): Promise<void> {
    await this.withLock(id, async () => {
      const f = this.file(id);
      let text: string;
      try { text = await readFile(`${f}.bak`, 'utf8'); } catch { throw new Error('There is no backup for this project.'); }
      let valid = false;
      try { valid = validateModel(JSON.parse(text)).ok; } catch { /* invalid */ }
      if (!valid) throw new Error('The backup does not validate either, so it was not restored. Both files are untouched.');
      await copyFile(f, `${f}.damaged`).catch(() => undefined);
      await atomicWrite(f, text);
    });
  }

  /* ----- revisions: immutable snapshots used for comparison ----- */
  private revDir(id: string) { return join(this.projectDir(id), 'revisions'); }
  async snapshot(id: string, label: string): Promise<{ id: string; label: string }> {
    return this.withLock(id, async () => {
      const { model } = await this.load(id);
      await mkdir(this.revDir(id), { recursive: true, mode: 0o700 });
      const existing = (await readdir(this.revDir(id)).catch(() => [])).filter((f) => f.endsWith('.json'));
      const n = existing.length + 1;
      const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'snapshot';
      const rid = `${String(n).padStart(4, '0')}-${slug}`;
      await atomicWrite(join(this.revDir(id), `${rid}.json`), serialiseModel(model));
      return { id: rid, label };
    });
  }

  async revisions(id: string): Promise<Array<{ id: string; size: number }>> {
    const files = (await readdir(this.revDir(id)).catch(() => [])).filter((f) => f.endsWith('.json')).sort();
    return Promise.all(files.map(async (f) => ({ id: f.replace(/\.json$/, ''), size: (await stat(join(this.revDir(id), f))).size })));
  }
  async revision(id: string, rid: string): Promise<Model> {
    if (!REVISION_ID.test(rid)) throw new NotFound('Invalid revision id');
    let text: string;
    try { text = await readFile(join(this.revDir(id), `${rid}.json`), 'utf8'); } catch { throw new NotFound(`Revision ${rid} not found`); }
    return assertValid(JSON.parse(text));
  }

  /** A run still marked running after a restart cannot be running. Mark it so the project is not left in limbo. */
  async recoverInterruptedRuns() {
    for (const p of await this.list()) {
      const { model } = await this.load(p.id);
      if (!model.runs.some((r) => r.status === 'running')) continue;
      await this.update(p.id, (m) => {
        for (const r of m.runs) if (r.status === 'running') { r.status = 'failed'; r.error = 'Interrupted by a server restart.'; r.finishedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'); }
        return m;
      });
    }
  }
}

export async function writePrivate(path: string, text: string) {
  await writeFile(path, text, { mode: 0o600 });
  await chmod(path, 0o600);
}
