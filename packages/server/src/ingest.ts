import { createHash } from 'node:crypto';
import { lstat, open, readFile, readdir, realpath } from 'node:fs/promises';
import { join, relative, resolve, sep, posix } from 'node:path';
import { redactSecrets, type SourceFileInput } from '@threatweave/core';

export interface IngestLimits {
  maxDepth: number; maxEntries: number; maxFileBytes: number; maxDocBytes: number; maxTotalBytes: number; maxFiles: number;
}
export const DEFAULT_LIMITS: IngestLimits = {
  maxDepth: 8, maxEntries: 5000, maxFileBytes: 256 * 1024, maxDocBytes: 64 * 1024, maxTotalBytes: 1024 * 1024, maxFiles: 100,
};

export type FileRole = 'config' | 'document';
export interface ScanFile { path: string; bytes: number; hash: string; role: FileRole }
export interface ScanSkip { path: string; reason: string }
export interface ScanResult {
  root: string; label: string; vcsRevision?: string | undefined; files: ScanFile[]; skipped: ScanSkip[];
  totalBytes: number; truncated: boolean; limits: IngestLimits;
  supported: string[]; unsupported: string[];
}

const IGNORE_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.venv', 'venv', '__pycache__', '.terraform', '.next', '.cache', 'coverage']);
const SECRETISH = /(^\.env|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|^id_(rsa|dsa|ecdsa|ed25519)|credential|secret|\.tfstate|\.kdbx$|kubeconfig|\.npmrc$|\.netrc$)/i;
const DOC = /^(readme|architecture|design|threat|security)[^/]*\.md$/i;

export const SUPPORTED = ['Docker Compose files (*.yml, *.yaml with a services map)', 'Kubernetes manifests (Deployment, StatefulSet, DaemonSet, Service, Ingress)', 'README, ARCHITECTURE, DESIGN and SECURITY markdown (context for AI analysis only)'];
export const UNSUPPORTED = ['Archives (zip, tar), single files, and symlinks', 'Terraform, CloudFormation, Helm templates, Kustomize overlays', 'Source code (not analysed in this release)', 'Secret-looking files (.env, keys, tfstate): never read'];

export class IngestError extends Error {}

/** Read the VCS revision without running git (no hooks, no config execution). */
async function vcsRevision(root: string): Promise<string | undefined> {
  try {
    const head = (await readFile(join(root, '.git', 'HEAD'), 'utf8')).trim();
    if (!head.startsWith('ref: ')) return /^[0-9a-f]{40}$/.test(head) ? head : undefined;
    const ref = head.slice(5).trim();
    if (!/^refs\/[A-Za-z0-9._/-]+$/.test(ref)) return undefined;
    try { return (await readFile(join(root, '.git', ref), 'utf8')).trim().slice(0, 40); } catch { /* maybe packed */ }
    const packed = await readFile(join(root, '.git', 'packed-refs'), 'utf8');
    const line = packed.split('\n').find((l) => l.endsWith(` ${ref}`));
    return line?.split(' ')[0];
  } catch { return undefined; }
}

export async function resolveRoot(input: string, allowedRoots: string[] = []): Promise<string> {
  if (!input || typeof input !== 'string' || input.includes('\0')) throw new IngestError('A directory path is required');
  const abs = resolve(input);
  let st;
  try { st = await lstat(abs); } catch { throw new IngestError(`Directory not found: ${input}`); }
  if (st.isSymbolicLink()) throw new IngestError('The source path is a symlink. Pass the real directory.');
  if (!st.isDirectory()) throw new IngestError('Only directories are supported. Archives and single files are not analysed.');
  const real = await realpath(abs);
  if (real === sep || /^[A-Za-z]:\\?$/.test(real)) throw new IngestError('Refusing to scan a filesystem root');
  if (allowedRoots.length && !allowedRoots.some((r) => real === r || real.startsWith(r + sep)))
    throw new IngestError('That directory is outside the allowed source roots (THREATWEAVE_SOURCE_ROOTS).');
  return real;
}

/**
 * Enumerate analysable files under a directory. Never follows symlinks, never reads secret-looking
 * files, never executes anything. Everything is bounded and every skip is reported with a reason.
 */
export async function scanDirectory(input: string, o: { allowedRoots?: string[]; limits?: Partial<IngestLimits> } = {}): Promise<ScanResult> {
  const limits = { ...DEFAULT_LIMITS, ...o.limits };
  const root = await resolveRoot(input, o.allowedRoots);
  const files: ScanFile[] = [];
  const skipped: ScanSkip[] = [];
  let entries = 0, total = 0, truncated = false;

  async function walk(dir: string, depth: number) {
    if (depth > limits.maxDepth) { skipped.push({ path: posix.join(...relative(root, dir).split(sep), ''), reason: 'deeper than the depth limit' }); return; }
    let names: string[];
    try { names = (await readdir(dir)).sort(); } catch { skipped.push({ path: relative(root, dir) || '.', reason: 'unreadable directory' }); return; }
    for (const name of names) {
      if (++entries > limits.maxEntries) { truncated = true; return; }
      const full = join(dir, name);
      const rel = relative(root, full).split(sep).join('/');
      let st;
      try { st = await lstat(full); } catch { continue; }
      if (st.isSymbolicLink()) { skipped.push({ path: rel, reason: 'symlink (never followed)' }); continue; }
      if (st.isDirectory()) {
        if (IGNORE_DIRS.has(name)) continue;
        await walk(full, depth + 1);
        if (truncated) return;
        continue;
      }
      if (!st.isFile()) { skipped.push({ path: rel, reason: 'not a regular file' }); continue; }
      const isYaml = /\.ya?ml$/i.test(name);
      const isDoc = /\.md$/i.test(name) && DOC.test(name);
      if (!isYaml && !isDoc) continue;
      if (SECRETISH.test(name)) { skipped.push({ path: rel, reason: 'looks like it may hold secrets (never read)' }); continue; }
      const cap = isDoc ? limits.maxDocBytes : limits.maxFileBytes;
      if (st.size > cap) { skipped.push({ path: rel, reason: `larger than ${Math.round(cap / 1024)} KB limit` }); continue; }
      if (files.length >= limits.maxFiles || total + st.size > limits.maxTotalBytes) { skipped.push({ path: rel, reason: 'total size or file count limit reached' }); truncated = true; continue; }
      const buf = await readNoFollow(full, cap);
      if (!buf) { skipped.push({ path: rel, reason: 'could not be read safely' }); continue; }
      if (buf.includes(0)) { skipped.push({ path: rel, reason: 'binary content' }); continue; }
      total += buf.length;
      files.push({ path: rel, bytes: buf.length, hash: createHash('sha256').update(buf).digest('hex'), role: isDoc ? 'document' : 'config' });
    }
  }
  await walk(root, 0);
  return { root, label: root.split(sep).pop() || 'source', vcsRevision: await vcsRevision(root), files, skipped, totalBytes: total, truncated, limits, supported: SUPPORTED, unsupported: UNSUPPORTED };
}

/** open with O_NOFOLLOW semantics emulated by lstat+realpath containment, then bounded read. */
async function readNoFollow(path: string, cap: number): Promise<Buffer | null> {
  const st = await lstat(path);
  if (st.isSymbolicLink() || !st.isFile()) return null;
  const fh = await open(path, 'r');
  try {
    const buf = Buffer.alloc(Math.min(st.size, cap) + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    return bytesRead > cap ? null : buf.subarray(0, bytesRead);
  } finally { await fh.close(); }
}

/** Load the selected files again, verifying they have not changed since the scan the user reviewed. */
export async function loadSelected(scan: ScanResult, selected?: string[]): Promise<{ inputs: SourceFileInput[]; redactions: number; changed: string[] }> {
  const pick = scan.files.filter((f) => !selected || selected.includes(f.path));
  const inputs: SourceFileInput[] = [];
  const changed: string[] = [];
  let redactions = 0;
  for (const f of pick) {
    const full = join(scan.root, ...f.path.split('/'));
    const real = await realpath(full).catch(() => '');
    if (!real.startsWith(scan.root + sep)) { changed.push(f.path); continue; }
    const buf = await readNoFollow(full, scan.limits.maxFileBytes);
    if (!buf) { changed.push(f.path); continue; }
    const hash = createHash('sha256').update(buf).digest('hex');
    if (hash !== f.hash) { changed.push(f.path); continue; }
    const text = buf.toString('utf8');
    const r = redactSecrets(text);
    redactions += r.count;
    inputs.push({ path: f.path, content: text, hash });
  }
  return { inputs, redactions, changed };
}

/** Digest identifying a captured set of files. Not a VCS revision. */
export function snapshotRevision(files: Array<{ path: string; hash: string }>): string {
  return createHash('sha256').update(files.map((f) => `${f.path}:${f.hash}`).sort().join('\n')).digest('hex').slice(0, 16);
}
