import { readFile, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { z } from 'zod';
import {
  Model as ModelSchema, deriveReviewItems, diffModels, exportThreatComposer, importThreatComposer, labelOf, renderMarkdownReport, serialiseModel, syncSource, validateModel,
  type Change, type ConversionWarning, type Issue, type Model, type ReviewItem,
} from '@threatweave/core';
import { loadSelected, scanDirectory, snapshotRevision } from '@threatweave/server';

export class CliError extends Error {
  constructor(message: string, public code = 1) { super(message); }
}

export async function readJson(path: string): Promise<unknown> {
  let text: string;
  try { text = await readFile(path, 'utf8'); } catch { throw new CliError(`Cannot read ${path}`, 2); }
  try { return JSON.parse(text); } catch (e) { throw new CliError(`${path} is not valid JSON: ${(e as Error).message}`, 1); }
}

export const isTc = (data: unknown) => !!data && typeof data === 'object' && 'schema' in (data as object) && !('format' in (data as object));

/** Load a native model, or convert a Threat Composer file (reporting what the conversion lost). */
export async function loadModel(path: string): Promise<{ model: Model; issues: Issue[]; warnings: ConversionWarning[]; converted: boolean }> {
  const data = await readJson(path);
  if (isTc(data)) {
    const r = importThreatComposer(data);
    const v = validateModel(r.model);
    if (!v.model) throw new CliError(`Converted model is invalid: ${v.issues[0]?.message}`);
    return { model: v.model, issues: v.issues, warnings: r.warnings, converted: true };
  }
  const v = validateModel(data);
  if (!v.model) throw new CliError(formatIssues(v.issues, path), 1);
  return { model: v.model, issues: v.issues, warnings: [], converted: false };
}

export function formatIssues(issues: Issue[], file = ''): string {
  return issues.map((i) => `${file ? `${file}: ` : ''}${i.severity}: ${i.path}: ${i.message} [${i.code}]`).join('\n');
}

export async function cmdValidate(file: string, o: { json?: boolean }) {
  const data = await readJson(file);
  let model: unknown = data, warnings: ConversionWarning[] = [];
  if (isTc(data)) { const r = importThreatComposer(data); model = r.model; warnings = r.warnings; }
  const v = validateModel(model);
  if (o.json) return { code: v.ok ? 0 : 1, out: JSON.stringify({ ok: v.ok, converted: isTc(data), issues: v.issues, conversionWarnings: warnings }, null, 2) };
  const lines = [v.ok ? `OK: ${file} is a valid ${isTc(data) ? 'Threat Composer file (converted for checking)' : 'ThreatWeave model'}.` : `INVALID: ${file}`];
  if (v.issues.length) lines.push(formatIssues(v.issues));
  for (const w of warnings) lines.push(`${w.level === 'warning' ? 'warning' : 'note'}: conversion: ${w.message}${w.count > 1 ? ` (x${w.count})` : ''}`);
  return { code: v.ok ? 0 : 1, out: lines.join('\n') };
}

export interface Comparison { changes: Change[]; reviewItems: ReviewItem[]; before: Model; after: Model }
export function compare(a: Model, b: Model): Comparison {
  const changes = diffModels(a, b);
  return { changes, reviewItems: deriveReviewItems(a, b, changes), before: a, after: b };
}

export function renderComparison(c: Comparison): string {
  const L: string[] = [`${c.changes.length} change(s), ${c.reviewItems.length} review item(s) this comparison would raise.`, ''];
  if (c.changes.length) L.push('Changes (deterministic):', ...c.changes.map((x) => `  - [${x.kind}] ${x.summary}`), '');
  if (c.reviewItems.length) {
    L.push('Needs review (explicit relationships only; not an exhaustive impact analysis):');
    for (const r of c.reviewItems) {
      const label = labelOf(c.after, r.target).endsWith('(missing)') ? labelOf(c.before, r.target) : labelOf(c.after, r.target);
      L.push(`  - ${r.target.type} "${label}": ${r.reason}`, ...r.trace.map((t, i) => `      ${i === 0 ? 'why: ' : '  -> '}${t}`));
    }
  }
  return L.join('\n');
}

export async function cmdCompare(a: string, b: string, o: { json?: boolean; failOnReview?: boolean }) {
  const c = compare((await loadModel(a)).model, (await loadModel(b)).model);
  const code = o.failOnReview && c.reviewItems.length ? 3 : 0;
  if (o.json) return { code, out: JSON.stringify({ changes: c.changes, reviewItems: c.reviewItems }, null, 2) };
  return { code, out: renderComparison(c) };
}

export async function cmdImportTc(file: string, out: string | undefined, o: { json?: boolean }) {
  const data = await readJson(file);
  let r;
  try { r = importThreatComposer(data); } catch (e) { throw new CliError((e as Error).message, 1); }
  const v = validateModel(r.model);
  if (!v.model) throw new CliError(`Converted model is invalid:\n${formatIssues(v.issues)}`);
  const target = out ?? file.replace(/\.tc\.json$|\.json$/i, '') + '.threatweave.json';
  await writeFile(target, serialiseModel(v.model));
  const lines = [`Wrote ${target} (${r.stats.threats} threats, ${r.stats.mitigations} mitigations, ${r.stats.assumptions} assumptions).`, ...r.warnings.map((w) => `${w.level === 'warning' ? 'warning' : 'note'}: ${w.message}${w.count > 1 ? ` (x${w.count})` : ''}`)];
  return { code: 0, out: o.json ? JSON.stringify({ wrote: target, stats: r.stats, warnings: r.warnings }, null, 2) : lines.join('\n') };
}

export async function cmdExportTc(file: string, out: string | undefined) {
  const { model } = await loadModel(file);
  const r = exportThreatComposer(model);
  const target = out ?? file.replace(/\.json$/i, '') + '.tc.json';
  await writeFile(target, JSON.stringify(r.json, null, 2) + '\n');
  return { code: 0, out: [`Wrote ${target}. This conversion is lossy.`, ...r.warnings.map((w) => `${w.level}: ${w.message}${w.count > 1 ? ` (x${w.count})` : ''}`)].join('\n') };
}

export async function cmdReport(file: string, out: string | undefined) {
  const { model } = await loadModel(file);
  const md = renderMarkdownReport(model, { generatedAt: new Date().toISOString().slice(0, 10) });
  if (out) { await writeFile(out, md); return { code: 0, out: `Wrote ${out}` }; }
  return { code: 0, out: md };
}

export async function cmdScan(dir: string, o: { json?: boolean }) {
  const scan = await scanDirectory(dir, { allowedRoots: (process.env.THREATWEAVE_SOURCE_ROOTS ?? '').split(':').filter(Boolean).map((p) => resolve(p)) });
  if (o.json) return { code: 0, out: JSON.stringify(scan, null, 2) };
  const L = [`Would analyse ${scan.files.length} file(s), ${scan.totalBytes} bytes, in ${scan.root}${scan.vcsRevision ? ` (git ${scan.vcsRevision.slice(0, 10)})` : ''}${scan.truncated ? ' [limit reached: partial]' : ''}`, ...scan.files.map((f) => `  ${f.role === 'document' ? 'doc   ' : 'config'} ${f.path} (${f.bytes} B)`)];
  if (scan.skipped.length) L.push('Skipped:', ...scan.skipped.map((s) => `  ${s.path}: ${s.reason}`));
  L.push('', 'Nothing was sent anywhere. Supported:', ...scan.supported.map((s) => `  + ${s}`), 'Not supported:', ...scan.unsupported.map((s) => `  - ${s}`));
  return { code: 0, out: L.join('\n') };
}

export async function cmdSync(modelFile: string, dir: string, out: string | undefined, o: { json?: boolean }) {
  const { model } = await loadModel(modelFile);
  const scan = await scanDirectory(dir);
  const { inputs } = await loadSelected(scan);
  if (!inputs.length) throw new CliError('No supported files found', 1);
  const res = syncSource(model, inputs, { label: scan.label, revision: snapshotRevision(inputs), ...(scan.vcsRevision ? { vcsRevision: scan.vcsRevision } : {}), actor: process.env.USER ?? 'cli' });
  const target = out ?? modelFile;
  await writeFile(target, serialiseModel(res.model));
  const c = { changes: res.changes, reviewItems: res.reviewItems, before: model, after: res.model };
  return { code: 0, out: o.json ? JSON.stringify({ wrote: target, changes: res.changes, reviewItems: res.reviewItems, proposals: res.proposals.length, notes: res.notes }, null, 2) : [`Wrote ${relative(process.cwd(), resolve(target)) || target}.`, renderComparison(c), `${res.proposals.length} rule-pack proposal(s) added as pending. Nothing was accepted.`, ...res.notes.map((n) => `note: ${n}`)].join('\n') };
}

/** The JSON Schema for the native model, generated from the same zod definition the validator uses. */
export function cmdSchema() {
  return { code: 0, out: JSON.stringify(z.toJSONSchema(ModelSchema, { io: 'input' }), null, 2) };
}
