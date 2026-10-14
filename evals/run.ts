/**
 * Evaluate AI proposal quality on the versioned example set.
 *   npx tsx evals/run.ts --adapter simulated --variant good|generic|fabricating   (add --save to record under evals/results/)
 *   ANTHROPIC_API_KEY=... EVAL_MODEL=<id> npx tsx evals/run.ts --adapter anthropic
 *   EVAL_BASE_URL=http://127.0.0.1:11434/v1 EVAL_MODEL=<id> npx tsx evals/run.ts --adapter openai-compatible
 *
 * "simulated" replays canned output through the real validation pipeline. It validates the HARNESS and
 * the pipeline's defences. It says nothing about any model's quality. Only live runs measure a model, and
 * a handful of small systems can expose failure modes but cannot establish general quality.
 *
 * Metrics (the number of proposals is deliberately NOT one):
 *   missed         expected threats with no matching proposal
 *   unsupported    kept proposals that assume an absent condition, plus proposals the pipeline discarded as ungrounded
 *   fabricated     evidence citations that failed verification against the files actually sent
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { ingestAiOutput, emptyModel, syncSource, type Model, type SourceFileInput } from '@threatweave/core';
import { AnthropicAdapter, OpenAICompatibleAdapter, runAnalysis, type AnalysisFile, type CompletionRequest, type CompletionResult, type ModelAdapter } from '@threatweave/ai';
import { CASES, EVAL_SET_VERSION, type EvalCase } from './cases.js';

const ROOT = new URL('.', import.meta.url).pathname;

class SimulatedAdapter implements ModelAdapter {
  id = 'simulated'; modelId = 'canned'; endpointHost = 'none';
  constructor(private proposals: unknown[]) {}
  capabilities() { return { id: 'simulated', displayName: 'Canned output', structuredOutput: 'prompt-only' as const, reportsUsage: false, liveVerified: false, notes: ['Replays canned output. Not a model.'] }; }
  async complete(_r: CompletionRequest): Promise<CompletionResult> {
    return { text: JSON.stringify({ summary: 'simulated', proposals: this.proposals }), usage: { inputTokens: null, outputTokens: null }, stopReason: 'end_turn', model: null };
  }
}

function load(c: EvalCase) {
  const dir = join(ROOT, 'systems', c.dir);
  const files: SourceFileInput[] = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).map((path) => {
    const content = readFileSync(join(dir, path), 'utf8');
    return { path, content, hash: createHash('sha256').update(content).digest('hex') };
  });
  const model = syncSource(emptyModel(`eval-${c.id}`), files, { label: c.id, revision: 'eval', actor: 'eval' }).model;
  model.proposals = []; model.reviewItems = []; model.runs = [];
  return { files, model };
}

const fill = (v: unknown, model: Model, files: SourceFileInput[]): unknown => {
  if (typeof v === 'string' && v.startsWith('@')) return model.elements.find((e) => e.name === v.slice(1))?.id ?? v;
  if (Array.isArray(v)) return v.map((x) => fill(x, model, files));
  if (v && typeof v === 'object') {
    const o = Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, model, files)])) as Record<string, any>;
    // locate real quotes so honest citations carry correct lines; fabricated ones will not be found
    if (typeof o.quote === 'string' && typeof o.path === 'string') {
      const f = files.find((x) => x.path === o.path);
      const idx = f ? f.content.split('\n').findIndex((l) => l.includes(o.quote.split('  #')[0])) : -1;
      if (idx >= 0) { o.lineStart = idx + 1; o.lineEnd = idx + 1; }
    }
    return o;
  }
  return v;
};

const text = (p: any) => `${p.title ?? ''} ${p.action ?? ''} ${p.consequence ?? ''} ${(p.preconditions ?? []).join(' ')}`.toLowerCase();

export interface CaseResult { id: string; kept: number; discarded: string[]; found: string[]; missed: string[]; unsupported: string[]; fabricated: string[]; usage: unknown }

export async function evaluate(c: EvalCase, adapter: (c: EvalCase, model: Model, files: SourceFileInput[]) => ModelAdapter): Promise<CaseResult> {
  const { files, model } = load(c);
  const analysisFiles: AnalysisFile[] = files.map((f) => ({ path: f.path, text: f.content, hash: f.hash }));
  const out = await runAnalysis({ adapter: adapter(c, model, files), model, runId: 'run_eval', files: analysisFiles, budgets: { maxRetries: 1, timeoutMs: 120000 } });
  if (!out.ingest) return { id: c.id, kept: 0, discarded: [out.error ?? 'no output'], found: [], missed: c.expected.map((e) => e.id), unsupported: [], fabricated: [], usage: out.usage };
  const kept = out.ingest.proposals.filter((p) => p.payload.kind === 'add-threat');
  const targetName = (p: (typeof kept)[number]) => (p.payload.kind === 'add-threat' ? p.payload.targets.map((t) => model.elements.find((e) => e.id === t.ref)?.name ?? t.ref) : []);
  const found: string[] = [], missed: string[] = [];
  for (const e of c.expected) {
    const hit = kept.some((p) => targetName(p).includes(e.target) && e.keywords.every((g) => g.some((w) => text(p.payload).includes(w))));
    (hit ? found : missed).push(e.id);
  }
  const unsupported: string[] = [];
  for (const p of out.ingest.proposals) for (const a of c.absent) if (a.patterns.some((r) => r.test(`${text(p.payload)} ${p.reasoning}`))) unsupported.push(`${a.id}: "${(p.payload as any).title ?? p.payload.kind}"`);
  for (const d of out.ingest.discarded) unsupported.push(`discarded as ungrounded: ${d.reason}`);
  const fabricated = out.ingest.proposals.flatMap((p) => p.validationNotes.filter((n) => n.startsWith('Dropped unverifiable evidence')).map((n) => `${(p.payload as any).title}: ${n}`));
  return { id: c.id, kept: out.ingest.proposals.length, discarded: out.ingest.discarded.map((d) => d.reason), found, missed, unsupported, fabricated, usage: out.usage };
}

async function main() {
  const { values } = parseArgs({ options: { adapter: { type: 'string', default: 'simulated' }, variant: { type: 'string', default: 'good' }, out: { type: 'string' }, save: { type: 'boolean', default: false } } });
  const kind = values.adapter!;
  const results: CaseResult[] = [];
  for (const c of CASES) {
    results.push(await evaluate(c, (cc, model, files) => {
      if (kind === 'simulated') return new SimulatedAdapter((cc.simulated as any)[values.variant!].map((p: unknown) => fill(p, model, files)));
      const modelId = process.env.EVAL_MODEL;
      if (!modelId) throw new Error('Set EVAL_MODEL to the model identifier to evaluate.');
      if (kind === 'anthropic') return new AnthropicAdapter({ apiKey: process.env.ANTHROPIC_API_KEY, model: modelId, ...(process.env.EVAL_BASE_URL ? { baseUrl: process.env.EVAL_BASE_URL } : {}) });
      if (kind === 'openai-compatible') return new OpenAICompatibleAdapter({ baseUrl: process.env.EVAL_BASE_URL ?? '', model: modelId, apiKey: process.env.OPENAI_API_KEY });
      throw new Error(`Unknown adapter ${kind}`);
    }));
  }
  const sum = (f: (r: CaseResult) => number) => results.reduce((n, r) => n + f(r), 0);
  const expectedTotal = CASES.reduce((n, c) => n + c.expected.length, 0);
  const report = { evalSetVersion: EVAL_SET_VERSION, adapter: kind, variant: kind === 'simulated' ? values.variant : undefined, live: kind !== 'simulated', ran: new Date().toISOString(), totals: { expected: expectedTotal, found: sum((r) => r.found.length), missed: sum((r) => r.missed.length), unsupported: sum((r) => r.unsupported.length), fabricatedCitations: sum((r) => r.fabricated.length) }, cases: results };
  console.log(`Eval set v${EVAL_SET_VERSION}, adapter ${kind}${kind === 'simulated' ? ` (${values.variant}; validates the harness, not a model)` : ' (LIVE)'}`);
  for (const r of results) {
    console.log(`\n[${r.id}] found ${r.found.length}/${r.found.length + r.missed.length}`);
    if (r.missed.length) console.log(`  missed:      ${r.missed.join(', ')}`);
    if (r.unsupported.length) console.log(`  unsupported: ${r.unsupported.join(' | ')}`);
    if (r.fabricated.length) console.log(`  fabricated:  ${r.fabricated.length} citation(s) failed verification`);
  }
  console.log(`\nTOTAL: found ${report.totals.found}/${expectedTotal}, missed ${report.totals.missed}, unsupported ${report.totals.unsupported}, fabricated citations ${report.totals.fabricatedCitations}`);
  if (values.save || values.out) {
    const file = values.out ?? join(ROOT, 'results', `${kind}${kind === 'simulated' ? `-${values.variant}` : ''}.json`);
    writeFileSync(file, JSON.stringify(report, null, 2) + '\n');
    console.log(`Wrote ${file}`);
  }
}
if (process.argv[1]?.endsWith('run.ts')) main().catch((e) => { console.error(e.message); process.exit(1); });
