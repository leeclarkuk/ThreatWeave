import {
  AI_OUTPUT_JSON_SCHEMA, AiOutput, ingestAiOutput, type IngestResult, type Model, type Usage,
} from '@threatweave/core';
import { AdapterError, type ModelAdapter } from './types.js';
import { parseJsonLoose } from './schema.js';
import { PROMPT_VERSION, SYSTEM_PROMPT, buildUserPrompt, estimateTokens, type AnalysisFile } from './prompt.js';

export interface Budgets {
  /** Refuse to send if the estimated input exceeds this. */
  maxInputTokens: number;
  maxOutputTokens: number;
  /** Cap across all attempts in one run (actual usage when reported, estimate otherwise). */
  maxTotalTokens: number;
  /** Total attempts = 1 + maxRetries. Hard-capped at 3 retries regardless of configuration. */
  maxRetries: number;
  timeoutMs: number;
  /** Optional currency cap; only enforceable when prices are configured. */
  maxCostUsd?: number | undefined;
  /** USD per million tokens. If absent, cost is reported as unavailable. */
  prices?: { inputPerMTok: number; outputPerMTok: number } | undefined;
}

export const DEFAULT_BUDGETS: Budgets = {
  maxInputTokens: 60_000, maxOutputTokens: 16_000, maxTotalTokens: 200_000, maxRetries: 2, timeoutMs: 180_000,
};

export interface AnalysisOutcome {
  status: 'completed' | 'failed' | 'cancelled';
  ingest: IngestResult | null;
  usage: Usage;
  attempts: number;
  error?: string;
  errorKind?: string;
  promptVersion: string;
  estimatedInputTokens: number;
  log: string[];
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(new AdapterError('cancelled', 'Cancelled.'));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new AdapterError('cancelled', 'Cancelled.')); }, { once: true });
  });

/**
 * One bounded analysis. Single provider call per attempt (no multi-agent fan-out: a single
 * structured call is the simplest thing that works; add agents only if measured quality warrants).
 * Never mutates the model: returns validated pending proposals for the caller to store.
 */
export async function runAnalysis(args: {
  adapter: ModelAdapter;
  model: Model;
  runId: string;
  sourceId?: string | undefined;
  files: AnalysisFile[];
  focus?: string | undefined;
  budgets?: Partial<Budgets>;
  signal?: AbortSignal | undefined;
  onLog?: (line: string) => void;
}): Promise<AnalysisOutcome> {
  const b: Budgets = { ...DEFAULT_BUDGETS, ...args.budgets };
  b.maxRetries = Math.min(Math.max(0, b.maxRetries), 3);
  const log: string[] = [];
  const say = (s: string) => { log.push(s); args.onLog?.(s); };
  const usage: Usage = { inputTokens: null, outputTokens: null, costUsd: null, note: '' };
  const user = buildUserPrompt(args.model, args.files, args.focus ? { focus: args.focus } : {});
  const estIn = estimateTokens(SYSTEM_PROMPT) + estimateTokens(user);
  const base = { promptVersion: PROMPT_VERSION, estimatedInputTokens: estIn, log };
  const fileMap = new Map(args.files.map((f) => [f.path, f.text]));
  const fail = (status: 'failed' | 'cancelled', error: string, kind: string, attempts: number): AnalysisOutcome =>
    ({ status, ingest: null, usage: finalise(), attempts, error, errorKind: kind, ...base });

  let inTok = 0, outTok = 0, known = true;
  const finalise = (): Usage => {
    const u: Usage = { inputTokens: known && inTok > 0 ? inTok : null, outputTokens: known && outTok > 0 ? outTok : null, costUsd: null, note: '' };
    if (u.inputTokens === null) u.note = 'The provider did not report token usage; nothing is estimated as actual usage.';
    if (b.prices && u.inputTokens !== null && u.outputTokens !== null)
      u.costUsd = (u.inputTokens * b.prices.inputPerMTok + u.outputTokens * b.prices.outputPerMTok) / 1_000_000;
    else u.note = `${u.note} Cost unavailable: no prices configured.`.trim();
    return u;
  };

  if (estIn > b.maxInputTokens)
    return fail('failed', `Estimated input is about ${estIn} tokens, above the configured limit of ${b.maxInputTokens}. Select fewer files. Nothing was sent.`, 'budget', 0);

  let lastError: AdapterError | undefined;
  let repairNote = '';
  const maxAttempts = 1 + b.maxRetries;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (args.signal?.aborted) return fail('cancelled', 'Cancelled before sending.', 'cancelled', attempt - 1);
    const spent = (inTok + outTok) || 0;
    if (spent + estIn > b.maxTotalTokens && attempt > 1)
      return fail('failed', `Stopped: another attempt would exceed the total token budget of ${b.maxTotalTokens}.`, 'budget', attempt - 1);
    const timeout = AbortSignal.timeout(b.timeoutMs);
    const signal = args.signal ? AbortSignal.any([args.signal, timeout]) : timeout;
    say(`attempt ${attempt}/${maxAttempts}: sending ${args.files.length} file(s) to ${args.adapter.endpointHost}`);
    try {
      const res = await args.adapter.complete({
        system: SYSTEM_PROMPT, user: repairNote ? `${user}\n\n${repairNote}` : user, jsonSchema: AI_OUTPUT_JSON_SCHEMA,
        schemaName: 'threat_model_proposals', maxOutputTokens: b.maxOutputTokens,
      }, signal);
      if (res.usage.inputTokens === null || res.usage.outputTokens === null) known = false;
      else { inTok += res.usage.inputTokens; outTok += res.usage.outputTokens; }
      const parsed = parseJsonLoose(res.text);
      const top = AiOutput.safeParse(parsed);
      if (parsed === undefined || !top.success) {
        lastError = new AdapterError('malformed', 'The model did not return valid JSON in the required shape.');
        say(`attempt ${attempt}: malformed output`);
        repairNote = 'Your previous reply was not valid JSON in the required shape. Reply again with only the JSON object.';
        if (b.maxCostUsd !== undefined && finalise().costUsd !== null && finalise().costUsd! > b.maxCostUsd) return fail('failed', 'Stopped: cost budget exceeded.', 'budget', attempt);
        continue;
      }
      const ingest = ingestAiOutput(args.model, parsed, { runId: args.runId, ...(args.sourceId ? { sourceId: args.sourceId } : {}), files: fileMap });
      say(`validated: ${ingest.proposals.length} proposal(s) kept, ${ingest.discarded.length} discarded`);
      return { status: 'completed', ingest, usage: finalise(), attempts: attempt, ...base };
    } catch (e) {
      let err = e instanceof AdapterError ? e : new AdapterError('network', (e as Error).message);
      if (err.kind === 'cancelled' && !args.signal?.aborted && timeout.aborted) err = new AdapterError('timeout', 'The provider did not respond in time.');
      if (err.kind === 'cancelled') return fail('cancelled', 'Cancelled. The project was not changed.', 'cancelled', attempt);
      lastError = err;
      say(`attempt ${attempt}: ${err.kind}`);
      if (!err.retryable || attempt === maxAttempts) break;
      const wait = err.opts.retryAfterMs ?? Math.min(500 * 2 ** (attempt - 1), 8000) + Math.floor(Math.random() * 250);
      try { await sleep(wait, args.signal); } catch { return fail('cancelled', 'Cancelled while waiting to retry.', 'cancelled', attempt); }
    }
  }
  return fail('failed', lastError ? `${lastError.message}${lastError.kind === 'malformed' ? ' Retries exhausted.' : ''}` : 'Analysis failed.', lastError?.kind ?? 'unknown', maxAttempts);
}
