/**
 * Live provider check. Sends real requests to a real endpoint, so it needs credentials and may cost money.
 *   ANTHROPIC_API_KEY=... LIVE_MODEL=<model id> npm run live:check -- anthropic
 *   LIVE_BASE_URL=http://127.0.0.1:11434/v1 LIVE_MODEL=<model id> [OPENAI_API_KEY=...] npm run live:check -- openai-compatible
 * It sends one tiny structured request, then one small analysis of the bundled fictional "shop" fixture
 * (no project data). Exit 0 only if both return valid, validated output.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { buildNorthwindExample } from '@threatweave/core';
import { AnthropicAdapter, OpenAICompatibleAdapter, runAnalysis, type ModelAdapter } from '@threatweave/ai';

const kind = process.argv[2];
const model = process.env.LIVE_MODEL;
if (!model || (kind !== 'anthropic' && kind !== 'openai-compatible')) { console.error('usage: LIVE_MODEL=<id> live-check <anthropic|openai-compatible>'); process.exit(2); }
const adapter: ModelAdapter = kind === 'anthropic'
  ? new AnthropicAdapter({ apiKey: process.env.ANTHROPIC_API_KEY, model, ...(process.env.LIVE_BASE_URL ? { baseUrl: process.env.LIVE_BASE_URL } : {}) })
  : new OpenAICompatibleAdapter({ baseUrl: process.env.LIVE_BASE_URL ?? '', model, apiKey: process.env.OPENAI_API_KEY, jsonMode: (process.env.LIVE_JSON_MODE as 'json_object') ?? 'json_object' });
console.log(`Sending to ${adapter.endpointHost} with model ${adapter.modelId}`);

const ping = await adapter.complete({ system: 'Reply with the JSON object {"ok": true}.', user: 'ping', jsonSchema: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'], additionalProperties: false }, schemaName: 'ping', maxOutputTokens: 200 }, AbortSignal.timeout(60000)).catch((e) => { console.error('PING FAILED:', e.kind, e.message); process.exit(1); });
console.log('ping ok:', JSON.stringify(ping.text).slice(0, 80), 'usage', ping.usage);

const dir = new URL('../evals/systems/shop/', import.meta.url);
const content = readFileSync(new URL('docker-compose.yml', dir), 'utf8');
const hash = createHash('sha256').update(content).digest('hex');
const m = buildNorthwindExample([{ path: 'docker-compose.yml', content, hash }], 'live-check');
const out = await runAnalysis({ adapter, model: m, runId: 'run_live', files: [{ path: 'docker-compose.yml', text: content, hash }], budgets: { timeoutMs: 180000 } });
console.log(`analysis: ${out.status}; kept ${out.ingest?.proposals.length ?? 0}, discarded ${out.ingest?.discarded.length ?? 0}; usage`, out.usage);
for (const d of out.ingest?.discarded ?? []) console.log('  discarded:', d.reason);
for (const p of out.ingest?.proposals ?? []) console.log(`  [${p.basis}] ${p.payload.kind}: ${'title' in p.payload ? p.payload.title : 'name' in p.payload ? p.payload.name : ''} (evidence verified: ${p.evidence.filter((e) => e.verified).length}/${p.evidence.length})`);
process.exit(out.status === 'completed' ? 0 : 1);
