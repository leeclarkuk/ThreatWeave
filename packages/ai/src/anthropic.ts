import Anthropic from '@anthropic-ai/sdk';
import { AdapterError, scrub, type AdapterCapabilities, type CompletionRequest, type CompletionResult, type ModelAdapter } from './types.js';
import { simplifySchema } from './schema.js';

export interface AnthropicConfig {
  apiKey?: string | undefined;
  /** Model identifier. Required: nothing is hard-coded. */
  model: string;
  baseUrl?: string | undefined;
  /** 'schema' sends output_config.format (json_schema). 'prompt' asks for JSON in the prompt only. */
  structuredOutput?: 'schema' | 'prompt';
}

const retryAfter = (h: unknown): number | undefined => {
  const raw = h && typeof (h as Headers).get === 'function' ? (h as Headers).get('retry-after') : (h as Record<string, string> | undefined)?.['retry-after'];
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) ? Math.min(n * 1000, 60_000) : undefined;
};

/**
 * Anthropic Messages API adapter. Uses structured outputs (output_config.format) rather than
 * forced tool use, which current models reject. Sampling parameters and thinking settings are
 * deliberately omitted so the adapter works across model generations.
 */
export class AnthropicAdapter implements ModelAdapter {
  readonly id = 'anthropic';
  readonly modelId: string;
  readonly endpointHost: string;
  private client: Anthropic | undefined;
  constructor(private cfg: AnthropicConfig) {
    this.modelId = cfg.model;
    this.endpointHost = new URL(cfg.baseUrl ?? 'https://api.anthropic.com').host;
    if (cfg.apiKey) this.client = new Anthropic({ apiKey: cfg.apiKey, ...(cfg.baseUrl ? { baseURL: cfg.baseUrl } : {}), maxRetries: 0 });
  }
  capabilities(): AdapterCapabilities {
    return {
      id: this.id, displayName: 'Anthropic Messages API', structuredOutput: this.cfg.structuredOutput === 'prompt' ? 'prompt-only' : 'json_schema',
      reportsUsage: true, liveVerified: false,
      notes: [
        'Requests use output_config.format with a simplified JSON schema; every response is re-validated locally against the full schema.',
        'Forced tool_choice is not used (rejected by current models). Temperature and thinking settings are omitted.',
        'Contract-tested against a local simulated server only. Not live-verified in this repository: run `npm run test:live` with credentials to verify.',
        'Cost is not computed unless you configure prices; the API reports tokens, not currency.',
      ],
    };
  }
  async complete(req: CompletionRequest, signal?: AbortSignal): Promise<CompletionResult> {
    if (!this.client) throw new AdapterError('not_configured', 'No Anthropic API key configured (set ANTHROPIC_API_KEY or save one in settings).');
    try {
      const body: Record<string, unknown> = {
        model: this.cfg.model, max_tokens: req.maxOutputTokens, system: req.system,
        messages: [{ role: 'user', content: req.user }],
      };
      if (this.cfg.structuredOutput !== 'prompt') body.output_config = { format: { type: 'json_schema', schema: simplifySchema(req.jsonSchema) } };
      const res = await this.client.messages.create(body as unknown as Anthropic.MessageCreateParamsNonStreaming, { ...(signal ? { signal } : {}) });
      if (res.stop_reason === 'refusal') throw new AdapterError('refused', 'The provider declined this request (safety refusal). Nothing was added to the model.');
      if (res.stop_reason === 'max_tokens') throw new AdapterError('truncated', 'The response hit the output token limit and is incomplete. Narrow the input or raise the output budget.');
      const text = res.content.filter((b): b is Anthropic.TextBlock => b.type === 'text').map((b) => b.text).join('');
      return {
        text, stopReason: res.stop_reason ?? null, model: res.model ?? null,
        usage: { inputTokens: res.usage?.input_tokens ?? null, outputTokens: res.usage?.output_tokens ?? null },
      };
    } catch (e) {
      throw this.classify(e);
    }
  }
  private classify(e: unknown): AdapterError {
    if (e instanceof AdapterError) return e;
    const msg = scrub((e as Error)?.message ?? String(e), [this.cfg.apiKey]);
    if (e instanceof Anthropic.APIUserAbortError) return new AdapterError('cancelled', 'Cancelled.');
    if (e instanceof Anthropic.APIConnectionTimeoutError) return new AdapterError('timeout', 'The provider did not respond in time.');
    if (e instanceof Anthropic.APIConnectionError) return new AdapterError('network', `Could not reach ${this.endpointHost}: ${msg}`);
    if (e instanceof Anthropic.APIError) {
      const status = e.status ?? 0;
      const ra = retryAfter(e.headers);
      const o = ra !== undefined ? { status, retryAfterMs: ra } : { status };
      if (status === 401 || status === 403) return new AdapterError('auth', `Authentication failed (${status}). Check the API key and its permissions.`, o);
      if (status === 429) return new AdapterError('rate_limit', 'Rate limited by the provider.', o);
      if (status === 529) return new AdapterError('overloaded', 'The provider is temporarily overloaded.', o);
      if (status >= 500) return new AdapterError('server', `Provider error ${status}.`, o);
      return new AdapterError('bad_request', `Provider rejected the request (${status}): ${msg}`, o);
    }
    if ((e as Error)?.name === 'AbortError') return new AdapterError('cancelled', 'Cancelled.');
    return new AdapterError('network', msg);
  }
}
