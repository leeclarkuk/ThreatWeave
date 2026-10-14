import { AdapterError, scrub, type AdapterCapabilities, type CompletionRequest, type CompletionResult, type ModelAdapter } from './types.js';
import { simplifySchema } from './schema.js';

export interface OpenAICompatibleConfig {
  /** Base URL including any /v1 prefix, e.g. https://api.example.com/v1 */
  baseUrl: string;
  model: string;
  apiKey?: string | undefined;
  /** How to ask for JSON. Servers differ; pick what yours supports. */
  jsonMode?: 'json_schema' | 'json_object' | 'none';
  /** Some servers want max_completion_tokens instead of max_tokens. */
  maxTokensParam?: 'max_tokens' | 'max_completion_tokens';
  extraHeaders?: Record<string, string>;
}

/**
 * Adapter for servers exposing POST {baseUrl}/chat/completions. It speaks the request and response
 * subset below and nothing else. It does NOT claim compatibility with every server or local model:
 * only the controlled fixture server in this repository has exercised it.
 */
export class OpenAICompatibleAdapter implements ModelAdapter {
  readonly id = 'openai-compatible';
  readonly modelId: string;
  readonly endpointHost: string;
  constructor(private cfg: OpenAICompatibleConfig) {
    this.modelId = cfg.model;
    this.endpointHost = new URL(cfg.baseUrl).host;
  }
  capabilities(): AdapterCapabilities {
    const mode = this.cfg.jsonMode ?? 'json_object';
    return {
      id: this.id, displayName: 'OpenAI-compatible chat completions', structuredOutput: mode === 'none' ? 'prompt-only' : mode,
      reportsUsage: true, liveVerified: false,
      notes: [
        'Uses POST {baseUrl}/chat/completions with system and user messages. Streaming, tools and images are not used.',
        `JSON mode "${mode}": json_schema sends response_format json_schema; json_object sends response_format json_object plus the schema in the prompt; none relies on the prompt alone.`,
        'Usage is read from usage.prompt_tokens and usage.completion_tokens when the server returns them; otherwise it is reported as unavailable.',
        'Verified only against the simulated fixture server in this repository. Hosted OpenAI models and local servers (Ollama, llama.cpp, vLLM and similar) are untested here, so treat compatibility as unconfirmed until you run the live check.',
      ],
    };
  }
  async complete(req: CompletionRequest, signal?: AbortSignal): Promise<CompletionResult> {
    const mode = this.cfg.jsonMode ?? 'json_object';
    const system = mode === 'json_schema' ? req.system : `${req.system}\n\nReturn ONLY a JSON object matching this JSON Schema, with no prose and no code fence:\n${JSON.stringify(simplifySchema(req.jsonSchema))}`;
    const body: Record<string, unknown> = {
      model: this.cfg.model, messages: [{ role: 'system', content: system }, { role: 'user', content: req.user }],
      [this.cfg.maxTokensParam ?? 'max_tokens']: req.maxOutputTokens,
    };
    if (mode === 'json_schema') body.response_format = { type: 'json_schema', json_schema: { name: req.schemaName, schema: simplifySchema(req.jsonSchema), strict: false } };
    else if (mode === 'json_object') body.response_format = { type: 'json_object' };
    let res: Response;
    try {
      res = await fetch(`${this.cfg.baseUrl.replace(/\/+$/, '')}/chat/completions`, {
        method: 'POST', body: JSON.stringify(body), ...(signal ? { signal } : {}),
        headers: { 'content-type': 'application/json', ...(this.cfg.apiKey ? { authorization: `Bearer ${this.cfg.apiKey}` } : {}), ...(this.cfg.extraHeaders ?? {}) },
      });
    } catch (e) {
      const err = e as Error;
      if (err.name === 'AbortError' || signal?.aborted) throw new AdapterError(signal?.reason?.name === 'TimeoutError' ? 'timeout' : 'cancelled', signal?.reason?.name === 'TimeoutError' ? 'The server did not respond in time.' : 'Cancelled.');
      if (err.name === 'TimeoutError') throw new AdapterError('timeout', 'The server did not respond in time.');
      throw new AdapterError('network', `Could not reach ${this.endpointHost}: ${scrub(err.message, [this.cfg.apiKey])}`);
    }
    if (!res.ok) {
      const ra = Number(res.headers.get('retry-after'));
      const o = { status: res.status, ...(Number.isFinite(ra) && ra > 0 ? { retryAfterMs: Math.min(ra * 1000, 60_000) } : {}) };
      let detail = '';
      try { detail = scrub(await res.text(), [this.cfg.apiKey]).slice(0, 300); } catch { /* ignore */ }
      if (res.status === 401 || res.status === 403) throw new AdapterError('auth', `Authentication failed (${res.status}).`, o);
      if (res.status === 429) throw new AdapterError('rate_limit', 'Rate limited by the server.', o);
      if (res.status >= 500) throw new AdapterError('server', `Server error ${res.status}.`, o);
      throw new AdapterError('bad_request', `Server rejected the request (${res.status}): ${detail}`, o);
    }
    let json: any;
    try { json = await res.json(); } catch { throw new AdapterError('malformed', 'The server returned a non-JSON response body.'); }
    const choice = json?.choices?.[0];
    const text = choice?.message?.content;
    if (typeof text !== 'string') throw new AdapterError('malformed', 'The response had no choices[0].message.content text.');
    if (choice?.finish_reason === 'length') throw new AdapterError('truncated', 'The response hit the output token limit and is incomplete.');
    if (choice?.finish_reason === 'content_filter') throw new AdapterError('refused', 'The server filtered this response.');
    const u = json?.usage;
    return {
      text, stopReason: choice?.finish_reason ?? null, model: typeof json?.model === 'string' ? json.model : null,
      usage: { inputTokens: Number.isInteger(u?.prompt_tokens) ? u.prompt_tokens : null, outputTokens: Number.isInteger(u?.completion_tokens) ? u.completion_tokens : null },
    };
  }
}
