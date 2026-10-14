/** Provider-neutral contract. Nothing in the domain model imports provider SDKs or formats. */

export interface AdapterCapabilities {
  id: string;
  displayName: string;
  /** How structured output is requested from the provider. */
  structuredOutput: 'json_schema' | 'json_object' | 'prompt-only';
  /** Whether token usage is read from the provider response. */
  reportsUsage: boolean;
  /** True only when this adapter has been exercised against a real endpoint. Set by documentation/tests, never assumed. */
  liveVerified: boolean;
  notes: string[];
}

export interface CompletionRequest {
  system: string;
  user: string;
  /** JSON schema for the expected output. Providers may simplify it; the caller always validates. */
  jsonSchema: Record<string, unknown>;
  schemaName: string;
  maxOutputTokens: number;
}

export interface CompletionResult {
  /** Raw text returned by the provider. Parsed and validated by the caller. */
  text: string;
  usage: { inputTokens: number | null; outputTokens: number | null };
  stopReason: string | null;
  /** Provider's served model id, if reported. */
  model: string | null;
}

export type AdapterErrorKind =
  | 'auth' | 'rate_limit' | 'overloaded' | 'server' | 'network' | 'timeout' | 'cancelled'
  | 'bad_request' | 'refused' | 'truncated' | 'malformed' | 'not_configured';

export class AdapterError extends Error {
  constructor(
    public kind: AdapterErrorKind,
    message: string,
    public opts: { status?: number; retryAfterMs?: number } = {},
  ) {
    super(message);
    this.name = 'AdapterError';
  }
  get retryable(): boolean {
    return ['rate_limit', 'overloaded', 'server', 'network', 'timeout'].includes(this.kind);
  }
}

export interface ModelAdapter {
  readonly id: string;
  /** Configured model identifier (never hard-coded). */
  readonly modelId: string;
  /** Host the request would be sent to, for the "what may be sent where" disclosure. */
  readonly endpointHost: string;
  capabilities(): AdapterCapabilities;
  complete(req: CompletionRequest, signal?: AbortSignal): Promise<CompletionResult>;
}

/** Never let a credential reach logs or error messages. */
export function scrub(message: string, secrets: Array<string | undefined>): string {
  let out = message;
  for (const s of secrets) if (s && s.length > 6) out = out.split(s).join('[redacted]');
  return out.slice(0, 600);
}
