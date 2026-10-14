import type { Model, Issue } from '@threatweave/core';

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: any) { super(message); }
}

async function req<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(path, {
    method, headers: { 'content-type': 'application/json', 'x-threatweave': '1', ...headers },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let json: any; try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
  if (!res.ok) throw new ApiError(res.status, json?.error ?? `Request failed (${res.status})`, json);
  return json as T;
}

export interface ProjectSummary { id: string; name: string; example: boolean; updatedAt: string; counts: { elements: number; threats: number; mitigations: number; openReview: number; pendingProposals: number } }
export interface ScanResult { root: string; label: string; vcsRevision?: string; files: Array<{ path: string; bytes: number; hash: string; role: 'config' | 'document' }>; skipped: Array<{ path: string; reason: string }>; totalBytes: number; truncated: boolean; supported: string[]; unsupported: string[]; limits: Record<string, number> }
export interface Disclosure { adapter: string; model: string; host: string; files: Array<{ path: string; bytes: number; role: string }>; totalBytes: number; redactions: number; note: string; capabilities: { notes: string[]; liveVerified: boolean; structuredOutput: string } }
export interface SettingsPayload {
  settings: { actor: string; ai: { adapter: 'anthropic' | 'openai-compatible'; anthropic: { model: string; baseUrl: string }; openaiCompatible: { model: string; baseUrl: string; jsonMode: 'json_schema' | 'json_object' | 'none'; maxTokensParam: 'max_tokens' | 'max_completion_tokens' }; budgets: { maxInputTokens: number; maxOutputTokens: number; maxTotalTokens: number; maxRetries: number; timeoutSeconds: number; maxCostUsd: number | null }; prices: { inputPerMTok: number; outputPerMTok: number } | null } };
  secrets: Record<'anthropic' | 'openaiCompatible', { configured: boolean; source: 'env' | 'file' | null; envNames: string[] }>;
  active: { id: string; model: string; host: string; capabilities: { notes: string[]; liveVerified: boolean; structuredOutput: string; displayName: string } };
}

export const api = {
  health: () => req<{ ok: boolean }>('GET', '/api/health'),
  projects: () => req<ProjectSummary[]>('GET', '/api/projects'),
  create: (b: Record<string, unknown>) => req<{ id: string; warnings: Array<{ level: string; code: string; message: string; count: number }> }>('POST', '/api/projects', b),
  load: (id: string) => req<{ model: Model; etag: string; issues: Issue[] }>('GET', `/api/projects/${id}`),
  save: (id: string, model: Model, etag: string) => req<{ etag: string; issues: Issue[] }>('PUT', `/api/projects/${id}`, { model }, { 'if-match': etag }),
  remove: (id: string) => req<{ ok: boolean }>('DELETE', `/api/projects/${id}`),
  importPreview: (kind: 'tc' | 'native', data: unknown) => req<{ ok: boolean; error?: string; name?: string; stats?: Record<string, number>; warnings: Array<{ level: string; code: string; message: string; count: number }>; issues: Issue[] }>('POST', '/api/import/preview', { kind, data }),
  revisions: (id: string) => req<Array<{ id: string; size: number }>>('GET', `/api/projects/${id}/revisions`),
  snapshot: (id: string, label: string) => req<{ id: string }>('POST', `/api/projects/${id}/revisions`, { label }),
  revision: (id: string, rid: string) => req<{ model: Model }>('GET', `/api/projects/${id}/revisions/${rid}`),
  scan: (id: string, path: string) => req<{ scan: ScanResult; disclosure: Disclosure | null }>('POST', `/api/projects/${id}/source/scan`, { path }),
  sync: (id: string, path: string) => req<{ summary: { changes: Array<{ kind: string; summary: string }>; reviewItems: number; proposals: number; notes: string[]; stats: Record<string, number> }; etag: string }>('POST', `/api/projects/${id}/source/sync`, { path }),
  analyze: (id: string, b: { path: string; files: string[]; expectHost: string; confirmSend: boolean; focus?: string }) => req<{ runId: string }>('POST', `/api/projects/${id}/source/analyze`, b),
  run: (id: string, rid: string) => req<{ run: Model['runs'][number]; log: string[] }>('GET', `/api/projects/${id}/runs/${rid}`),
  cancelRun: (id: string, rid: string) => req<{ ok: boolean; note: string }>('POST', `/api/projects/${id}/runs/${rid}/cancel`, {}),
  settings: () => req<SettingsPayload>('GET', '/api/settings'),
  putSettings: (settings: SettingsPayload['settings']) => req<unknown>('PUT', '/api/settings', { settings }),
  putSecret: (name: 'anthropic' | 'openaiCompatible', value: string) => req<unknown>('PUT', '/api/settings/secret', { name, value }),
  testAi: () => req<{ ok: boolean; host: string; model: string; ms?: number; error?: string; usage?: { inputTokens: number | null; outputTokens: number | null } }>('POST', '/api/ai/test', {}),
  examples: () => req<{ models: Array<{ id: string; label: string }>; repos: Array<{ id: string; label: string; path: string }> }>('GET', '/api/examples'),
  exportFile: async (id: string, format: 'json' | 'markdown' | 'tc') => {
    const res = await fetch(`/api/projects/${id}/export?format=${format}`, { headers: { 'x-threatweave': '1' } });
    if (!res.ok) throw new ApiError(res.status, 'Export failed');
    const warnings = res.headers.get('x-conversion-warnings');
    const cd = res.headers.get('content-disposition') ?? '';
    return { text: await res.text(), filename: /filename="([^"]+)"/.exec(cd)?.[1] ?? `${id}.${format}`, warnings: warnings ? (JSON.parse(decodeURIComponent(warnings)) as Array<{ level: string; code: string; message: string; count: number }>) : [] };
  },
};
