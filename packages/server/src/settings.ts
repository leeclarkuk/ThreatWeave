import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createAdapter, DEFAULT_BUDGETS, type AdapterSettings, type Budgets, type ModelAdapter } from '@threatweave/ai';

export interface Settings {
  /** Name recorded on your decisions. */
  actor: string;
  ai: {
    adapter: 'anthropic' | 'openai-compatible';
    anthropic: { model: string; baseUrl: string };
    openaiCompatible: { model: string; baseUrl: string; jsonMode: 'json_schema' | 'json_object' | 'none'; maxTokensParam: 'max_tokens' | 'max_completion_tokens' };
    budgets: { maxInputTokens: number; maxOutputTokens: number; maxTotalTokens: number; maxRetries: number; timeoutSeconds: number; maxCostUsd: number | null };
    prices: { inputPerMTok: number; outputPerMTok: number } | null;
  };
}

export const DEFAULT_SETTINGS: Settings = {
  actor: 'local-user',
  ai: {
    adapter: 'anthropic',
    // Model identifiers are configuration, never hard-coded. Set yours in Settings.
    anthropic: { model: '', baseUrl: 'https://api.anthropic.com' },
    openaiCompatible: { model: '', baseUrl: 'http://127.0.0.1:11434/v1', jsonMode: 'json_object', maxTokensParam: 'max_tokens' },
    budgets: { maxInputTokens: DEFAULT_BUDGETS.maxInputTokens, maxOutputTokens: DEFAULT_BUDGETS.maxOutputTokens, maxTotalTokens: DEFAULT_BUDGETS.maxTotalTokens, maxRetries: DEFAULT_BUDGETS.maxRetries, timeoutSeconds: DEFAULT_BUDGETS.timeoutMs / 1000, maxCostUsd: null },
    prices: null,
  },
};

type SecretName = 'anthropic' | 'openaiCompatible';
interface Stored { settings: Settings; secrets: Partial<Record<SecretName, string>> }

const ENV_KEYS: Record<SecretName, string[]> = {
  anthropic: ['THREATWEAVE_ANTHROPIC_API_KEY', 'ANTHROPIC_API_KEY'],
  openaiCompatible: ['THREATWEAVE_OPENAI_API_KEY', 'OPENAI_API_KEY'],
};

/**
 * Local settings and credentials. Credentials live in config.json (mode 0600) or in environment
 * variables, and are never sent to the browser, written to models, or logged. They are stored in
 * plaintext: protect the data directory like you would ~/.aws/credentials.
 */
export class SettingsStore {
  private file: string;
  private cache: Stored | undefined;
  constructor(dir: string) { this.file = join(dir, 'config.json'); }

  private async read(): Promise<Stored> {
    if (this.cache) return this.cache;
    let raw: Partial<Stored> = {};
    try { raw = JSON.parse(await readFile(this.file, 'utf8')); } catch { /* defaults */ }
    const s = raw.settings ?? ({} as Partial<Settings>);
    this.cache = {
      settings: { ...DEFAULT_SETTINGS, ...s, ai: { ...DEFAULT_SETTINGS.ai, ...(s.ai ?? {}), anthropic: { ...DEFAULT_SETTINGS.ai.anthropic, ...(s.ai?.anthropic ?? {}) }, openaiCompatible: { ...DEFAULT_SETTINGS.ai.openaiCompatible, ...(s.ai?.openaiCompatible ?? {}) }, budgets: { ...DEFAULT_SETTINGS.ai.budgets, ...(s.ai?.budgets ?? {}) } } },
      secrets: raw.secrets ?? {},
    };
    return this.cache;
  }
  private async write(s: Stored) {
    await mkdir(dirname(this.file), { recursive: true, mode: 0o700 });
    await writeFile(this.file, JSON.stringify(s, null, 2) + '\n', { mode: 0o600 });
    await chmod(this.file, 0o600);
    this.cache = s;
  }

  async get(): Promise<Settings> { return (await this.read()).settings; }
  async put(patch: Settings): Promise<Settings> {
    const cur = await this.read();
    const next: Settings = { ...patch, actor: (patch.actor ?? '').trim().slice(0, 100) || cur.settings.actor };
    await this.write({ ...cur, settings: next });
    return next;
  }
  async setSecret(name: SecretName, value: string | null) {
    const cur = await this.read();
    const secrets = { ...cur.secrets };
    if (value) secrets[name] = value.trim(); else delete secrets[name];
    await this.write({ ...cur, secrets });
  }
  private async key(name: SecretName): Promise<{ value?: string; source: 'env' | 'file' | null }> {
    for (const e of ENV_KEYS[name]) if (process.env[e]) return { value: process.env[e]!, source: 'env' };
    const v = (await this.read()).secrets[name];
    return v ? { value: v, source: 'file' } : { source: null };
  }
  /** What the browser may see: whether a key exists and where from. Never the key. */
  async secretStatus() {
    const out: Record<SecretName, { configured: boolean; source: 'env' | 'file' | null; envNames: string[] }> = {
      anthropic: { configured: false, source: null, envNames: ENV_KEYS.anthropic },
      openaiCompatible: { configured: false, source: null, envNames: ENV_KEYS.openaiCompatible },
    };
    for (const n of ['anthropic', 'openaiCompatible'] as const) { const k = await this.key(n); out[n] = { ...out[n], configured: !!k.value, source: k.source }; }
    return out;
  }

  async adapter(): Promise<ModelAdapter> {
    const s = (await this.read()).settings.ai;
    if (s.adapter === 'anthropic') {
      const k = await this.key('anthropic');
      const cfg: AdapterSettings = { adapter: 'anthropic', model: s.anthropic.model, baseUrl: s.anthropic.baseUrl || undefined, apiKey: k.value };
      return createAdapter(cfg);
    }
    const k = await this.key('openaiCompatible');
    return createAdapter({ adapter: 'openai-compatible', baseUrl: s.openaiCompatible.baseUrl, model: s.openaiCompatible.model, apiKey: k.value, jsonMode: s.openaiCompatible.jsonMode, maxTokensParam: s.openaiCompatible.maxTokensParam });
  }
  async budgets(): Promise<Partial<Budgets>> {
    const b = (await this.read()).settings.ai;
    return { maxInputTokens: b.budgets.maxInputTokens, maxOutputTokens: b.budgets.maxOutputTokens, maxTotalTokens: b.budgets.maxTotalTokens, maxRetries: b.budgets.maxRetries, timeoutMs: b.budgets.timeoutSeconds * 1000, maxCostUsd: b.budgets.maxCostUsd ?? undefined, prices: b.prices ?? undefined };
  }
}
