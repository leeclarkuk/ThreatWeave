export * from './types.js';
export * from './schema.js';
export * from './anthropic.js';
export * from './openai.js';
export * from './prompt.js';
export * from './orchestrator.js';

import { AnthropicAdapter, type AnthropicConfig } from './anthropic.js';
import { OpenAICompatibleAdapter, type OpenAICompatibleConfig } from './openai.js';
import type { ModelAdapter } from './types.js';

export type AdapterSettings =
  | ({ adapter: 'anthropic' } & AnthropicConfig)
  | ({ adapter: 'openai-compatible' } & OpenAICompatibleConfig);

/** Add new providers here: implement ModelAdapter and register a case. Nothing else needs to change. */
export function createAdapter(s: AdapterSettings): ModelAdapter {
  switch (s.adapter) {
    case 'anthropic': return new AnthropicAdapter(s);
    case 'openai-compatible': return new OpenAICompatibleAdapter(s);
  }
}
