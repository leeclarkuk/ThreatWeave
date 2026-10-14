/**
 * Providers accept different JSON Schema subsets. We keep structure (types, enums, required,
 * additionalProperties) and drop validation keywords providers commonly reject. Strict
 * validation still happens locally against the full zod schema.
 */
const DROP = new Set([
  'maxItems', 'minItems', 'maxLength', 'minLength', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
  'pattern', 'format', 'default', '$schema', 'title', 'description', 'examples', 'multipleOf', 'uniqueItems',
]);

export function simplifySchema(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(simplifySchema);
  if (!node || typeof node !== 'object') return node;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (DROP.has(k)) continue;
    if (k === 'oneOf') { out.anyOf = simplifySchema(v); continue; }
    out[k] = k === 'properties' && v && typeof v === 'object'
      ? Object.fromEntries(Object.entries(v).map(([pk, pv]) => [pk, simplifySchema(pv)]))
      : simplifySchema(v);
  }
  if (out.type === 'object' && out.properties && !('additionalProperties' in out)) out.additionalProperties = false;
  return out;
}

/** Extract a JSON value from model text, tolerating a code fence or leading prose. Returns undefined if none. */
export function parseJsonLoose(text: string): unknown | undefined {
  const t = text.trim();
  try { return JSON.parse(t); } catch { /* fall through */ }
  const fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(t);
  if (fence) { try { return JSON.parse(fence[1]!.trim()); } catch { /* fall through */ } }
  const first = t.indexOf('{'), last = t.lastIndexOf('}');
  if (first >= 0 && last > first) { try { return JSON.parse(t.slice(first, last + 1)); } catch { /* none */ } }
  return undefined;
}
