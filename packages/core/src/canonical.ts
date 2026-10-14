import { ENTITY_COLLECTIONS, Model } from './model.js';

const SORTED_STRING_ARRAYS = new Set([
  'tags', 'memberIds', 'evidenceIds', 'threatIds', 'assumptionIds', 'storedIn', 'assetIds', 'goals', 'stride',
  'proposalIds',
]);

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) out[k] = sortKeys((value as Record<string, unknown>)[k]);
    return out;
  }
  return value;
}

function canonItem(item: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(item)) {
    if (v === undefined) continue;
    if (SORTED_STRING_ARRAYS.has(k) && Array.isArray(v)) out[k] = [...v].sort();
    else if ((k === 'targets' || k === 'relatesTo') && Array.isArray(v))
      out[k] = [...v].sort((a, b) => `${a.type ?? ''}:${a.id ?? a.ref}`.localeCompare(`${b.type ?? ''}:${b.id ?? b.ref}`));
    else if (k === 'properties' || k === 'layout') out[k] = sortKeys(v);
    else if (v && typeof v === 'object' && !Array.isArray(v)) out[k] = canonItem(v as Record<string, unknown>);
    else if (Array.isArray(v)) out[k] = v.map((x) => (x && typeof x === 'object' ? canonItem(x as Record<string, unknown>) : x));
    else out[k] = v;
  }
  return out;
}

/**
 * Deterministic form of a model: schema key order, entity collections sorted by id,
 * order-insensitive lists sorted, free-form maps key-sorted. Routine saves of an
 * unchanged model produce byte-identical files.
 */
export function canonicalise(model: Model): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(model)) {
    if ((ENTITY_COLLECTIONS as readonly string[]).includes(k)) {
      out[k] = (v as Array<Record<string, unknown>>)
        .map(canonItem)
        .sort((a, b) => String(a.id).localeCompare(String(b.id)));
    } else if (k === 'view') {
      out[k] = canonItem(v as Record<string, unknown>);
    } else out[k] = v;
  }
  return out;
}

export function serialiseModel(model: Model): string {
  return JSON.stringify(canonicalise(model), null, 2) + '\n';
}
