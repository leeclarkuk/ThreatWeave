import { ID_PREFIXES, type EntityType } from './model.js';

/** Non-cryptographic 53-bit string hash (cyrb53), used for fingerprints and deterministic ids. */
export function shortHash(input: string, seed = 0): string {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, '0');
}

export function slug(input: string, max = 24): string {
  const s = input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, max)
    .replace(/-+$/g, '');
  return s || 'item';
}

/**
 * Determinism hooks for reproducible generated files (the bundled example) and tests. Production code never calls
 * these: by default time is the wall clock and ids use the platform's secure random source.
 */
let fixedNow: string | null = null;
let seeded: (() => number) | null = null;
export function useFixedClock(iso: string | null) { fixedNow = iso; }
export function useSeededRandom(seed: number | null) {
  if (seed === null) { seeded = null; return; }
  let a = seed >>> 0; // mulberry32
  seeded = () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const clock = () => (fixedNow ? new Date(fixedNow) : new Date());

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  if (seeded) for (let i = 0; i < bytes; i++) buf[i] = Math.floor(seeded() * 256);
  else globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function nowIso(): string {
  return clock().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Readable, stable id: prefix + slug of the initial name + random suffix. Never changes on rename. */
export function newId(type: EntityType, name = ''): string {
  return `${ID_PREFIXES[type]}_${slug(name || type)}-${randomHex(2)}`;
}

/** Time-ordered ids for events (runs, decisions, review items, proposals). */
export function newEventId(type: EntityType): string {
  const t = clock().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  return `${ID_PREFIXES[type]}_${t}-${randomHex(3)}`;
}

/** Deterministic id derived from a stable key, so re-scanning a source yields the same ids. */
export function derivedId(type: EntityType, key: string): string {
  return `${ID_PREFIXES[type]}_${slug(key.replace(/^[a-z]+:/, ''), 20)}-${shortHash(key).slice(0, 4)}`;
}

export function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}
