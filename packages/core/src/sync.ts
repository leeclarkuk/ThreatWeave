import type { Evidence, Model, Source, Run } from './model.js';
import { derivedId, newEventId, nowIso, shortHash, slug } from './util.js';
import { redactSecrets, extractTopology, type DerivedEvidence, type SourceFileInput, type Extraction } from './extract.js';
import { removeEntity, clone } from './ops.js';
import { diffModels, type Change } from './diff.js';
import { deriveReviewItems, mergeReviewItems } from './review.js';
import { packProposals, mergeProposals } from './packs.js';
import type { Proposal, ReviewItem } from './model.js';

export interface SyncOptions {
  label: string;
  /** Digest of the captured files (and VCS revision when known). */
  revision: string;
  vcsRevision?: string;
  actor: string;
}
export interface SyncResult {
  model: Model;
  changes: Change[];
  reviewItems: ReviewItem[];
  proposals: Proposal[];
  notes: string[];
  stats: { elements: number; flows: number; boundaries: number; staleEvidence: number };
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim();

function evidenceFor(src: Source, d: DerivedEvidence, summary: string): Evidence {
  return {
    id: derivedId('evidence', `${d.path}:${d.lineStart}-${d.lineEnd}:${d.fileHash}`),
    kind: 'config', summary, sourceId: src.id, path: d.path, lineStart: d.lineStart, lineEnd: d.lineEnd, quote: d.quote,
    revision: src.revision, contentHash: d.fileHash, stale: false, provenance: { origin: 'source-scan', at: nowIso() },
  };
}

/** Mark evidence from earlier sources stale when the cited text is no longer present. */
export function markStaleEvidence(model: Model, files: SourceFileInput[], currentSourceId: string): { model: Model; count: number } {
  const next = clone(model);
  const byPath = new Map(files.map((f) => [f.path, f]));
  let count = 0;
  for (const ev of next.evidence) {
    if (!ev.path || !ev.sourceId || ev.sourceId === currentSourceId || ev.stale) continue;
    if (!['config', 'source-file', 'document'].includes(ev.kind)) continue;
    const f = byPath.get(ev.path);
    if (!f) { ev.stale = true; ev.staleReason = `${ev.path} is no longer present in the analysed source`; count++; continue; }
    if (f.hash === ev.contentHash) continue;
    const redacted = norm(redactSecrets(f.content).text);
    if (ev.quote && redacted.includes(norm(ev.quote))) continue; // file changed elsewhere; the cited text still exists
    ev.stale = true;
    ev.staleReason = ev.quote ? `the quoted text is no longer present in ${ev.path}` : `${ev.path} changed and no quote was captured to re-check`;
    count++;
  }
  return { model: next, count };
}

/** Merge a deterministic extraction into the model, keyed by stable source keys. Human edits and links survive. */
export function applyExtraction(model: Model, ex: Extraction, files: SourceFileInput[], opts: SyncOptions): { model: Model; stale: number } {
  const next = clone(model);
  const at = nowIso();
  const src: Source = {
    id: `src_${slug(opts.label, 20)}-${shortHash(opts.revision).slice(0, 6)}`, kind: 'directory-snapshot', label: opts.label,
    revision: opts.revision, ...(opts.vcsRevision ? { vcsRevision: opts.vcsRevision } : {}), capturedAt: at,
    files: files.map((f) => ({ path: f.path, hash: f.hash, bytes: Buffer_byteLength(f.content) })).sort((a, b) => a.path.localeCompare(b.path)),
  };
  if (!next.sources.some((s) => s.id === src.id)) next.sources.push(src);
  const idOfKey = (k: string) => derivedId('element', k);

  const evSet = new Map<string, Evidence>();
  const toEv = (list: DerivedEvidence[], what: string) =>
    list.map((d) => {
      const e = evidenceFor(src, d, `${what} (${d.path}:${d.lineStart})`);
      evSet.set(e.id, e);
      return e.id;
    });

  const seenElementKeys = new Set<string>();
  for (const d of ex.elements) {
    seenElementKeys.add(d.sourceKey);
    const id = idOfKey(d.sourceKey);
    const evIds = toEv(d.evidence, d.name);
    const idx = next.elements.findIndex((e) => e.sourceKey === d.sourceKey);
    if (idx < 0) {
      next.elements.push({
        id, kind: d.kind, name: d.name, description: d.description, technology: d.technology, exposure: d.exposure, tags: d.tags,
        properties: d.properties, basis: 'observed', provenance: { origin: 'source-scan', actor: opts.actor, at }, sourceKey: d.sourceKey, evidenceIds: evIds,
      });
      continue;
    }
    const cur = next.elements[idx]!;
    if (cur.properties['pin.exposure'] !== 'human') cur.exposure = d.exposure;
    cur.technology = d.technology || cur.technology;
    const humanProps = Object.fromEntries(Object.entries(cur.properties).filter(([k]) => k.startsWith('pin.')));
    const props = { ...cur.properties, ...d.properties, ...humanProps };
    delete props['source.missing'];
    if (cur.properties['pin.exposure'] === 'human') delete props['exposure.reason'];
    cur.properties = props;
    cur.tags = [...new Set([...cur.tags, ...d.tags])];
    const keepHuman = cur.evidenceIds.filter((eid) => next.evidence.find((e) => e.id === eid)?.provenance.origin === 'human');
    cur.evidenceIds = [...new Set([...keepHuman, ...evIds])];
  }
  for (const e of next.elements)
    if (e.sourceKey && !seenElementKeys.has(e.sourceKey) && e.provenance.origin === 'source-scan' && !e.properties['source.missing'])
      e.properties['source.missing'] = `not in revision ${opts.revision.slice(0, 8)}`;

  // Flows: replace derived flows wholesale; they carry no human reasoning of their own beyond links.
  const resolveKey = (k: string) => next.elements.find((e) => e.sourceKey === k)?.id;
  const seenFlowKeys = new Set<string>();
  for (const d of ex.flows) {
    const from = resolveKey(d.fromKey), to = resolveKey(d.toKey);
    if (!from || !to) continue;
    seenFlowKeys.add(d.sourceKey);
    const id = derivedId('flow', d.sourceKey);
    const evIds = toEv(d.evidence, `Flow ${d.label || 'link'}`);
    const cur = next.flows.find((f) => f.sourceKey === d.sourceKey);
    if (!cur)
      next.flows.push({
        id, from, to, label: d.label, protocol: d.protocol, description: '', authenticated: d.authenticated, encrypted: d.encrypted,
        assetIds: [], properties: {}, basis: d.basis, provenance: { origin: 'source-scan', actor: opts.actor, at }, sourceKey: d.sourceKey, evidenceIds: evIds,
      });
    else {
      cur.from = from; cur.to = to; cur.protocol = d.protocol; cur.label = d.label;
      if (cur.provenance.origin === 'source-scan') cur.encrypted = d.encrypted;
      cur.evidenceIds = evIds;
    }
  }
  let out = next;
  for (const f of [...next.flows]) if (f.sourceKey && !seenFlowKeys.has(f.sourceKey) && f.provenance.origin === 'source-scan') out = removeEntity(out, 'flow', f.id);

  const seenB = new Set<string>();
  for (const d of ex.boundaries) {
    seenB.add(d.sourceKey);
    const members = d.memberKeys.map(resolveKey).filter((x): x is string => !!x);
    const evIds = toEv(d.evidence, d.name);
    const cur = out.boundaries.find((b) => b.sourceKey === d.sourceKey);
    if (!cur)
      out.boundaries.push({
        id: derivedId('boundary', d.sourceKey), name: d.name, kind: 'network', trust: d.trust, description: d.description, memberIds: members, properties: {},
        basis: 'inferred', provenance: { origin: 'source-scan', actor: opts.actor, at }, sourceKey: d.sourceKey, evidenceIds: evIds,
      });
    else {
      const manual = cur.memberIds.filter((m) => !out.elements.find((e) => e.id === m)?.sourceKey);
      cur.memberIds = [...new Set([...members, ...manual])];
      cur.evidenceIds = evIds;
    }
  }
  for (const b of [...out.boundaries]) if (b.sourceKey && !seenB.has(b.sourceKey) && b.provenance.origin === 'source-scan') out = removeEntity(out, 'boundary', b.id);

  for (const e of evSet.values()) if (!out.evidence.some((x) => x.id === e.id)) out.evidence.push(e);
  const stale = markStaleEvidence(out, files, src.id);
  out = stale.model;
  // Drop scan evidence nothing references any more (never anything a person cited).
  const referenced = new Set<string>();
  for (const l of [out.elements, out.flows, out.boundaries, out.assets, out.assumptions, out.threats, out.mitigations] as Array<Array<{ evidenceIds: string[] }>>)
    for (const x of l) x.evidenceIds.forEach((i) => referenced.add(i));
  out.mitigations.forEach((m) => m.verification.evidenceIds.forEach((i) => referenced.add(i)));
  out.evidence = out.evidence.filter((e) => e.provenance.origin !== 'source-scan' || referenced.has(e.id));
  return { model: out, stale: stale.count };
}

function Buffer_byteLength(s: string) {
  return new TextEncoder().encode(s).length;
}

/**
 * One call for the "newer source revision" workflow: extract, merge, diff, derive review
 * items and rule-pack proposals. Existing decisions and closed review items are untouched.
 */
export function syncSource(model: Model, files: SourceFileInput[], opts: SyncOptions): SyncResult {
  const ex = extractTopology(files);
  const applied = applyExtraction(model, ex, files, opts);
  const changes = diffModels(model, applied.model);
  const items = deriveReviewItems(model, applied.model, changes);
  const mergedReview = mergeReviewItems(applied.model, items);
  const props = packProposals(mergedReview.model, changes);
  const mergedProps = mergeProposals(mergedReview.model, props);
  const run: Run = {
    id: newEventId('run'), kind: 'source-scan', status: 'completed', startedAt: nowIso(), finishedAt: nowIso(),
    sourceId: mergedProps.model.sources.at(-1)?.id,
    inputManifest: files.map((f) => ({ path: f.path, hash: f.hash, bytes: Buffer_byteLength(f.content) })),
    usage: { inputTokens: null, outputTokens: null, costUsd: null, note: 'Deterministic scan: no model provider used.' },
    proposalIds: mergedProps.added.map((p) => p.id),
    notes: [...ex.notes, `${changes.length} change(s), ${mergedReview.added.length} new review item(s), ${mergedProps.added.length} rule-pack proposal(s).`],
  };
  const final = mergedProps.model;
  final.runs.push(run);
  return {
    model: final, changes, reviewItems: mergedReview.added, proposals: mergedProps.added, notes: ex.notes,
    stats: { elements: ex.elements.length, flows: ex.flows.length, boundaries: ex.boundaries.length, staleEvidence: applied.stale },
  };
}
