import type { Model, Ref } from './model.js';
import { labelOf } from './ops.js';
import { shortHash } from './util.js';

export type ChangeKind =
  | 'element-added' | 'element-removed' | 'element-exposure-changed' | 'element-changed'
  | 'flow-added' | 'flow-removed' | 'flow-changed'
  | 'boundary-added' | 'boundary-removed' | 'boundary-membership-changed' | 'boundary-changed'
  | 'evidence-stale' | 'element-missing-from-source'
  | 'threat-added' | 'threat-removed' | 'threat-status-changed'
  | 'mitigation-added' | 'mitigation-removed' | 'mitigation-status-changed'
  | 'assumption-added' | 'assumption-removed' | 'assumption-status-changed';

export interface Change {
  id: string;
  kind: ChangeKind;
  entity: Ref;
  label: string;
  field?: string;
  before?: string;
  after?: string;
  summary: string;
  /** Deterministic: produced by comparing two models, no interpretation involved. */
  deterministic: true;
}

const mk = (kind: ChangeKind, entity: Ref, label: string, summary: string, field?: string, before?: string, after?: string): Change => ({
  id: `chg_${shortHash([kind, entity.id, field ?? '', before ?? '', after ?? ''].join('|'))}`,
  kind, entity, label, summary, deterministic: true,
  ...(field !== undefined ? { field } : {}), ...(before !== undefined ? { before } : {}), ...(after !== undefined ? { after } : {}),
});

const SKIP_PROPS = new Set(['source.file']);
const relevant = (p: Record<string, string>) =>
  JSON.stringify(Object.entries(p).filter(([k]) => !SKIP_PROPS.has(k)).sort(([a], [b]) => a.localeCompare(b)));

/**
 * Compare two model revisions. Pure and symmetric in data handling: only semantic
 * fields are compared; layout, timestamps and provenance are ignored.
 */
export function diffModels(before: Model, after: Model): Change[] {
  const out: Change[] = [];
  const idx = <T extends { id: string }>(xs: T[]) => new Map(xs.map((x) => [x.id, x]));

  const be = idx(before.elements), ae = idx(after.elements);
  for (const [id, e] of ae) {
    const old = be.get(id);
    const ref: Ref = { type: 'element', id };
    if (!old) {
      out.push(mk('element-added', ref, e.name, `Component "${e.name}" added (${e.kind}, exposure ${e.exposure}).`, undefined, undefined, e.exposure));
      continue;
    }
    if (old.exposure !== e.exposure)
      out.push(mk('element-exposure-changed', ref, e.name, `Exposure of "${e.name}" changed from ${old.exposure} to ${e.exposure}${e.properties['exposure.reason'] ? ` (${e.properties['exposure.reason']})` : ''}.`, 'exposure', old.exposure, e.exposure));
    const was = old.properties['source.missing'], now = e.properties['source.missing'];
    if (!was && now) out.push(mk('element-missing-from-source', ref, e.name, `"${e.name}" is no longer present in the analysed source (${now}).`, 'source.missing', '', now));
    for (const f of ['name', 'kind', 'technology'] as const)
      if (old[f] !== e[f]) out.push(mk('element-changed', ref, e.name, `${f} of "${e.name}" changed from "${old[f]}" to "${e[f]}".`, f, old[f], e[f]));
    if (relevant(old.properties) !== relevant(e.properties) && old.exposure === e.exposure && !(!was && now))
      out.push(mk('element-changed', ref, e.name, `Properties of "${e.name}" changed.`, 'properties', relevant(old.properties), relevant(e.properties)));
  }
  for (const [id, e] of be) if (!ae.has(id)) out.push(mk('element-removed', { type: 'element', id }, e.name, `Component "${e.name}" was removed.`));

  const bf = idx(before.flows), af = idx(after.flows);
  const flowName = (m: Model, id: string) => labelOf(m, { type: 'flow', id });
  for (const [id, f] of af) {
    const old = bf.get(id);
    const ref: Ref = { type: 'flow', id };
    if (!old) { out.push(mk('flow-added', ref, flowName(after, id), `Data flow ${flowName(after, id)} added.`)); continue; }
    for (const k of ['from', 'to', 'protocol', 'authenticated', 'encrypted', 'label'] as const)
      if (old[k] !== f[k]) out.push(mk('flow-changed', ref, flowName(after, id), `${k} of flow ${flowName(after, id)} changed from "${old[k]}" to "${f[k]}".`, k, old[k], f[k]));
  }
  for (const [id] of bf) if (!af.has(id)) out.push(mk('flow-removed', { type: 'flow', id }, flowName(before, id), `Data flow ${flowName(before, id)} was removed.`));

  const bb = idx(before.boundaries), ab = idx(after.boundaries);
  const nm = (m: Model, id: string) => m.elements.find((e) => e.id === id)?.name ?? id;
  for (const [id, b] of ab) {
    const old = bb.get(id);
    const ref: Ref = { type: 'boundary', id };
    if (!old) { out.push(mk('boundary-added', ref, b.name, `Trust boundary "${b.name}" added.`)); continue; }
    const added = b.memberIds.filter((m) => !old.memberIds.includes(m));
    const removed = old.memberIds.filter((m) => !b.memberIds.includes(m));
    if (added.length || removed.length)
      out.push(mk('boundary-membership-changed', ref, b.name,
        `Membership of "${b.name}" changed${added.length ? `; joined: ${added.map((m) => nm(after, m)).join(', ')}` : ''}${removed.length ? `; left: ${removed.map((m) => nm(before, m)).join(', ')}` : ''}.`,
        'memberIds', removed.map((m) => nm(before, m)).join(', '), added.map((m) => nm(after, m)).join(', ')));
    for (const k of ['name', 'trust', 'kind'] as const)
      if (old[k] !== b[k]) out.push(mk('boundary-changed', ref, b.name, `${k} of boundary "${b.name}" changed from "${old[k]}" to "${b[k]}".`, k, old[k], b[k]));
  }
  for (const [id, b] of bb) if (!ab.has(id)) out.push(mk('boundary-removed', { type: 'boundary', id }, b.name, `Trust boundary "${b.name}" was removed.`));

  const bev = idx(before.evidence);
  for (const e of after.evidence) {
    const old = bev.get(e.id);
    if (e.stale && (!old || !old.stale))
      out.push(mk('evidence-stale', { type: 'evidence', id: e.id }, e.summary.slice(0, 80), `Evidence "${e.summary.slice(0, 80)}" became stale: ${e.staleReason ?? 'source changed'}.`, 'stale', 'false', 'true'));
  }

  // Reasoning-layer changes are reported for completeness but do not raise review flags.
  const tracked = [
    ['threat', before.threats, after.threats, 'status', 'title'], ['mitigation', before.mitigations, after.mitigations, 'status', 'title'],
    ['assumption', before.assumptions, after.assumptions, 'status', 'text'],
  ] as const;
  for (const [type, b, a, f, lab] of tracked) {
    const bm = idx(b as Array<{ id: string }>), am = idx(a as Array<{ id: string }>);
    for (const [id, x] of am as Map<string, any>) {
      const old = (bm as Map<string, any>).get(id);
      if (!old) out.push(mk(`${type}-added` as ChangeKind, { type, id }, String(x[lab]).slice(0, 80), `${type} "${String(x[lab]).slice(0, 80)}" added.`));
      else if (old[f] !== x[f]) out.push(mk(`${type}-status-changed` as ChangeKind, { type, id }, String(x[lab]).slice(0, 80), `Status of ${type} "${String(x[lab]).slice(0, 80)}" changed from ${old[f]} to ${x[f]}.`, f, old[f], x[f]));
    }
    for (const [id, x] of bm as Map<string, any>) if (!am.has(id)) out.push(mk(`${type}-removed` as ChangeKind, { type, id }, String(x[lab]).slice(0, 80), `${type} "${String(x[lab]).slice(0, 80)}" was removed.`));
  }
  return out.sort((a, b) => a.kind.localeCompare(b.kind) || a.entity.id.localeCompare(b.entity.id) || (a.field ?? '').localeCompare(b.field ?? ''));
}

export const STRUCTURAL: ChangeKind[] = [
  'element-added', 'element-removed', 'element-exposure-changed', 'element-changed', 'flow-added', 'flow-removed', 'flow-changed',
  'boundary-added', 'boundary-removed', 'boundary-membership-changed', 'boundary-changed', 'evidence-stale', 'element-missing-from-source',
];
