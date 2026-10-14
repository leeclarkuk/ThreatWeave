/**
 * Threat Composer (.tc.json, schema v1) import and export.
 * Mapping is derived from the inspected schema at
 * https://github.com/awslabs/threat-composer (schemas/threat-composer-v1.schema.json).
 * Everything that cannot be represented is reported, never silently dropped.
 */
import { MODEL_FORMAT, SCHEMA_VERSION, type Model, type Mitigation, type Threat, type Ref } from './model.js';
import { nowIso, slug, uniq } from './util.js';

export interface ConversionWarning {
  level: 'info' | 'warning';
  code: string;
  message: string;
  count: number;
}

class Warnings {
  private m = new Map<string, ConversionWarning>();
  add(level: ConversionWarning['level'], code: string, message: string) {
    const hit = this.m.get(code);
    if (hit) hit.count++;
    else this.m.set(code, { level, code, message, count: 1 });
  }
  list() {
    return [...this.m.values()];
  }
}

type Json = Record<string, any>;
const IMPORT_ACTOR = 'threat-composer-import';
const KNOWN_TOP = new Set(['schema', 'applicationInfo', 'architecture', 'dataflow', 'assumptions', 'mitigations', 'assumptionLinks', 'mitigationLinks', 'threats', 'brainstorm', '$schema']);

const idFor = (prefix: string, raw: unknown, fallback: string) => {
  const s = typeof raw === 'string' ? raw.toLowerCase() : '';
  return /^[a-z0-9][a-z0-9._-]{0,80}$/.test(s) ? `${prefix}_${s}` : `${prefix}_${slug(fallback, 30)}`;
};

function readMetadata(meta: unknown, w: Warnings) {
  const out = { comments: '', stride: [] as string[], priority: '', props: {} as Record<string, string> };
  if (!Array.isArray(meta)) return out;
  for (const m of meta as Json[]) {
    const k = String(m?.key ?? '');
    const v = m?.value;
    if (k === 'Comments') out.comments = String(v ?? '');
    else if (k === 'STRIDE' && Array.isArray(v)) out.stride = v.map(String);
    else if (k === 'Priority') out.priority = String(v ?? '');
    else if (k.startsWith('custom:')) {
      if (Array.isArray(v)) w.add('warning', 'custom-array-flattened', 'Custom metadata with list values was flattened to a comma-separated string.');
      out.props[k.slice(0, 60)] = (Array.isArray(v) ? v.join(', ') : String(v ?? '')).slice(0, 500);
    } else if (k) out.props[`tc.${k}`.slice(0, 60)] = (Array.isArray(v) ? v.join(', ') : String(v ?? '')).slice(0, 500);
  }
  return out;
}

export interface ImportResult {
  model: Model;
  warnings: ConversionWarning[];
  stats: Record<string, number>;
}

export function importThreatComposer(input: unknown, opts: { modelId?: string; importedBy?: string } = {}): ImportResult {
  const w = new Warnings();
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Not a Threat Composer workspace: expected a JSON object');
  const tc = input as Json;
  if (tc.schema !== 1) throw new Error(`Unsupported Threat Composer schema version ${JSON.stringify(tc.schema)}; only schema 1 was inspected`);
  for (const k of Object.keys(tc)) if (!KNOWN_TOP.has(k)) w.add('warning', 'unknown-top-level', `Unknown top-level field "${k}" was not imported.`);

  const at = nowIso();
  const prov = { origin: 'import' as const, actor: opts.importedBy ?? IMPORT_ACTOR, at };
  const name = String(tc.applicationInfo?.name || 'Imported threat model').slice(0, 200);
  const sysId = `sys_${slug(name, 24)}`;
  const model: Model = {
    format: MODEL_FORMAT, schemaVersion: SCHEMA_VERSION,
    id: opts.modelId ?? `${slug(name, 40)}-imported`.replace(/^-+/, 'model'),
    name, description: '', example: false, systems: [], elements: [], flows: [], boundaries: [], assets: [],
    assumptions: [], threats: [], mitigations: [], evidence: [], sources: [], proposals: [], reviewItems: [],
    decisions: [], runs: [], view: { layout: {} },
  };
  if (model.id.length < 3) model.id = `model-${model.id}`;

  const arch = String(tc.architecture?.description ?? '');
  const flow = String(tc.dataflow?.description ?? '');
  const notes = [arch && `## Architecture (from Threat Composer)\n\n${arch}`, flow && `## Data flow (from Threat Composer)\n\n${flow}`].filter(Boolean).join('\n\n');
  model.systems.push({ id: sysId, name, description: String(tc.applicationInfo?.description ?? '').slice(0, 20000), notes: notes.slice(0, 40000) });
  if (notes) w.add('info', 'architecture-as-text', 'Architecture and data flow descriptions were kept as system notes. They were not converted into canvas components, flows or boundaries.');
  for (const key of ['architecture', 'dataflow'] as const) {
    const img = tc[key]?.image;
    if (typeof img === 'string' && img.length > 0)
      w.add('warning', 'diagram-image-dropped', `Embedded ${key} diagram image (${Math.round(img.length / 1024)} KB as a data URL) cannot be represented and was dropped. Re-draw it on the canvas.`);
  }

  // Assets are free-text names in TC. Create one asset per distinct name.
  const assetByName = new Map<string, string>();
  const assetFor = (n: string) => {
    const key = n.trim().toLowerCase();
    if (!key) return undefined;
    let id = assetByName.get(key);
    if (!id) {
      id = `ast_${slug(n, 24)}`;
      let k = 2;
      while (model.assets.some((a) => a.id === id)) id = `ast_${slug(n, 24)}-${k++}`;
      assetByName.set(key, id);
      model.assets.push({ id, name: n.trim().slice(0, 200), description: '', classification: 'unknown', storedIn: [], basis: 'observed', provenance: prov, evidenceIds: [] });
    }
    return id;
  };

  const tagsOf = (t: unknown) => (Array.isArray(t) ? t.map(String).map((x) => x.slice(0, 40)) : []);

  for (const a of (tc.assumptions ?? []) as Json[]) {
    const md = readMetadata(a.metadata, w);
    model.assumptions.push({
      id: idFor('asm', a.id, `assumption-${a.numericId}`), kind: 'assumption',
      text: String(a.content ?? '').slice(0, 2000) || '(empty assumption)', status: 'open', answer: '', relatesTo: [], rationale: '',
      notes: md.comments.slice(0, 5000), properties: { ...md.props, 'tc.numericId': String(a.numericId ?? ''), ...(a.displayOrder != null ? { 'tc.displayOrder': String(a.displayOrder) } : {}) },
      basis: 'hypothesis', provenance: prov, evidenceIds: [],
    });
  }

  let resolvedCount = 0;
  const statusMap: Record<string, Mitigation['status']> = {
    mitigationIdentified: 'planned', mitigationInProgress: 'in-progress', mitigationResolved: 'implemented', mitigationResolvedWillNotAction: 'wont-do',
  };
  for (const m of (tc.mitigations ?? []) as Json[]) {
    const md = readMetadata(m.metadata, w);
    const status = statusMap[String(m.status ?? 'mitigationIdentified')] ?? 'planned';
    if (status === 'implemented') resolvedCount++;
    model.mitigations.push({
      id: idFor('mit', m.id, `mitigation-${m.numericId}`), title: String(m.content ?? '').slice(0, 300) || '(empty mitigation)',
      description: String(m.content ?? '').length > 300 ? String(m.content).slice(0, 5000) : '', status,
      ...(status === 'implemented' ? { statusSetBy: { actorKind: 'import' as const, actor: IMPORT_ACTOR, at } } : {}),
      threatIds: [], assumptionIds: [], evidenceIds: [], verification: { plan: [], evidenceIds: [], note: '' },
      notes: md.comments.slice(0, 5000), properties: { ...md.props, 'tc.numericId': String(m.numericId ?? '') }, provenance: prov,
    });
    if (status === 'planned' && !m.status) w.add('info', 'mitigation-status-defaulted', 'Mitigations without a status were imported as "planned".');
  }
  if (resolvedCount)
    w.add('info', 'resolved-not-verified', `${resolvedCount} mitigation(s) marked resolved were imported as "implemented", not "verified". Threat Composer carries no verification evidence.`);

  const threatStatus: Record<string, Threat['status']> = { threatIdentified: 'open', threatResolved: 'mitigated', threatResolvedNotUseful: 'not-applicable' };
  let sawPriority = false;
  for (const t of (tc.threats ?? []) as Json[]) {
    const md = readMetadata(t.metadata, w);
    const source = String(t.threatSource ?? ''), action = String(t.threatAction ?? ''), consequence = String(t.threatImpact ?? '');
    const title = (t.statement ? String(t.statement) : [source, action].filter(Boolean).join(' → ') || 'Untitled threat').slice(0, 300);
    const targets: Ref[] = [];
    for (const an of (t.impactedAssets ?? []) as string[]) {
      const id = assetFor(String(an));
      if (id) targets.push({ type: 'asset', id });
    }
    if (md.priority) sawPriority = true;
    const props: Record<string, string> = { ...md.props, 'tc.numericId': String(t.numericId ?? '') };
    if (md.priority) props['tc.priority'] = md.priority;
    if (t.customTemplate) props['tc.customTemplate'] = String(t.customTemplate).slice(0, 500);
    const stride = md.stride.filter((s) => 'STRIDE'.includes(s) && s.length === 1);
    model.threats.push({
      id: idFor('thr', t.id, `threat-${t.numericId}`), title, source,
      preconditions: t.prerequisites ? [String(t.prerequisites).slice(0, 500)] : [], action, consequence,
      goals: ((t.impactedGoal ?? []) as string[]).map(String).map((g) => g.slice(0, 100)),
      stride: stride as Threat['stride'], targets,
      likelihood: { level: 'unknown', rationale: '' }, impact: { level: 'unknown', rationale: '' },
      evidenceStrength: 'none', evidenceRationale: '', status: threatStatus[String(t.status ?? 'threatIdentified')] ?? 'open',
      basis: 'hypothesis',
      notes: [md.comments, !source && !action && t.statement ? `Imported statement: ${t.statement}` : ''].filter(Boolean).join('\n\n').slice(0, 5000),
      tags: tagsOf(t.tags), properties: props, provenance: prov, evidenceIds: [],
    });
  }
  if (sawPriority)
    w.add('info', 'priority-not-mapped', 'Threat Composer "Priority" has no direct equivalent. It is kept as a property; likelihood and impact were left "unknown" for you to judge.');
  if (model.threats.length) w.add('info', 'no-target-elements', 'Imported threats target assets only. Link them to components or flows once the architecture is drawn.');

  const has = (list: Array<{ id: string }>, id: string) => list.some((x) => x.id === id);
  for (const l of (tc.mitigationLinks ?? []) as Json[]) {
    const mid = idFor('mit', l.mitigationId, ''), tid = idFor('thr', l.linkedId, '');
    const mit = model.mitigations.find((x) => x.id === mid);
    if (!mit || !has(model.threats, tid)) { w.add('warning', 'dangling-link', 'A mitigation link referred to a missing mitigation or threat and was skipped.'); continue; }
    mit.threatIds = uniq([...mit.threatIds, tid]);
  }
  for (const l of (tc.assumptionLinks ?? []) as Json[]) {
    const a = model.assumptions.find((x) => x.id === idFor('asm', l.assumptionId, ''));
    const type = l.type === 'Mitigation' ? 'mitigation' : 'threat';
    const target = idFor(type === 'mitigation' ? 'mit' : 'thr', l.linkedId, '');
    if (!a || !has(type === 'mitigation' ? model.mitigations : model.threats, target)) { w.add('warning', 'dangling-link', 'An assumption link referred to a missing item and was skipped.'); continue; }
    if (!a.relatesTo.some((r) => r.type === type && r.id === target)) a.relatesTo.push({ type, id: target });
  }

  const bs = tc.brainstorm as Json | undefined;
  if (bs && typeof bs === 'object') {
    const n = Object.values(bs).reduce((s: number, v) => s + (Array.isArray(v) ? v.length : 0), 0);
    if (n) w.add('warning', 'brainstorm-dropped', `${n} brainstorm note(s) were not imported. They are working notes, not part of the threat model.`);
  }
  w.add('info', 'no-authors', 'Threat Composer files carry no author for statements. Imported items are attributed to the import, not to a person.');

  model.sources.push({ id: 'src_threat-composer-import', kind: 'tc-import', label: 'Threat Composer import', revision: '', capturedAt: at, files: [] });
  model.sources[0]!.label = `Threat Composer schema 1 import (${model.threats.length} threats, ${model.mitigations.length} mitigations)`;
  return {
    model, warnings: w.list(),
    stats: { threats: model.threats.length, mitigations: model.mitigations.length, assumptions: model.assumptions.length, assets: model.assets.length },
  };
}

const trunc = (w: Warnings, s: string, max: number, what: string) => {
  if (s.length <= max) return s;
  w.add('warning', 'truncated', `${what} exceeded Threat Composer's length limit and was truncated.`);
  return s.slice(0, max);
};

/** Lossy export to Threat Composer schema 1. Round trips are NOT lossless; see warnings. */
export function exportThreatComposer(model: Model): { json: Json; warnings: ConversionWarning[] } {
  const w = new Warnings();
  const sys = model.systems[0];
  const nameOf = (id: string) => model.elements.find((e) => e.id === id)?.name ?? id;
  const archText = [
    sys?.notes,
    model.elements.length && `### Components\n${model.elements.map((e) => `- ${e.name} (${e.kind}${e.exposure !== 'unknown' ? `, ${e.exposure}` : ''})${e.technology ? ` - ${e.technology}` : ''}`).join('\n')}`,
    model.boundaries.length && `### Trust boundaries\n${model.boundaries.map((b) => `- ${b.name}: ${b.memberIds.map(nameOf).join(', ')}`).join('\n')}`,
  ].filter(Boolean).join('\n\n');
  const flowText = model.flows.map((f) => `- ${nameOf(f.from)} → ${nameOf(f.to)}${f.label ? `: ${f.label}` : ''}${f.protocol ? ` [${f.protocol}]` : ''}`).join('\n');
  if (model.elements.length || model.flows.length || model.boundaries.length)
    w.add('warning', 'graph-flattened', 'Components, flows and trust boundaries were exported as description text only. Threat Composer has no structured architecture.');

  const customMeta = (props: Record<string, string>) =>
    Object.entries(props).filter(([k]) => k.startsWith('custom:')).map(([key, value]) => ({ key: key.slice(0, 50), value }));
  const num = (p: Record<string, string>, i: number) => {
    const n = Number(p['tc.numericId']);
    return Number.isFinite(n) && n > 0 ? n : i + 1;
  };
  const strip = (id: string) => id.replace(/^[a-z]+_/, '').slice(0, 36);

  const out: Json = {
    schema: 1,
    applicationInfo: { name: model.name.slice(0, 200), description: trunc(w, model.description || sys?.description || '', 100000, 'Description') },
    architecture: { description: trunc(w, archText, 100000, 'Architecture text') },
    dataflow: { description: trunc(w, flowText, 100000, 'Data flow text') },
    assumptions: [], mitigations: [], assumptionLinks: [], mitigationLinks: [], threats: [],
  };
  model.assumptions.forEach((a, i) => {
    const n = num(a.properties, i);
    out.assumptions.push({
      id: strip(a.id), numericId: n, displayOrder: n,
      metadata: [...(a.notes ? [{ key: 'Comments', value: trunc(w, a.notes, 1000, 'Comment') }] : []), ...customMeta(a.properties)],
      tags: [], content: trunc(w, a.text, 1000, 'Assumption text'),
    });
    if (a.kind === 'question' || a.status !== 'open') w.add('warning', 'assumption-state-lost', 'Question/validation state of assumptions is not representable and was dropped.');
    a.relatesTo.forEach((r) => {
      if (r.type === 'threat' || r.type === 'mitigation')
        out.assumptionLinks.push({ type: r.type === 'threat' ? 'Threat' : 'Mitigation', assumptionId: strip(a.id), linkedId: strip(r.id) });
      else w.add('warning', 'link-dropped', 'Assumption links to components, flows, boundaries or assets are not representable and were dropped.');
    });
  });
  const mstat: Record<string, string> = { proposed: 'mitigationIdentified', planned: 'mitigationIdentified', 'in-progress': 'mitigationInProgress', implemented: 'mitigationResolved', verified: 'mitigationResolved', 'wont-do': 'mitigationResolvedWillNotAction' };
  model.mitigations.forEach((m, i) => {
    const n = num(m.properties, i);
    out.mitigations.push({
      id: strip(m.id), numericId: n, displayOrder: n,
      metadata: [...(m.notes ? [{ key: 'Comments', value: trunc(w, m.notes, 1000, 'Comment') }] : []), ...customMeta(m.properties)],
      tags: [], content: trunc(w, m.title, 1000, 'Mitigation text'), status: mstat[m.status],
    });
    if (m.status === 'verified') w.add('warning', 'verification-lost', 'Verified status and verification evidence are not representable. Verified mitigations export as "resolved".');
    if (m.status === 'proposed') w.add('warning', 'proposed-as-identified', 'Mitigations still "proposed" export as "identified".');
    m.threatIds.forEach((t) => out.mitigationLinks.push({ mitigationId: strip(m.id), linkedId: strip(t) }));
    if (m.evidenceIds.length) w.add('warning', 'evidence-dropped', 'Evidence references are not representable and were dropped.');
  });
  const tstat: Record<string, string> = { open: 'threatIdentified', mitigated: 'threatResolved', 'accepted-risk': 'threatResolved', 'not-applicable': 'threatResolvedNotUseful' };
  model.threats.forEach((t, i) => {
    const n = num(t.properties, i);
    const assets = t.targets.filter((r) => r.type === 'asset').map((r) => model.assets.find((a) => a.id === r.id)?.name ?? r.id);
    const pre = t.preconditions.join('; ');
    const metadata: Json[] = [];
    if (t.stride.length) metadata.push({ key: 'STRIDE', value: t.stride });
    const pr = t.properties['tc.priority'];
    if (pr === 'High' || pr === 'Medium' || pr === 'Low') metadata.push({ key: 'Priority', value: pr });
    if (t.notes) metadata.push({ key: 'Comments', value: trunc(w, t.notes, 1000, 'Comment') });
    metadata.push(...customMeta(t.properties));
    const src = trunc(w, t.source, 200, 'Threat source'), act = trunc(w, t.action, 200, 'Threat action'), imp = trunc(w, t.consequence, 200, 'Threat impact'), pq = trunc(w, pre, 200, 'Prerequisites');
    out.threats.push({
      id: strip(t.id), numericId: n, displayOrder: n, metadata, tags: t.tags.map((x) => x.slice(0, 30)),
      threatSource: src, prerequisites: pq, threatAction: act, threatImpact: imp,
      impactedGoal: t.goals.map((g) => g.slice(0, 200)), impactedAssets: assets.map((a) => a.slice(0, 200)),
      statement: trunc(w, `A ${src}${pq ? ` ${pq}` : ''} can ${act}, which leads to ${imp}`.slice(0, 1400), 1400, 'Statement'), status: tstat[t.status],
    });
    if (t.status === 'accepted-risk') w.add('warning', 'risk-accepted-lost', '"Accepted risk" threats export as "resolved"; the acceptance and rationale are not representable.');
    if (t.targets.some((r) => r.type !== 'asset')) w.add('warning', 'targets-dropped', 'Threat links to components, flows and boundaries are not representable and were dropped.');
  });
  if (model.threats.length) w.add('warning', 'judgements-dropped', 'Likelihood, impact, evidence strength, basis and provenance are not representable and were dropped.');
  if (model.evidence.length || model.decisions.length || model.runs.length)
    w.add('warning', 'history-dropped', 'Evidence, decisions, analysis runs and review items are not representable and were dropped.');
  // Normalise ids that could clash after stripping prefixes.
  for (const key of ['assumptions', 'mitigations', 'threats'] as const) {
    const ids = new Set<string>();
    for (const it of out[key]) { while (ids.has(it.id)) it.id = (it.id + 'x').slice(0, 36); ids.add(it.id); }
  }
  return { json: out, warnings: w.list() };
}
