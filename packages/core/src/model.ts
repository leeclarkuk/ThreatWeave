import { z } from 'zod';

/** Product name is a single constant so it is trivial to change. */
export const PRODUCT_NAME = 'ThreatWeave';
export const MODEL_FORMAT = 'threatweave/model';
export const SCHEMA_VERSION = 1;

const idOf = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-z0-9][a-z0-9._-]{0,80}$`), `must look like ${prefix}_<slug>`);

export const ID_PREFIXES = {
  system: 'sys',
  element: 'el',
  flow: 'flow',
  boundary: 'tb',
  asset: 'ast',
  assumption: 'asm',
  threat: 'thr',
  mitigation: 'mit',
  evidence: 'ev',
  source: 'src',
  proposal: 'prp',
  review: 'rvw',
  decision: 'dec',
  run: 'run',
} as const;
export type EntityType = keyof typeof ID_PREFIXES;

export const SystemId = idOf('sys');
export const ElementId = idOf('el');
export const FlowId = idOf('flow');
export const BoundaryId = idOf('tb');
export const AssetId = idOf('ast');
export const AssumptionId = idOf('asm');
export const ThreatId = idOf('thr');
export const MitigationId = idOf('mit');
export const EvidenceId = idOf('ev');
export const SourceId = idOf('src');
export const ProposalId = idOf('prp');
export const ReviewId = idOf('rvw');
export const DecisionId = idOf('dec');
export const RunId = idOf('run');

const text = (max: number) => z.string().max(max);
const iso = z.string().max(40).regex(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/, 'ISO-8601 UTC timestamp');

/** A typed pointer to another entity. Integrity is checked by validateModel. */
export const RefType = z.enum([
  'system', 'element', 'flow', 'boundary', 'asset', 'assumption', 'threat', 'mitigation', 'evidence',
]);
export type RefType = z.infer<typeof RefType>;
export const Ref = z.strictObject({ type: RefType, id: z.string().max(100) });
export type Ref = z.infer<typeof Ref>;

/**
 * Where a statement came from. Distinct from `basis`, which says how well
 * grounded it is. Human provenance must name an actor.
 */
export const Provenance = z.strictObject({
  origin: z.enum(['human', 'ai', 'import', 'source-scan', 'pack-rule']),
  actor: text(100).optional(),
  runId: RunId.optional(),
  proposalId: ProposalId.optional(),
  at: iso.optional(),
});
export type Provenance = z.infer<typeof Provenance>;

/**
 * How well grounded a claim is.
 *  observed   - read directly from a source or stated by a person as fact
 *  inferred   - reasoned from observed facts
 *  hypothesis - plausible, awaiting validation
 * Human decisions and verified controls are separate entities, not bases.
 */
export const Basis = z.enum(['observed', 'inferred', 'hypothesis']);
export type Basis = z.infer<typeof Basis>;

export const Tri = z.enum(['unknown', 'yes', 'no']);
export type Tri = z.infer<typeof Tri>;
export const Level = z.enum(['unknown', 'low', 'medium', 'high']);
export type Level = z.infer<typeof Level>;

const Props = z.record(z.string().max(60), z.string().max(500)).default({});
const Tags = z.array(z.string().max(40)).default([]);

export const System = z.strictObject({
  id: SystemId,
  name: text(200).min(1),
  description: text(20000).default(''),
  notes: text(40000).default(''),
});
export type System = z.infer<typeof System>;

export const ElementKind = z.enum(['process', 'datastore', 'external-system', 'actor']);
export type ElementKind = z.infer<typeof ElementKind>;
/** Reachability from outside the trust perimeter the team cares about. */
export const Exposure = z.enum(['unknown', 'internal', 'external']);
export type Exposure = z.infer<typeof Exposure>;

export const Element = z.strictObject({
  id: ElementId,
  kind: ElementKind,
  name: text(200).min(1),
  description: text(5000).default(''),
  technology: text(200).default(''),
  systemId: SystemId.optional(),
  exposure: Exposure.default('unknown'),
  tags: Tags,
  properties: Props,
  basis: Basis.default('observed'),
  provenance: Provenance,
  /** Stable key for source-derived elements, e.g. "compose:api". */
  sourceKey: text(200).optional(),
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Element = z.infer<typeof Element>;

export const Flow = z.strictObject({
  id: FlowId,
  from: ElementId,
  to: ElementId,
  label: text(200).default(''),
  protocol: text(100).default(''),
  description: text(5000).default(''),
  authenticated: Tri.default('unknown'),
  encrypted: Tri.default('unknown'),
  assetIds: z.array(AssetId).default([]),
  properties: Props,
  basis: Basis.default('observed'),
  provenance: Provenance,
  sourceKey: text(200).optional(),
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Flow = z.infer<typeof Flow>;

export const Boundary = z.strictObject({
  id: BoundaryId,
  name: text(200).min(1),
  kind: z.enum(['network', 'process', 'account', 'organisation', 'physical', 'other']).default('network'),
  trust: z.enum(['unknown', 'untrusted', 'semi-trusted', 'trusted']).default('unknown'),
  description: text(5000).default(''),
  memberIds: z.array(ElementId).default([]),
  properties: Props,
  basis: Basis.default('observed'),
  provenance: Provenance,
  sourceKey: text(200).optional(),
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Boundary = z.infer<typeof Boundary>;

export const Asset = z.strictObject({
  id: AssetId,
  name: text(200).min(1),
  description: text(5000).default(''),
  classification: z.enum(['unknown', 'public', 'internal', 'confidential', 'restricted']).default('unknown'),
  storedIn: z.array(ElementId).default([]),
  basis: Basis.default('observed'),
  provenance: Provenance,
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Asset = z.infer<typeof Asset>;

export const Assumption = z.strictObject({
  id: AssumptionId,
  kind: z.enum(['assumption', 'question']).default('assumption'),
  text: text(2000).min(1),
  status: z.enum(['open', 'validated', 'invalidated', 'answered']).default('open'),
  answer: text(2000).default(''),
  relatesTo: z.array(Ref).default([]),
  rationale: text(2000).default(''),
  notes: text(5000).default(''),
  properties: Props,
  basis: Basis.default('hypothesis'),
  provenance: Provenance,
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Assumption = z.infer<typeof Assumption>;

/** Likelihood and impact are ordinal judgements with a stated reason, not scores. */
export const Judgement = z.strictObject({
  level: Level.default('unknown'),
  rationale: text(2000).default(''),
});
export type Judgement = z.infer<typeof Judgement>;

export const EvidenceStrength = z.enum(['none', 'weak', 'moderate', 'strong']);
export type EvidenceStrength = z.infer<typeof EvidenceStrength>;

export const Stride = z.enum(['S', 'T', 'R', 'I', 'D', 'E']);

export const Threat = z.strictObject({
  id: ThreatId,
  title: text(300).min(1),
  /** Actor or source of the threat. */
  source: text(300).default(''),
  preconditions: z.array(text(500)).default([]),
  action: text(1000).default(''),
  consequence: text(1000).default(''),
  goals: z.array(text(100)).default([]),
  stride: z.array(Stride).default([]),
  /** Affected elements, flows, boundaries or assets. */
  targets: z.array(Ref).default([]),
  likelihood: Judgement.default({ level: 'unknown', rationale: '' }),
  impact: Judgement.default({ level: 'unknown', rationale: '' }),
  /** How well supported the threat is. Deliberately separate from severity. */
  evidenceStrength: EvidenceStrength.default('none'),
  evidenceRationale: text(2000).default(''),
  status: z.enum(['open', 'mitigated', 'accepted-risk', 'not-applicable']).default('open'),
  basis: Basis.default('hypothesis'),
  notes: text(5000).default(''),
  tags: Tags,
  properties: Props,
  provenance: Provenance,
  evidenceIds: z.array(EvidenceId).default([]),
});
export type Threat = z.infer<typeof Threat>;

export const MitigationStatus = z.enum(['proposed', 'planned', 'in-progress', 'implemented', 'verified', 'wont-do']);
export type MitigationStatus = z.infer<typeof MitigationStatus>;

export const Mitigation = z.strictObject({
  id: MitigationId,
  title: text(300).min(1),
  description: text(5000).default(''),
  status: MitigationStatus.default('proposed'),
  /**
   * Who set an implemented/verified status. Required for those statuses, so a
   * generated mitigation cannot mark itself done.
   */
  statusSetBy: z
    .strictObject({ actorKind: z.enum(['human', 'import']), actor: text(100).min(1), at: iso })
    .optional(),
  threatIds: z.array(ThreatId).default([]),
  /** Assumptions this mitigation relies on. */
  assumptionIds: z.array(AssumptionId).default([]),
  /** Where the control is implemented (evidence of implementation). */
  evidenceIds: z.array(EvidenceId).default([]),
  verification: z
    .strictObject({
      plan: z.array(text(500)).default([]),
      evidenceIds: z.array(EvidenceId).default([]),
      note: text(2000).default(''),
    })
    .default({ plan: [], evidenceIds: [], note: '' }),
  notes: text(5000).default(''),
  properties: Props,
  provenance: Provenance,
});
export type Mitigation = z.infer<typeof Mitigation>;

export const EvidenceKind = z.enum(['source-file', 'document', 'human-note', 'test-result', 'config', 'import']);
export const Evidence = z.strictObject({
  id: EvidenceId,
  kind: EvidenceKind,
  summary: text(1000).min(1),
  sourceId: SourceId.optional(),
  path: text(500).optional(),
  lineStart: z.number().int().min(1).optional(),
  lineEnd: z.number().int().min(1).optional(),
  quote: text(600).optional(),
  /** Source revision at capture time (content digest or VCS revision). */
  revision: text(100).optional(),
  contentHash: text(100).optional(),
  /** Source key of the component, flow or boundary this was captured for. Lets a rescan check the same thing still says it. */
  anchor: text(200).optional(),
  stale: z.boolean().default(false),
  staleReason: text(500).optional(),
  provenance: Provenance,
});
export type Evidence = z.infer<typeof Evidence>;

export const SourceFile = z.strictObject({ path: text(500), hash: text(100), bytes: z.number().int().min(0) });
export const Source = z.strictObject({
  id: SourceId,
  kind: z.enum(['directory-snapshot', 'tc-import', 'document', 'manual']),
  label: text(300).min(1),
  revision: text(100).default(''),
  vcsRevision: text(100).optional(),
  capturedAt: iso,
  files: z.array(SourceFile).max(2000).default([]),
});
export type Source = z.infer<typeof Source>;

/** What a proposal would add. Strict so unexpected AI fields are rejected. */
const LevelJ = z.strictObject({ level: Level, rationale: text(2000) });
const TargetRef = z.strictObject({ type: RefType, ref: z.string().max(200) });
export const ProposalPayload = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('add-element'),
    name: text(200).min(1), elementKind: ElementKind, description: text(5000).default(''),
    technology: text(200).default(''), exposure: Exposure.default('unknown'),
  }),
  z.strictObject({
    kind: z.literal('add-flow'),
    from: z.string().max(200), to: z.string().max(200), label: text(200).default(''),
    protocol: text(100).default(''), authenticated: Tri.default('unknown'), encrypted: Tri.default('unknown'),
  }),
  z.strictObject({
    kind: z.literal('add-boundary'),
    name: text(200).min(1), boundaryKind: Boundary.shape.kind.default('network'),
    description: text(5000).default(''), members: z.array(z.string().max(200)).default([]),
  }),
  z.strictObject({
    kind: z.literal('add-asset'),
    name: text(200).min(1), description: text(5000).default(''),
    classification: Asset.shape.classification.default('unknown'), storedIn: z.array(z.string().max(200)).default([]),
  }),
  z.strictObject({
    kind: z.literal('add-threat'),
    title: text(300).min(1), source: text(300), preconditions: z.array(text(500)).default([]),
    action: text(1000), consequence: text(1000), goals: z.array(text(100)).default([]),
    stride: z.array(Stride).default([]), targets: z.array(TargetRef).default([]),
    likelihood: LevelJ, impact: LevelJ, evidenceStrength: EvidenceStrength,
  }),
  z.strictObject({
    kind: z.literal('add-mitigation'),
    title: text(300).min(1), description: text(5000).default(''),
    threats: z.array(z.string().max(200)).min(1), verificationSteps: z.array(text(500)).default([]),
  }),
  z.strictObject({
    kind: z.literal('add-assumption'),
    text: text(2000).min(1), relatesTo: z.array(TargetRef).default([]),
  }),
  z.strictObject({
    kind: z.literal('add-question'),
    text: text(2000).min(1), relatesTo: z.array(TargetRef).default([]),
  }),
]);
export type ProposalPayload = z.infer<typeof ProposalPayload>;
export type ProposalKind = ProposalPayload['kind'];

export const ProposalEvidence = z.strictObject({
  path: text(500),
  lineStart: z.number().int().min(1),
  lineEnd: z.number().int().min(1),
  quote: text(600),
  /** True only if the quote was found in the captured file at that location. */
  verified: z.boolean(),
});
export type ProposalEvidence = z.infer<typeof ProposalEvidence>;

export const Proposal = z.strictObject({
  id: ProposalId,
  /** Draft handle other proposals in the same batch can reference. */
  key: text(100).optional(),
  origin: z.enum(['ai', 'pack-rule', 'mcp']),
  runId: RunId.optional(),
  sourceId: SourceId.optional(),
  payload: ProposalPayload,
  reasoning: text(4000).min(1),
  basis: z.enum(['inferred', 'hypothesis']).default('hypothesis'),
  evidence: z.array(ProposalEvidence).default([]),
  missingInformation: z.array(text(500)).default([]),
  /** Why this was raised, for change-driven proposals. */
  trigger: text(1000).optional(),
  fingerprint: text(60),
  status: z.enum(['pending', 'accepted', 'rejected']).default('pending'),
  validationNotes: z.array(text(500)).default([]),
  createdEntity: z.strictObject({ type: RefType, id: z.string() }).optional(),
  decisionId: DecisionId.optional(),
  createdAt: iso,
});
export type Proposal = z.infer<typeof Proposal>;

export const ReviewItem = z.strictObject({
  id: ReviewId,
  target: Ref,
  /** Machine code for the rule that raised this. */
  code: text(60),
  reason: text(1500),
  /** Relationship path from the change to the target. */
  trace: z.array(text(500)).default([]),
  change: text(500),
  deterministic: z.boolean().default(true),
  status: z.enum(['open', 'resolved', 'dismissed']).default('open'),
  decisionId: DecisionId.optional(),
  raisedAt: iso,
});
export type ReviewItem = z.infer<typeof ReviewItem>;

export const Decision = z.strictObject({
  id: DecisionId,
  subject: z.strictObject({ type: z.enum(['proposal', 'review', ...RefType.options]), id: z.string().max(100) }),
  action: z.enum(['accept', 'edit-accept', 'reject', 'accept-risk', 'dismiss', 'resolve', 'set-status', 'verify']),
  rationale: text(3000).default(''),
  actor: text(100).min(1),
  at: iso,
  detail: text(1000).default(''),
});
export type Decision = z.infer<typeof Decision>;

export const Usage = z.strictObject({
  inputTokens: z.number().int().min(0).nullable().default(null),
  outputTokens: z.number().int().min(0).nullable().default(null),
  /** Null unless the user configured prices. Never guessed. */
  costUsd: z.number().min(0).nullable().default(null),
  note: text(300).default(''),
});
export type Usage = z.infer<typeof Usage>;

export const Run = z.strictObject({
  id: RunId,
  kind: z.enum(['ai-analysis', 'source-scan', 'pack-rules', 'comparison']),
  status: z.enum(['running', 'completed', 'failed', 'cancelled']),
  startedAt: iso,
  finishedAt: iso.optional(),
  adapter: text(100).optional(),
  modelId: text(200).optional(),
  promptVersion: text(40).optional(),
  sourceId: SourceId.optional(),
  /** Exactly what was sent to the provider (paths + hashes, not content). */
  inputManifest: z.array(SourceFile).default([]),
  usage: Usage.default({ inputTokens: null, outputTokens: null, costUsd: null, note: '' }),
  proposalIds: z.array(ProposalId).default([]),
  error: text(1000).optional(),
  notes: z.array(text(500)).default([]),
});
export type Run = z.infer<typeof Run>;

export const Model = z.strictObject({
  format: z.literal(MODEL_FORMAT),
  schemaVersion: z.literal(SCHEMA_VERSION),
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,60}$/),
  name: text(200).min(1),
  description: text(20000).default(''),
  /** Set for models that ship as demonstrations. */
  example: z.boolean().default(false),
  systems: z.array(System).default([]),
  elements: z.array(Element).default([]),
  flows: z.array(Flow).default([]),
  boundaries: z.array(Boundary).default([]),
  assets: z.array(Asset).default([]),
  assumptions: z.array(Assumption).default([]),
  threats: z.array(Threat).default([]),
  mitigations: z.array(Mitigation).default([]),
  evidence: z.array(Evidence).default([]),
  sources: z.array(Source).default([]),
  proposals: z.array(Proposal).default([]),
  reviewItems: z.array(ReviewItem).default([]),
  decisions: z.array(Decision).default([]),
  runs: z.array(Run).default([]),
  /** Presentation only. Ignored by comparison. */
  view: z
    .strictObject({ layout: z.record(z.string(), z.strictObject({ x: z.number(), y: z.number() })).default({}) })
    .default({ layout: {} }),
});
export type Model = z.infer<typeof Model>;

/** Collections whose items have an `id` and are serialised sorted by it. */
export const ENTITY_COLLECTIONS = [
  'systems', 'elements', 'flows', 'boundaries', 'assets', 'assumptions', 'threats', 'mitigations',
  'evidence', 'sources', 'proposals', 'reviewItems', 'decisions', 'runs',
] as const;
export type EntityCollection = (typeof ENTITY_COLLECTIONS)[number];
