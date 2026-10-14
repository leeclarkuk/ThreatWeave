# Model schema and compatibility

Source of truth: `packages/core/src/model.ts` (zod 4). A model file is JSON with `"format": "threatweave/model"` and `"schemaVersion": 1`.

## Collections
All carry stable ids with a type prefix and are serialised sorted by id.

| Collection | Id prefix | Purpose |
|---|---|---|
| `systems` | `sys_` | Name, description, notes |
| `elements` | `el_` | Components: `process`, `datastore`, `external-system`, `actor`; `exposure` (unknown, internal, external); `sourceKey` for derived items |
| `flows` | `flow_` | Directed, `from`, `to`, protocol, `authenticated` and `encrypted` (unknown, yes, no), `assetIds` |
| `boundaries` | `tb_` | Trust boundaries with `memberIds` and `trust` |
| `assets` | `ast_` | Classification, where stored |
| `assumptions` | `asm_` | Assumptions and open questions, with `relatesTo` references |
| `threats` | `thr_` | Source, preconditions, action, consequence, STRIDE, `targets`, likelihood and impact with rationale, `evidenceStrength`, `basis`, `status` |
| `mitigations` | `mit_` | `status`, `statusSetBy`, `threatIds`, `assumptionIds`, verification plan and evidence |
| `evidence` | `ev_` | Kind, summary, path, line range, quote, revision, content hash, `stale` |
| `sources` | `src_` | Captured directory snapshots: revision digest, VCS revision, file hashes |
| `proposals` | `prp_` | Pending, accepted, rejected suggestions with reasoning and verified evidence |
| `reviewItems` | `rvw_` | What needs review, why, and the relationship trace |
| `decisions` | `dec_` | Who decided what, when, and why |
| `runs` | `run_` | Analysis and scan runs: provider, model id, exactly which files (path and hash) were sent, usage, errors |

`provenance` on content entities records `origin` (`human`, `ai`, `import`, `source-scan`, `pack-rule`), `actor`, run and proposal ids. Human provenance requires an actor.

Integrity rules beyond the schema are in `validate.ts`: no dangling references, `implemented` and `verified` need `statusSetBy`, `verified` needs verification evidence, human input must be attributed. Warnings (not errors) cover threats with no target, threats marked mitigated without an implemented control, and verification resting on stale evidence.

## JSON Schema
`threatweave schema` prints a JSON Schema generated from the same zod definition the validator uses (`z.toJSONSchema`, input shape, so defaults are optional). It is generated rather than committed so there is one source of truth. It describes structure only; the integrity and invariant rules in `validate.ts` cannot be expressed in JSON Schema, so use `threatweave validate` for the full check.

## Versioning
`schemaVersion` is 1. A future incompatible change will bump it and ship a migration that `validateModel` reports clearly. Files with a different `schemaVersion` fail validation with a version error today; there is no automatic migration yet because there is only one version.

## Threat Composer (`.tc.json`, schema 1)
Mapping, derived from the published schema:

| Threat Composer | ThreatWeave |
|---|---|
| `applicationInfo` | system name and description; the model name |
| `architecture.description`, `dataflow.description` | system notes (not converted to components or flows) |
| `architecture.image`, `dataflow.image` | **dropped, reported** (cannot become canvas data) |
| `assumptions[]` | `assumptions` (kind assumption, status open, basis hypothesis); `Comments` metadata to `notes`; `custom:*` to `properties` |
| `mitigations[]` and `status` | `mitigations`; identified becomes planned, in progress stays, resolved becomes **implemented (not verified)** attested to the import, resolved-will-not-action becomes wont-do |
| `threats[]` | `threats`; the grammar fields map one-to-one; `impactedAssets` become `assets` and targets; `STRIDE` kept; `Priority` kept as a property (no likelihood or impact is invented) |
| `threats[].status` | identified is open, resolved is mitigated, resolved-not-useful is not-applicable |
| `mitigationLinks`, `assumptionLinks` | `mitigations[].threatIds`, `assumptions[].relatesTo`; links to missing items are skipped and counted |
| `brainstorm` | dropped, reported |
| ids | kept: `thr_<lowercased tc id>`, so repeated imports and exports line up |
| unknown top-level fields | dropped, reported |

Export is lossy and says so: components, flows and boundaries become description text; likelihood, impact, evidence strength, basis, provenance, evidence, decisions and runs are dropped; verified and proposed mitigations export as resolved and identified; over-long text is truncated with a warning. Supported fields (threat statement fields, status, STRIDE, links, ids) round-trip; a test imports a real file, exports it, and compares them. Whole-file round trips are **not** claimed to be lossless.
