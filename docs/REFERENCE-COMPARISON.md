# Comparison with AWS Threat Composer

Inspected: https://github.com/awslabs/threat-composer at commit `84f5628113ba8db6253e17c6b7afc86c6b4bc0eb` (cloned 2026-10-14): README, `docs/`, `schemas/threat-composer-v1.schema.json`, the example `.tc.json` files, `packages/threat-composer-ai` configuration, and a search of the app source. Nothing below was inferred from memory. "Not found" means a search of the repository at that commit found nothing, which is weaker than "does not exist".

## 1. Features verified in the reference

| Feature | Evidence |
|---|---|
| Threat statement composer based on a threat grammar | README, `threatFieldData.ts`, schema fields `threatSource`, `prerequisites`, `threatAction`, `threatImpact`, `impactedGoal`, `impactedAssets`, `statement` |
| Assumptions, mitigations, and links between threats, mitigations and assumptions | Schema: `assumptionLinks`, `mitigationLinks` |
| Mitigation status (4 values) and threat status (3 values) | Schema enums |
| STRIDE and Priority (High/Medium/Low) as threat metadata | Schema `metadata` variants |
| Threat packs and mitigation packs (self-hosted builds) | `docs/WEB-APP.md` |
| Workspaces, import and export of JSON, Markdown, DOCX, PDF | README, `docs/WEB-APP.md` |
| Insights dashboard | README |
| Data stored only in browser local storage; no backend | `docs/WEB-APP.md` |
| Extra delivery forms: VS Code extension, browser extension | README, `docs/` |
| Experimental AI CLI and MCP server that analyse source and write a starter `.tc.json` | `docs/AI-CLI-MCP.md` |
| AI path uses Amazon Bedrock via `boto3`; default model id `global.anthropic.claude-sonnet-5`; needs AWS credentials; Graphviz for diagrams; eight cooperating agents | `pyproject.toml`, `app_config.py`, `docs/AI-CLI-MCP.md` |
| Apache-2.0 licence, with a `NOTICE` and third-party licence file | `LICENSE`, `NOTICE`, `LICENSE-THIRD-PARTY` |

## 2. Limitations supported by evidence

| Limitation | Evidence |
|---|---|
| Architecture and data flow are free text plus one image each. There are no components, flows or trust boundaries as data, so a threat cannot reference a component or flow. | Schema: `architecture` and `dataflow` allow only `description` and `image`; `threats[].impactedAssets` is an array of strings |
| The same-model diagram and threat list requirement therefore cannot be met by the schema as published | Same |
| No evidence references (file, line, revision) and no staleness concept | Schema has no such fields; search for stale, revision, compare and drift in the app source found nothing |
| Likelihood and impact are not modelled; Priority is the only ordinal field | Schema |
| No record of who made which statement, or why a decision was made | Schema has `createdBy` only inside `brainstorm` items |
| The shipped AI path requires AWS Bedrock and AWS credentials | `app_config.py`, `pyproject.toml` |
| AI output is a complete starter model, not a set of proposals with accept, edit and reject | `docs/AI-CLI-MCP.md` describes generating a threat model for the user to edit afterwards |
| Browser-local storage means no durable file-per-project workflow outside export | `docs/WEB-APP.md` |
| Example data contains dangling references | `ThreatComposer.tc.json` has 4 `mitigationLinks` pointing at non-existent threats (checked by this project's tests) |

Not claimed: that Threat Composer cannot be used well with Git (its JSON export is stated to be Git friendly), that it is low quality, or that any listed limitation is accidental. It is a different product shape: a threat statement composer.

## 3. Proposed improvements in this project

These are design choices for a different product shape, not defects in the reference.

- A structured, validated model (components, actors, assets, flows, boundaries) shared by canvas, tables, threats and review.
- Explicit separation of observed, inferred, hypothesised, decided and verified.
- Evidence with source revision and location, flagged stale when the cited text changes.
- Change-aware review: compare revisions, trace explicit links, flag what needs a human look.
- AI output as validated proposals with accept, edit, reject and preserved decisions.
- Provider-neutral AI adapters and local-first storage as one JSON file per project.
- A CLI usable in CI (`compare --fail-on-review`) and a narrow MCP interface limited to read tools and proposal submission.

## 4. Recommendation: new implementation with a Threat Composer importer

| Option | Maintainability | Compatibility | Effort | Verdict |
|---|---|---|---|---|
| Fork | Inherit a Nx and pnpm monorepo, Cloudscape UI and a model whose core assumption (architecture is an image) must be replaced. Upstream merges would conflict with the replacement. | Best for `.tc.json` | Highest: replace the data model, canvas, AI path and storage | Rejected |
| Selective reuse of source | Mixed stacks (React and Python) and AWS-specific AI | Good | Medium, with licence bookkeeping for each file | Rejected: little that is reusable, since the parts we need differ |
| New implementation, reuse the schema for import | Small TypeScript codebase with one domain package | `.tc.json` schema 1 import and lossy export, tested against the published schema | Lowest for the target design | **Chosen** |

Reused: the published JSON Schema and example files, only for tests, with notices in `NOTICE`. No Threat Composer source code is included.
