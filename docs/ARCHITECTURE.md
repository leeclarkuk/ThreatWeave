# Architecture

A modular monolith in one npm workspace. No database, no queue, no cloud service.

```
packages/
  core     domain model, validation, serialisation, edits, import/export, extraction, diff, review, proposals, report
           (pure TypeScript, browser-safe, no node: imports)
  ai       provider adapters (Anthropic, OpenAI-compatible), prompt, bounded orchestrator
  server   file store, safe directory ingestion, settings and credentials, run lifecycle, HTTP API (Hono)
  cli      `threatweave` command and the MCP server
  web      React app (Vite). Bundles core and calls the HTTP API
```

Dependency direction: `web, cli, server -> ai -> core`. `core` imports nothing from the others. The rule that matters: **the web app, the CLI, the MCP server and the HTTP server all call the same `core` functions.** There is one validator (`validateModel`), one set of edit functions, one comparison.

## Decisions

### Storage: one deterministic JSON file per project
`<data>/projects/<id>/model.json`, plus immutable snapshots in `revisions/`. Chosen over SQLite because the product's value depends on Git-reviewable models and portability: the file is the model. Cost: no queries across projects and no cross-process locking. Writes are atomic (temp file and rename) and serialised per project inside the server. The save endpoint requires `If-Match` with the loaded etag and returns 409 on a stale write; the web session replays its pending edits onto the newer file instead of overwriting it.

Determinism (`canonical.ts`): schema key order, entity collections sorted by id, order-insensitive lists sorted, free-form maps key-sorted, no timestamps on the root. Ids are readable and stable (`thr_forged-callbacks-3fa1`), never change on rename, and for source-derived entities are computed from a stable key so rescanning yields the same ids. Reloading and saving an unchanged model writes the same bytes (tested).

### Domain validation: zod 4 schemas plus an integrity pass
Strict schemas (unknown fields fail) in `model.ts`. `validate.ts` adds what a schema cannot express: referential integrity, unattributed human input, and the control invariants (an `implemented` or `verified` mitigation needs a named person or import in `statusSetBy`; `verified` needs evidence). The server refuses to store a model that fails; the CLI and MCP use the same function.

### The five kinds of claim stay separate
- *Observed fact*: `basis: observed`, backed by evidence with source revision and location.
- *Inference*: `basis: inferred`.
- *Hypothesis*: `basis: hypothesis`. Threats default to this.
- *Human decision*: a `Decision` record with actor, time and rationale. Accepting a risk, closing a review item, accepting or rejecting a proposal and changing a status all create one.
- *Implemented and verified control*: mitigation `status` with `statusSetBy` and verification evidence. Evidence that goes stale makes "verified" read as "verified, evidence stale".

Likelihood and impact are ordinal levels with a required-in-practice rationale. Evidence strength is a separate field. There are no numeric scores.

### Graph editing: React Flow (`@xyflow/react`)
Chosen for accessible-by-default nodes (focusable, keyboard movable), custom node types and a mature edge model. Trust boundaries are computed bounding boxes around member components, not React Flow parents, so membership is data (`memberIds`) editable in the inspector and the table, and overlapping boundaries (a component in two networks) work. Layout is stored in `view.layout` and ignored by comparison. A Table view provides every essential canvas operation without a pointer.

### Review: deterministic, explicit links only
`diffModels` compares semantic fields of two models. `deriveReviewItems` walks explicit relationships from each change (component to its flows, boundaries, threats, assumptions; threats to their mitigations; evidence to everything citing it), each item carrying a human-readable trace. Items have deterministic ids, so repeating a comparison creates nothing new and never reopens an item a person closed. This is intentionally not attack-path analysis.

### Source analysis
`extract.ts` parses Docker Compose and Kubernetes YAML as data (no execution), records evidence with file, line range, a redacted quote and a content hash, and emits source-keyed elements, flows and boundaries. `sync.ts` merges by stable key: human edits and links survive, a human override of exposure is pinned against rescans, components that disappear are flagged rather than deleted, and evidence whose quoted text vanished is marked stale.

`server/ingest.ts` enforces the filesystem boundary: directories only, no symlinks followed, no archives, depth/entry/size limits, secret-looking filenames never opened, VCS revision read from `.git` files without running git.

### AI: adapters, one structured call, proposals only
`ModelAdapter` is a four-method interface. Provider specifics (request shape, error mapping, usage fields) live in the adapter. The Anthropic adapter uses the official SDK with an explicit base URL and `output_config.format`; the OpenAI-compatible adapter uses `fetch`.

The orchestrator makes one bounded structured call per attempt, not an agent graph. A simple call is the cheapest thing that can work; agents should be added only when the evaluation in `docs/AI.md` shows a measured gain. Retries are limited to retryable errors plus one repair attempt for malformed output, capped at 3, with token budgets and cancellation.

All output passes `ingestAiOutput`, the only way model text reaches the project: strict schema, references must resolve to existing entities or batch keys, citations must quote text that was actually sent (corrected or dropped), unverifiable `inferred` becomes `hypothesis`, duplicates and previously rejected proposals are skipped. The model has no tools, so there is nothing for injected text to authorise.

### Visual system
"Drafting table": paper and ink neutrals, one action colour, one signal colour reserved for *needs review*. Every status is a glyph plus a word (`◆ Needs review`, `▲ Stale evidence`, `✓ Verified`, `◇ Proposed`, `? Hypothesis`), never colour alone. Node shapes differ by kind. System fonts only (no network fetches); light, dark and system themes; visible focus on everything.

## Where to extend
- New provider: implement `ModelAdapter` in `packages/ai/src`, register it in `createAdapter` (see CONTRIBUTING).
- New knowledge pack: rules in `packages/core/src/packs.ts` produce proposals from model facts or changes.
- New source artefact: add an extractor in `packages/core/src/extract.ts` returning the `Extraction` shape and allow its filenames in `server/ingest.ts`.
