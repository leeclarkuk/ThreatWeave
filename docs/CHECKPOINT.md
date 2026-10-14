# Checkpoint

Temporary progress notes. Durable lessons live in `CLAUDE.md`.

## Completed
- Domain core: strict versioned model, integrity and control invariants, deterministic serialisation, edit functions, Threat Composer import and lossy export (tested against the published schema), Compose and Kubernetes extraction, evidence staleness, model diff, relationship-traced review, rule pack, proposal pipeline (validation, accept, edit, reject, dedupe), Markdown report.
- AI: Anthropic and OpenAI-compatible adapters, bounded orchestrator (budgets, retries, timeout, cancel, usage), contract tests against a simulated server, evaluation harness with a versioned set.
- Server: file store with optimistic concurrency, safe ingestion, settings and credentials, run lifecycle with restart recovery, HTTP API with host and CSRF guards.
- Web: canvas and table, inspector, threats, assumptions, mitigations with attestation dialogs, evidence, review with grouped items and proposals, compare, source, settings, report, import preview, undo and redo, light and dark.
- CLI and MCP server sharing the same core. Docs, Dockerfile and compose file, CI workflow.
- Browser journey (`npm run e2e`): see `docs/VERIFICATION.md` for the latest result.
- Stabilisation milestone: cross-process locking, crash-safe writes, backup and restore, anchored evidence invalidation, deterministic example, clean-clone `npm run verify`. All covered by tests written first.

## Remaining and known gaps
- Not verified live: both AI adapters (no credentials in the build environment). Run `npm run live:check`.
- Not verified: the Docker image build (no Docker daemon). The runtime layout is exercised by `npm run verify` with production dependencies only.
- Unanchored evidence (documents, accepted AI citations) is only checked at file level. Candidate: assign an anchor at acceptance time by locating the cited lines inside a component's block.
- No assistive-technology or user testing. The file lock is advisory, local, and tested on Linux only.
- Source support is Compose and Kubernetes only. NetworkPolicy is noted, not evaluated.
- No schema migrations yet (only schema version 1 exists).
- Large-model canvas performance and layout quality untested beyond tens of components.

## Next concrete action
Run the live adapter checks with real credentials and record `evals/results/<adapter>.json`, then use the missed and unsupported lists to decide whether a second pass (for example a separate verification call) earns its cost.
