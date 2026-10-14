# ThreatWeave: working notes for coding agents

Keep this file short. Verified, reusable lessons only. Progress and incident detail live in `docs/CHECKPOINT.md`. Never put secrets or unverified conclusions here.

## Commands
- `npm install && npm run build` (tsc project builds, then the Vite web build)
- `npm test` (vitest: core, ai, server)
- `npm run e2e` (real Chromium against a real server; needs a build first; set `CHROMIUM_PATH` if Chromium is not in `PLAYWRIGHT_BROWSERS_PATH`)
- `node packages/cli/dist/bin.js serve` then open http://localhost:4317

## Architecture rules (do not break)
- All domain rules live in `packages/core` and must stay browser-safe (no `node:` imports). Web, server, CLI and MCP call the same functions. Do not reimplement validation elsewhere.
- Edits are pure functions `(Model) => Model` (see `ops.ts`, `proposals.ts`). The web session replays pending ops on top of a newer file after a 409.
- Provider SDKs and formats stay inside `packages/ai`. Model identifiers are configuration; never hard-code one.
- Model output goes through `ingestAiOutput` only. It must never reach the model un-validated, never create entities directly, never set mitigation status.

## Security constraints (permanent)
- A mitigation can be `implemented`/`verified` only with a named person or import in `statusSetBy`; `verified` needs evidence. AI and rule-pack mitigations start `proposed`.
- Repository text, imported files and model output are untrusted data. Nothing from them executes, selects tools or changes settings. Ingestion never runs git or scripts, never follows symlinks, never reads secret-looking files.
- No telemetry. No credentials in models, bundles, logs or API responses. Local server binds 127.0.0.1 and checks Host and `X-ThreatWeave`.

## Verified lessons
- Current Claude models reject forced `tool_choice` (HTTP 400). The Anthropic adapter uses `output_config.format` instead. (From the API reference; not live-verified here.)
- `yaml`'s `maxAliasCount` is a `toJS` option, not a parse option.
- A button disabled until a commit-on-blur field changes is skipped by Tab. Use `TextField live` when a control depends on the value.
- Threat Composer's own `ThreatComposer.tc.json` example contains links to threats that do not exist. The importer skips and reports them; tests assert the exact count.
- Do not `pkill -f <pattern>` where the pattern appears in your own command line.
- Prefer env-var `ANTHROPIC_BASE_URL` awareness: the adapter always passes an explicit base URL so the disclosed host is the real host.
