# Contributing

## Set up
```bash
npm install
npm run build        # tsc project builds, then the Vite web build
npm test             # vitest
npm run check        # build, tests, simulated evaluation, example validation
npm run verify       # clean clone of the committed tree: npm ci, build, tests, production-only runtime, tracked files unchanged
npm run e2e          # real Chromium against a real server (needs a build; see CLAUDE.md for CHROMIUM_PATH)
npm run dev:web      # Vite dev server on :5173, proxies /api to a server on :4317
node packages/cli/dist/bin.js serve   # the API server
```

## Ground rules
- Domain logic goes in `packages/core` and stays browser-safe. The web app, CLI, MCP server and HTTP server must call it, not copy it. A rule that exists in two places will drift.
- Edits are pure functions `(Model) => Model`. Keep them undoable and replayable.
- Never weaken the invariants in `CLAUDE.md` (AI cannot attest controls, untrusted content has no authority, no telemetry, no secrets in models).
- New behaviour needs a test that checks behaviour, not only that code runs. Anything a user can see goes through the browser journey in `e2e/journey.ts` when practical.
- Say what you verified and what you could not. Simulated provider tests are not live evidence; label them.
- Plain English, British spelling in user-facing text.

## Add a provider adapter
1. Create `packages/ai/src/<name>.ts` implementing `ModelAdapter` from `types.ts`:
   - `complete(req, signal)` returns `{ text, usage, stopReason, model }`.
   - Map provider failures to `AdapterError` kinds (`auth`, `rate_limit`, `overloaded`, `server`, `network`, `timeout`, `cancelled`, `bad_request`, `refused`, `truncated`). Only the retryable kinds are retried by the orchestrator. Honour `retryAfterMs`.
   - `capabilities()` must say honestly how structured output is requested, whether usage is reported, and `liveVerified: false` unless you have verified it against a real endpoint.
   - Scrub the credential from any message with `scrub()`.
   - Keep provider types inside this file.
2. Register it in `createAdapter` in `packages/ai/src/index.ts`, add its settings to `packages/server/src/settings.ts` and the settings dialog.
3. Add contract tests with the simulated server in `packages/ai/test/mock-server.ts`: request shape, usage, auth, refusal, retries, timeout, cancellation. Add a live check you can run with credentials.

## Add a knowledge pack
Rules live in `packages/core/src/packs.ts`. A rule reads model facts (or a `Change`) and returns `Proposal`s with `origin: 'pack-rule'`, `basis: 'hypothesis'` (or `inferred` if a fact proves it), a `reasoning` that names the rule and why it fired, and honest `missingInformation`. Rules must not claim a threat is real, must not set a mitigation status, and should be specific to a fact in the model. Provider-specific knowledge (AWS, Azure, GCP, Kubernetes distributions) belongs in an optional pack, not the generic one. Add a test that the rule fires on the fact and not on a near miss.

## Add a source artefact
Add an extractor in `packages/core/src/extract.ts` that returns the `Extraction` shape with line-level evidence, allow its filenames in `packages/server/src/ingest.ts`, and add a fixture directory under `examples/repos/`. Keep ingestion safe: no execution, bounded size, report what you skip.

## Commit messages
Describe the behaviour change and how you verified it.
