# Verification

What was checked, how, and what could not be. Simulated evidence is labelled as such throughout. Nothing here is live provider evidence.

## Reproduce
```bash
npm install && npm run build
npm test            # 77 unit and integration tests (vitest)
npm run e2e         # 38 browser steps in real Chromium against a real server process
npm run eval:sim    # AI evaluation harness with canned output (writes nothing unless --save)
npm run check       # build + tests + simulated evaluation + example validation
npm run verify      # all of the above from a clean clone of the COMMITTED tree, plus a production-only runtime
```
`npm run e2e` writes `e2e/last-run.json` and screenshots to `docs/screenshots/`. It needs Chromium (`CHROMIUM_PATH`, or `PLAYWRIGHT_BROWSERS_PATH`).

## Results (this build)
| Suite | Result |
|---|---|
| Unit and integration tests | 77 passed: core 30 (Threat Composer import and export against the real schema; extraction; the change-aware scenario; mitigation invariants; serialisation; evidence invalidation), ai 18 (adapter contracts, failure modes, hostile content), server 19 (persistence, concurrency, crash and corruption handling, ingestion safety, local-service hardening, reproducible example), cli 10 (exit codes, scenario, MCP) |
| Browser journey (`e2e/journey.ts`) | 38 of 38 steps passed |
| Evaluation harness, simulated variants | grounded 9/9 found, 0 unsupported, 0 fabricated; generic 2/9, 7 unsupported; fabricating 4/9, 7 fabricated citations (see `docs/AI.md`; harness validation, not a model result) |
| Clean-clone reproducibility (`npm run verify`) | Passed for commit `f78ae1a`: fresh clone of committed files only, `npm ci` (241 packages), build, 77 tests, simulated evaluation, example validation, then a production-only runtime (`npm ci --omit=dev`, built output only: health, static app, example creation, CLI) and a check that no tracked file changed during build or tests |

## Requirement to evidence
| Requirement | Evidence |
|---|---|
| Manual modelling without AI credentials | E2E A1, A2, B1 to B5, C1 to C4 run with the provider key variables blanked; H3 asserts the manual workflow makes no request beyond the local server |
| Persistence across restart | E2E D1 reloads the page, kills and restarts the server process on the same data directory, and compares element ids; server test "creates, edits and persists a project across a simulated restart" |
| Architecture and threat relationships consistent | E2E B4 and C1 (flow endpoints exist, threat targets come from the shared model); validator rejects dangling references (server test, 422); canvas highlighting from a threat selection (F2, F9) |
| Import and export preserve supported information and stable ids | core `tc.test.ts`: real files import with ids preserved, mitigation and assumption links preserved, export validates against the published Threat Composer schema, supported fields round-trip; E2E E1 compares exported element ids with the stored model and runs the CLI validator on the downloaded file |
| Unsupported import data produces visible warnings | core test (image, unknown field, brainstorm notes, dangling links with exact count); E2E E3 shows them in the import preview before anything is saved; E2 shows loss before a Threat Composer export; E4 rejects a malformed file without crashing |
| Malformed AI output rejected safely | ai test (over-reaching, fabricated, generic and wrongly shaped proposals: 4 of 5 discarded, one kept as a downgraded hypothesis, model unchanged); E2E G6 (non-JSON reply: run fails with a reason, nothing added) |
| Accepting and rejecting proposals without corrupting existing work | core scenario tests; E2E F7 (dependency ordering, edit then accept, reject with reason, generated mitigation stays "proposed", validator still passes) |
| Reanalysis preserves human decisions | core: a closed review item stays closed and decisions are not duplicated on re-sync; a rejected proposal is not resurrected; E2E F6 and G4 |
| Cancellation and provider failure leave the project usable | ai tests (cancel with no retry; 500 with bounded retries; timeout; unreachable); E2E G5 (failed run, then a successful edit), G7 (cancel: exactly one provider call) |
| Meaningful comparison of two revisions | core diff test (layout and ordering ignored, one semantic change reported), CLI `compare` with `--fail-on-review` exit code 3, E2E F8 |
| Untrusted source instructions gain no tool authority | server test (hostile compose file: settings unchanged, secret value absent from the model); ai test (injected closing tag neutralised, no extra provider call); the model has no tools; MCP exposes no decision tools (cli test) |
| Basic keyboard access to the primary workflow | E2E A1 and A2: reach the name field with Tab only, create a model with Enter, switch section with Alt+2, add a threat with `/` and Enter; focus outline asserted; every canvas operation also exists in the table view |
| Provider contract tests with controlled fixtures | `packages/ai/test/analysis.test.ts` against `mock-server.ts`: request shape and headers, absence of forbidden parameters, usage, cost only when prices are set, auth, refusal, retry-after, bounded retries, timeout, cancellation, missing key |
| Accessibility | E2E H1: axe-core (WCAG 2.0 and 2.1 A and AA rules) found no serious or critical violations on home, canvas, table, threats, assumptions, mitigations, evidence, review, source, report, the settings dialog and the review view in dark mode. H2: no horizontal page scroll at 900 and 420 px |
| Persistence under concurrency | `persistence.test.ts`: 4 processes x 25 read-modify-write cycles land 100 of 100; an ad hoc run of 8 processes x 40 landed 320 of 320 three times; a lock left by a dead process does not block writers; concurrent snapshots number 1 to 5 without collision |
| Crash and corruption handling | tests: previous version kept as `.bak`; a truncated model file is listed as unreadable (not hidden) and restored from the backup; a backup that does not validate is refused; stale temp files are cleaned and fresh ones are not. E2E D3 does this through the UI |
| Evidence invalidation | core tests: stale when cited text moves to another component (the text still exists in the file), when the component is renamed, when the cited line is edited, when the file moves; **not** stale for whitespace, comments or unrelated edits; stale stays until a person re-affirms; server test: capturing a newer source for AI analysis invalidates contradicted evidence before any provider answer |
| Credentials | server test: a saved key is never returned by the API or present in an export; ai test: a key a server echoes back never appears in a run result |

## What could not be verified here
- **Live provider behaviour.** No credentials were available. Both adapters are verified only against a local simulated server whose responses follow each API's documented shape; the real APIs may differ. Run `LIVE_MODEL=<id> npm run live:check -- anthropic` (needs `ANTHROPIC_API_KEY`) or `-- openai-compatible` (needs `LIVE_BASE_URL`), then `npx tsx evals/run.ts --adapter ...` for quality.
- **Local-model compatibility.** The OpenAI-compatible adapter was not run against Ollama, llama.cpp, vLLM or any hosted OpenAI-compatible service.
- **The Docker image.** The sandbox has no Docker daemon, so `docker build` and `docker compose up` were not run. Command to finish: `docker compose up --build`, then open http://localhost:4317 and `docker compose exec threatweave node packages/cli/dist/bin.js validate examples/northwind.threatweave.json`.
- **Assistive technology and real users.** Automated rules and a keyboard walkthrough cannot show that a screen reader user can complete the workflow. Test with one before claiming accessibility.
- **Scale.** Models with hundreds of components, and canvas performance and layout quality at that size.
- **Cross-browser.** Only Chromium was used.
- **Evaluation of any model.** The evaluation set is small and the matching is keyword-based. Simulated runs test the harness, not a model.

## Defects found and fixed by this verification (so they stay fixed)
Found while building the first version:
- A rejected import (no `warnings` array in the response) crashed the whole interface with a blank page. Fixed; E4 covers it; an error boundary now shows a recoverable message for any future render fault.
- Pressing Enter in a single-field form did nothing, because the field blurred itself and cancelled implicit submission. Fixed.
- Buttons disabled until a commit-on-blur field changed were skipped by Tab. Fixed with live fields where a button depends on the value.
- The weaker `depends_on` flow shadowed the richer environment-URL flow, hiding the observed `http://` scheme. Fixed; core test asserts the flow keeps its protocol.
- Review flagged outbound flows as if they were inbound. Fixed.
- "Analysis finished" appeared before the project had reloaded, so Review briefly showed no proposals. Fixed.
- A hidden screen-reader span inside the scrolling section rail leaked into the page's scroll width at phone size. Fixed.
- Escape did not close a dialog unless focus was inside it. Fixed; asserted in H1.
- Form labels wrapped their `<select>` so accessible names included option text. Fixed.
- The canvas "＋ Boundary" button only switched view; "Show on diagram" in Review did not leave Review. Fixed; B5 and F9 cover them.
- The inspector drawer covered the page at phone width even with nothing selected. Fixed; asserted in H2.

Found by the stabilisation milestone (each with a failing test written first):
- **Lost updates across processes.** The web server, CLI and MCP server could all write one project with no cross-process lock; four processes lost updates. Now every write takes a lock file, and writes are flushed and atomically replaced.
- **No recovery from a damaged file.** A torn write left no backup, and the old UI listed the project as an empty model ("0 components") instead of saying it could not be opened. Now the previous version is kept as `.bak`, the project is shown as unreadable with its reason, and restore is one click or `threatweave restore`.
- **Concurrent snapshots could collide** on revision numbers and were not written atomically. Now serialised and atomic.
- **Evidence invalidation had false negatives.** It only asked whether the quote existed somewhere in the file, so text moved to another service, or a renamed service, stayed "valid". Evidence is now anchored to the component it was captured for and re-checked against what the current files say about it. Unanchored evidence still gets only the weaker file-level check, and that is stated in the UI.
- **The bundled example could not be reproduced** (wall-clock times and random ids), and `npm run eval:sim` rewrote tracked result files on every run. Both are now deterministic; a test asserts the committed example is byte-identical to a regeneration.
- **Process error:** I ran a browser journey against a stale web bundle after editing the home page without rebuilding it. The journey caught it (it showed the damaged project as empty), but the lesson is that `npm run check` and `npm run verify` build first.

## Still not verified
- The lock was exercised on one machine, one local filesystem, Linux. Network file systems, Windows and macOS were not tested, and advisory locking is documented as unsupported on network shares.
- Only Node 22.22.0 was tested. `engines` allows 20.3 and later; that range is untested.
- The Dockerfile now pins `node:22.22.0-slim`, but the image was not built (no Docker daemon). No image digest is pinned.
- Evidence checks for unanchored evidence (documents, accepted AI citations) remain file-level.
