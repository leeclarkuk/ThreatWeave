# AI assistance

AI is optional. Everything except "Run analysis" works with no provider and no network.

## What it does
You select files from a folder you have previewed. ThreatWeave sends the redacted file text and the model's current component, flow, boundary, threat and assumption names (as trusted-structure context) to the configured provider and asks for structured proposals: threats, mitigations with verification steps, assumptions, open questions, and missing components, flows or boundaries. Each proposal arrives as a pending item with its reasoning, citations, missing information, and validation notes. A person accepts, edits or rejects each one. Output never replaces accepted work.

## Adapters
| Adapter | Request | Structured output | Usage | Notes |
|---|---|---|---|---|
| Anthropic Messages API | Official SDK, explicit base URL, `max_tokens`, `system`, one user message | `output_config.format` with a simplified JSON schema | Read from `usage.input_tokens` and `output_tokens` | Forced `tool_choice` is not used (rejected by current models). Temperature and thinking settings are omitted so the adapter works across model generations. `refusal` and `max_tokens` stop reasons are treated as failures, never as partial results |
| OpenAI-compatible | `POST {base}/chat/completions`, system and user messages | `response_format` of `json_object` (default), `json_schema` or none (schema in the prompt) | Read from `usage.prompt_tokens` and `completion_tokens` when present; otherwise reported as unavailable | Streaming, tools and images are not used. `max_tokens` or `max_completion_tokens` is selectable |

**Model identifiers are configuration.** There is no default model id in code; you set one in Settings. Cost is `null` ("unavailable") unless you enter per-million-token prices, and a missing usage block is reported as unavailable, never estimated as actual.

### What is and is not verified
- **Verified, simulated:** request shapes (headers, body fields, absence of forbidden fields), usage parsing, error mapping, retry-after handling, bounded retries, timeout, cancellation, malformed and refused output, and that a credential echoed by a server never reaches an error message. Tests: `packages/ai/test/analysis.test.ts`, using a local server whose responses follow each API's documented shape.
- **Not verified live:** neither adapter has been exercised against a real endpoint in this repository, because no credentials were available. A simulated server can be wrong about the real API. Each adapter reports `liveVerified: false` and the UI says so.
- **Local models:** the OpenAI-compatible adapter is *not* claimed to work with Ollama, llama.cpp, vLLM or any particular local server. JSON mode support and token parameter names differ between them. Test your server with Settings, Test connection, then a small analysis, and use `json_object` or `none` if `json_schema` is rejected.

### Run the live checks yourself
```bash
# connectivity and one small analysis, from the UI: Settings, Test connection; Source, Run analysis
# or measure quality on the evaluation set:
ANTHROPIC_API_KEY=... EVAL_MODEL=<model id> npx tsx evals/run.ts --adapter anthropic
EVAL_BASE_URL=http://127.0.0.1:11434/v1 EVAL_MODEL=<model id> npx tsx evals/run.ts --adapter openai-compatible
```
Record the results under `evals/results/` with the model id. Treat a run as evidence for that model on that day only.

## Controls
- **Disclosure and confirmation:** the Source tab lists the exact files, sizes, redaction count and provider host. Running requires ticking a confirmation, and the server rejects a run whose confirmed host differs from the configured one or whose files changed since the preview.
- **Budgets:** max estimated input tokens (the request is refused before sending if exceeded), max output tokens, max total tokens across attempts, retries (hard cap 3), timeout, and an optional cost cap that applies only when prices are configured.
- **Cancellation:** cancels the in-flight request, never retries afterwards, records the run as cancelled and leaves the project unchanged.
- **Failure:** provider failures, refusals, malformed output and timeouts are recorded on the run with a readable reason. No partial proposals are kept.
- **Orchestration:** one structured call per attempt. A multi-agent design was not built: nothing here shows it would improve quality, and it would multiply cost and the surface for injected text. Revisit only if the evaluation below shows a measured gain.

## Validation of model output (`ingestAiOutput`)
1. Strict schema: unknown fields, wrong types, and any attempt to set a status fail. Mitigations are created as `proposed`; they cannot be implemented or verified by the model.
2. References must resolve to an existing element, flow, boundary, asset, threat or assumption, to an exact component name, or to a draft key from the same batch. Otherwise the proposal is discarded as not tied to this system.
3. Citations (`path`, line range, quote) must quote text that exists in a file that was actually sent. A real quote at the wrong lines is corrected; anything else is dropped with a note. Inferred claims with no surviving citation become hypotheses and a "moderate" or "strong" evidence rating is lowered to "weak".
4. Duplicates, near-duplicates on the same target, and previously rejected proposals are skipped. A dependent proposal (a mitigation for a proposed threat) can be accepted only after what it depends on.
5. Control characters are stripped. All text is rendered as text, never as markup.

**Limits of that validation:** it proves a quote exists in a sent file, not that the quote supports the claim, and it cannot judge whether a hypothesis is true. A fluent, wrong proposal with a real but irrelevant quote will pass. That is why proposals show their reasoning and need a person.

## Untrusted content
Repository text is placed inside `<untrusted_file>` blocks (any closing tag inside the content is neutralised), the system prompt says it is data and never an instruction, and the model is given no tools, so it cannot be talked into using one. Injected text could at worst influence the *content* of a proposal, which still passes validation and still needs a decision. Tested: a hostile file cannot close its own block, change settings, or cause a second provider call.

## Evaluation
`evals/` holds a small versioned set (v1): three fictional systems, expected threats matched by keyword groups and a target component, and conditions deliberately absent from the files. Metrics: **missed expected threats**, **unsupported suggestions** (assuming an absent condition, or discarded as ungrounded), and **fabricated citations**. The number of threats generated is deliberately not a metric.

Simulated runs (canned output through the real validation pipeline). These test the harness and the pipeline's defences, not any model:

| Variant | Found | Missed | Unsupported | Fabricated citations |
|---|---|---|---|---|
| grounded | 9/9 | 0 | 0 | 0 |
| generic | 2/9 | 7 | 7 | 0 |
| fabricating | 4/9 | 5 | 2 | 7 |

In the fabricating variant, proposals with fake citations still count as "found" when their text matches, because the pipeline keeps the proposal as a hypothesis with the citation stripped and a visible note. The fabricated citations are what the last column counts.

**No live model has been evaluated.** Three small systems can expose failure modes but cannot establish general quality; matching is keyword-based and will miss valid phrasings and accept some invalid ones.
