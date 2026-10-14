# Security model

Threat model for ThreatWeave itself, in brief. Assets: your threat models (sensitive: they describe weaknesses), provider API keys, and the integrity of accepted decisions.

## Defaults
- Binds to `127.0.0.1`. Binding elsewhere prints a warning. There is no authentication, so anyone who can reach the port can read and change every project and use any saved key.
- Rejects requests whose `Host` is not localhost (defends against DNS rebinding). State-changing requests need the `X-ThreatWeave: 1` header and a same-origin `Origin` if one is sent (defends against cross-site form posts). No CORS headers are sent.
- Static files are served with a restrictive Content-Security-Policy (`default-src 'self'`, no external scripts, styles, fonts or connections).
- No analytics, no telemetry, no update checks, no external fonts or CDNs. A test records every network request the manual workflow makes and asserts they all go to the local server.

## Credentials
- Read from environment variables (`ANTHROPIC_API_KEY`, `THREATWEAVE_ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `THREATWEAVE_OPENAI_API_KEY`) or saved in `<data>/config.json` with file mode 0600.
- **Saved keys are plaintext.** There is no OS keychain integration and no encryption at rest. Prefer environment variables, and keep the data directory out of Git and backups you do not control.
- Keys are never returned by the API (only "configured, from env or file"), never written into models or exports, never put in error messages (provider error text is not passed through, and a test asserts that a key a server echoes back never appears in a run result), and never logged. The server logs the method and path of failures only, never bodies.
- The browser bundle contains no credentials.

## Untrusted input
Repository text, imported files, tool arguments and model output are data. Ingestion never runs git or any repository script, never follows symlinks, never opens archives, never opens secret-looking filenames, and bounds depth, entries and size. The AI call has no tools, so injected instructions have nothing to authorise; the output is parsed as JSON and validated, and cannot set a mitigation status or create anything except a pending proposal. Secret-looking values are redacted before they become evidence or are sent to a provider. Imported models go through the same validator as saved ones.

What can still go wrong: a model can still write persuasive, wrong text inside a valid proposal. Proposals show reasoning and evidence, mark unverified claims, and need a person to accept them; they are not a substitute for judgement.

## What goes where
Sent to a provider only after you press Run and tick the confirmation: the text of the files you selected (redacted) and the names and ids of components, flows, threats and assumptions as context. The disclosure screen lists the files, sizes, redaction count and the host.

## Not defended
A malicious local user or process, a compromised machine, another user on a shared host with access to the port or data directory, a browser extension with access to localhost, and a hostile model provider reading what you chose to send.
