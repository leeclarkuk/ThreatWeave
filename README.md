# ThreatWeave

A local-first threat modelling workbench for engineers. It is built around one question:

> What changed, which security assumptions did it invalidate, and what needs review?

"ThreatWeave" is a working name. It is one constant (`PRODUCT_NAME` in `packages/core/src/model.ts`) plus package names, so it is cheap to change.

- **Manual first.** Model a system, its threats, assumptions and mitigations with no account, no network and no AI provider.
- **One model.** The canvas, the tables, the threat list and the review queue all read the same validated model. Selecting a threat highlights what it affects; selecting a component shows its reasoning.
- **Honest about certainty.** Observed facts, inferences, hypotheses, human decisions and verified controls are different things and are shown differently. Severity and evidence strength are separate. A threat is a hypothesis, not a finding.
- **Change-aware.** Scan a newer revision of a Docker Compose or Kubernetes folder, or compare two model revisions. You get the deterministic changes, the affected boundary, and the assumptions, threats and mitigations connected to it through explicit links, each with the reason it was flagged.
- **Your decisions survive.** AI and rule-pack output arrives as validated proposals you accept, edit or reject. Reanalysis never replaces accepted work and never resurrects what you rejected.
- **Portable.** One deterministic JSON file per project (readable Git diffs), Markdown report, Threat Composer import and lossy export, a CLI that works in CI, and a narrow MCP server.

Status: first release. See [Limitations](#limitations) before relying on it.

## First successful workflow (about five minutes, offline)

Requires Node.js 20 or later.

```bash
npm install
npm run build
node packages/cli/dist/bin.js serve        # http://localhost:4317, data in ./.threatweave-data
```

1. Open http://localhost:4317 and choose **Open a copy of the demonstration**. It is a fictional shop, labelled as demonstration content.
2. Open **Threats**, select *Unauthorised stock manipulation through the inventory service*, then go to **Architecture**. The components it affects are highlighted and the rest are dimmed.
3. Open **Source**, click *Northwind Shop, revision 2*, then **Sync from this folder**. In revision 2 the internal `inventory` service now publishes port 9000.
4. Open **Review**. The inventory component, the assumption that it is internal-only, the threat, the mitigation recorded as implemented, the flows into it and the `backend` boundary are flagged. Expand *Why was this flagged?* to see the chain. Rule-pack proposals wait for your decision.
5. Resolve or dismiss items (a reason is required and recorded under your name), accept, edit or reject proposals, then export from **Report**.

To start your own model, use **New model** on the home page, or import a `.threatweave.json` or Threat Composer `.tc.json` file.

### Container

```bash
docker compose up --build        # http://localhost:4317, published to loopback only
```

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for mounting a folder to analyse and for the limits of the container setup. The image could not be built in the environment this release was developed in (no Docker daemon); see [Verification](docs/VERIFICATION.md).

### CLI

After `npm run build`, run it as `node packages/cli/dist/bin.js <command>`, or `alias threatweave='node packages/cli/dist/bin.js'` (or `npm link -w @threatweave/cli`) to use the short form below.

```bash
threatweave validate model.threatweave.json
threatweave compare before.json after.json --fail-on-review   # exit 3 if the change needs review: usable in CI
threatweave import-tc workspace.tc.json -o model.threatweave.json   # prints what was lost
threatweave scan ./repo                                       # what would be analysed; sends nothing
threatweave sync model.threatweave.json ./repo                # deterministic source sync, no AI
threatweave report model.threatweave.json -o report.md
threatweave mcp                                               # MCP server on stdio
```

## AI assistance (optional)

Two adapters ship: **Anthropic Messages API** and **OpenAI-compatible chat completions**. Provider SDK types never reach the domain model. Model identifiers are settings. You see exactly which files and which host before anything is sent, and you must confirm each run. Output is validated, citations are checked against the text that was actually sent, and fabricated references are dropped. Cancellation, timeouts, bounded retries, token budgets and usage reporting are built in; cost is shown only if you enter prices.

Neither adapter has been verified against a live endpoint in this repository (no credentials were available). Contract tests run against a simulated server. See [docs/AI.md](docs/AI.md) for what that does and does not show and the command to run the live check yourself.

## Documentation

- [Architecture and design decisions](docs/ARCHITECTURE.md)
- [Model schema and compatibility](docs/SCHEMA.md)
- [Comparison with AWS Threat Composer](docs/REFERENCE-COMPARISON.md)
- [AI adapters, budgets, evaluation](docs/AI.md)
- [Security model and credential storage](docs/SECURITY-MODEL.md) and [SECURITY.md](SECURITY.md)
- [Operations: data, container, backups](docs/OPERATIONS.md)
- [Verification results](docs/VERIFICATION.md)
- [Contributing](CONTRIBUTING.md) (adding a provider adapter or a knowledge pack)
- [Working notes for coding agents](CLAUDE.md), [checkpoint](docs/CHECKPOINT.md)

## Limitations

Read these before you rely on the output.

- **Not an attack-path tool.** Review flags follow explicit links (a flagged component leads to threats and assumptions that reference it, its flows and its boundaries). Anything you did not link is not found. Coverage is incomplete by design.
- **Source input is narrow.** Docker Compose and Kubernetes manifests only (Deployment, StatefulSet, DaemonSet, Service, Ingress). No Terraform, CloudFormation, Helm, Kustomize, or application source. NetworkPolicy is noted but not evaluated. Exposure from published ports means reachable from the host's network, which may or may not be the internet.
- **Heuristics.** Data stores are recognised from image names; flows are inferred from environment URLs and `depends_on`; these are marked as inferred.
- **Evidence staleness is textual.** Evidence goes stale when its quoted text is gone from the file. A semantic change that leaves the text intact is not detected.
- **AI quality is unproven.** The small evaluation set can show failure modes, not general quality. See docs/AI.md.
- **Single user, local.** No authentication, no multi-user editing, no real-time collaboration. Two processes writing the same project at the same instant can lose an update (the web app detects and merges its own conflicts; the MCP server and CLI do not take a cross-process lock).
- **Credentials are stored in plaintext** in the data directory (mode 0600) if you save them in the app. Prefer environment variables.
- **Threat Composer round trips are not lossless.** Import keeps threats, mitigations, assumptions, links and ids; the architecture images, brainstorm notes and unknown fields are not converted. Export drops structure, judgements, evidence and provenance and tells you so.
- **Accessibility.** An automated audit (axe-core) and a keyboard walkthrough pass on the main views; there has been no testing with assistive technology or users.
- **Large models.** The canvas has no automatic routing or grouping beyond a simple layered layout and has been exercised with tens of components, not hundreds.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Material reused from AWS Threat Composer (also Apache-2.0) is listed in NOTICE.
