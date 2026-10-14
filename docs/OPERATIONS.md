# Operations

## Data
Default data directory: `./.threatweave-data` (override with `--data DIR` or `THREATWEAVE_DATA`).

```
<data>/config.json                      settings and, if you saved them, credentials (mode 0600)
<data>/projects/<id>/model.json         the model (commit this to Git if you like)
<data>/projects/<id>/revisions/*.json   immutable snapshots used by Compare
```

To keep models in a repository, point `--data` at a directory in that repository and add `config.json` to `.gitignore`. `model.json` is deterministic, so diffs show real changes only.

Back up by copying the directory. Deleting a project in the UI removes its directory and revisions; it asks first and cannot be undone.

## Recovery
- A save that fails validation is refused with the reasons; the file on disk is untouched.
- A run left `running` by a crash or restart is marked `failed (interrupted)` on the next start.
- If a file is edited by hand and no longer validates, the project is skipped in the list and `threatweave validate <file>` prints why. The server never deletes it.

## Container
`docker compose up --build` publishes `127.0.0.1:4317` only. The data volume is `threatweave-data`. To analyse a local folder, uncomment the read-only bind mount in `docker-compose.yml`; set the path in the Source tab to `/sources/repo`. `THREATWEAVE_SOURCE_ROOTS` limits which directories can be scanned.

The compose file drops capabilities, sets `no-new-privileges` and a read-only root filesystem. It is a convenience for one person, not a deployment pattern: there is no authentication, so do not publish the port beyond loopback or put it on a shared network without a gateway that adds authentication.

Kubernetes is not required and no manifests are provided.

## Environment
| Variable | Purpose |
|---|---|
| `THREATWEAVE_DATA` | Data directory |
| `THREATWEAVE_SOURCE_ROOTS` | Colon-separated allow-list of directories the Source tab may scan |
| `THREATWEAVE_ALLOWED_HOSTS` | Extra Host header values to accept (for example a reverse proxy name) |
| `ANTHROPIC_API_KEY`, `THREATWEAVE_ANTHROPIC_API_KEY` | Anthropic credential |
| `OPENAI_API_KEY`, `THREATWEAVE_OPENAI_API_KEY` | OpenAI-compatible credential (optional for local servers) |
| `THREATWEAVE_BIND_ACK=1` | Suppress the non-loopback bind warning (set in the container image) |

## MCP
`threatweave mcp --data DIR` speaks MCP over stdio. Tools: `list_projects`, `get_model_summary`, `validate_model`, `list_review_items`, `list_proposals`, `list_revisions`, `compare_models`, `submit_proposals`. There is deliberately no tool to accept or reject anything, change a status, or edit the model. `submit_proposals` validates input like AI output and stores pending proposals; file evidence cannot be asserted through MCP so they arrive as hypotheses. The MCP process and a running web server can write the same project; a simultaneous write can lose an update.

Example client configuration:
```json
{ "mcpServers": { "threatweave": { "command": "node", "args": ["/path/to/threatweave/packages/cli/dist/bin.js", "mcp", "--data", "/path/to/data"] } } }
```
