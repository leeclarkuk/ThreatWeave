# Security policy

ThreatWeave is a local, single-user tool. It is not a hardened multi-tenant service; see `docs/SECURITY-MODEL.md` for what it does and does not defend against.

## Reporting a vulnerability

No security contact address has been published for this project yet, and this file deliberately does not invent one.

Until the maintainers publish one:

1. **Do not open a public issue** containing exploit details.
2. If the repository is hosted on GitHub and private vulnerability reporting is enabled, use the repository's **Security** tab, then **Report a vulnerability**.
3. If that is not available, open a public issue that says only "I have a security report, please provide a private channel", with no technical detail, and wait for a maintainer to respond.

Maintainers: please replace this section with a monitored address or enable private reporting before the first public release, and state a response target you can meet.

## Supported versions

Only the latest commit on the default branch. There are no tagged releases yet.

## Scope notes for reporters

In scope: path traversal or symlink escape in source ingestion, a way for repository or model-provider text to change settings, run code, read files outside the chosen folder or alter accepted model content, credential exposure through exports, logs, API responses or the browser bundle, cross-site request forgery or DNS rebinding against the local server.

Known and documented, not vulnerabilities: no authentication when you bind beyond localhost; credentials saved through the UI are stored in plaintext with file mode 0600; two processes can race on the same project file.
