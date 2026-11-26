# Security Policy

## Architectural Security Guarantees

IntuneGuard Studio is designed for regulated enterprise environments (financial services, healthcare, public sector):

- **Local Custody Only:** Runs 100% locally or inside your own private infrastructure. Zero external SaaS control plane or telemetry.
- **Hardcoded Outbound Egress Allowlist:** In `live` mode, `LiveGraphAdapter` blocks any outbound connection outside `login.microsoftonline.com` and `graph.microsoft.com`.
- **Zero Static Secrets in Production:** Documentation and setup scripts enforce X.509 Certificate or Azure Managed Identity authentication.
- **Tamper-Evident ITIL Logging:** All governance actions write to a SHA-256 hash-chained SQLite database and append-only JSONL file.
- **Human-in-the-Loop AI Governance:** MCP write proposals (`propose_policy_change`) cannot mutate Microsoft Graph directly; they queue for human CAB review.

---

## Reporting a Vulnerability

If you discover a security issue (such as an egress allowlist bypass, path traversal, XSS in report exports, or audit chain tampering weakness):

1. **Do NOT open a public GitHub issue** containing exploit details.
2. Report privately via GitHub Security Advisories ("Report a vulnerability" in the repository's **Security** tab) or contact the repository maintainer directly.
3. Include steps to reproduce, affected file/endpoint, and suggested mitigation if known.

We aim to acknowledge reports within **48 hours** and release a verified fix promptly.

---

## Operational Security Reminder for Users

- **Never commit** exported tenant JSON files (`intuneguard_snapshot.json`), `.env` files, certificates (`.pfx`/`.pem`), or local `data/` audit databases to version control.
- Always run cleanup scripts in default **Dry-Run / Read-Only** mode first and review changes through your organization's ITIL CAB process.
