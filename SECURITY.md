# Security Policy

## Reporting

Report suspected vulnerabilities to the maintainers via the private channel defined in
`CODEOWNERS` (do not open a public issue for sensitive reports). Include: affected version,
reproduction scope (lab only), redacted logs, and impact assessment. Expect an acknowledgement
within 2 business days.

## Rules for this repository

- Never commit secrets, passwords, private keys, certificates, tokens, or lab credentials.
- LDAPS with certificate validation is mandatory for password operations; fail closed.
- Service account follows least privilege: only the minimum ACLs listed in the capability
  catalog; no Domain Admin.
- Logs, audit records, API responses and exceptions must never contain secrets or full
  hostnames/DNs beyond what the redaction policy allows.
- Dependency and secret scans run in CI (`security.yml`) and block merges on failure.
