# LDAP Spike (excluded from production package)

Goal: validate primitives against a real DC before declaring support (Step 3).

Scripts are manual, lab-only, and never import production secrets:

- `test_bind.py` — LDAPS bind, cert validation (valid/expired/untrusted), simple bind under TLS, Kerberos/gMSA notes.
- `test_paging.py` — paged search over a dataset larger than the page size; duplicate/loss detection via `PagedSearchState`.

Rules:

- Run only against the lab DC with lab credentials from env vars (`LAB_LDAPS_HOST`, `LAB_BIND_USER`, `LAB_BIND_PASSWORD`, `LAB_BASE_DN`, `LAB_CA_BUNDLE`).
- Never commit credentials, certs, or lab hostnames.
- Record outcomes in `matrix.md` (supported / not supported / uncertain + evidence).
- No test in `spikes/` runs in CI quality gates except lint/type check.
