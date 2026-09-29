# Connector configuration templates

Copy `connector.example.json` to `C:\ProgramData\MWA\connector.json` and fill
in **lab** values. Validate with:

```powershell
uv run python scripts/validate_config.py --config C:\ProgramData\MWA\connector.json
```

Rules (fail-fast at startup):

- Every record carries `customer_id`, `tenant_id`, `connector_id`,
  `forest_id`, `domain_id` — no global defaults cross boundaries.
- `managed_ous` must sit under `base_dn`; targets outside are denied.
- `use_ldaps: true` + `ldaps_require_cert: true` are mandatory for any
  password capability; cleartext LDAP never carries secrets.
- `auth_mode: "gmsa"` preferred; `bind_password` stays empty unless the
  traditional-account phase explicitly requires it (vault-sourced).
- `source_anchor_strategy` is per-customer config, never a hardcoded global.
- No real secrets, hosts, DNs, or certificates in version control — ever.
