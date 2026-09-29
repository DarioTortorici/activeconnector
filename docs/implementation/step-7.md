# Step 7 — Policy engine & preflight

Deny-by-default BaseDN/OU scope, attribute allowlists, protected targets,
risk/approval/dry-run. Owner: policy track. API enforces scope checks
(`require_scopes`) and forwards approval contexts; schema allowlists in
`api/schemas/{users,groups}.py`. Tests: `tests/unit/test_policy.py`.
