# Step 4 — Secure config & profiles

Fail-fast customer/tenant/connector/forest/domain boundaries, Base DN + OU
allowlist, trust store, source-anchor strategy. Owner: config track. The API
reads the effective subset via `RuntimeConfig` (`api/dependencies.py`);
template: `packaging/config-templates/connector.example.json`.
