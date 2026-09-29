# Step 1 — Bootstrap & CI

Deliverable: executable repo skeleton with blocking quality gates
(`uv sync --frozen`, `ruff format --check`, `ruff check`, `mypy src tests`,
`pytest` + coverage). Owner: bootstrap track. API/transport layers build on
the `create_app` factory (`src/mwa_ad_connector/api/app.py`) and the
`mwa-api`/`mwa-worker` entrypoints.
