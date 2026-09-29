# Step 2 — Domain, errors, ports

Deliverable: FastAPI/LDAP-independent contracts (`domain/*`,
`application/ports/*`, in-memory fakes). Owner: domain track. The API layer
consumes them via seam dependencies (`api/dependencies.py`,
`api/error_handlers.py`) with typed fallbacks; cross-check tests live in
`tests/unit/test_{enums,errors}.py` and `tests/contract/`.
