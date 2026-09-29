# Step 8 — AuthN/AuthZ & anti-replay

JWT (allowlisted iss/aud) + tenant/connector binding + scope checks in
`api/dependencies.py:require_caller/require_scopes`; nonce/timestamp headers
validated, replay store at envelope layer. Middleware: payload limit (413),
token-bucket rate limit (429), security headers, correlation propagation.
Negatives: `tests/security/test_negative.py`.
