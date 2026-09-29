# Step 6 — Identity resolution

GUID-first resolution, allowlisted identifiers, LDAP escaping, no-heuristic
ambiguity (409). Owner: services track. API resolve endpoints
(`POST /users:resolve`, `/groups:resolve`) delegate through the operation
service; injection negatives in `tests/security/test_negative.py`.
