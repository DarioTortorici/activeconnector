# Step 12 — Password reset & force-change

`SecretStr` transport, LDAPS-only enforcement, no secret in logs/audit/
response/evidence; leakage scan in `tests/security/test_negative.py::test_password_leakage_scan`.
API: `:reset-password`, `:force-password-change`. Owner: services track
(mutation), this track (secret-safe schemas + tests).
