# Step 13 — User attribute updates

Allowlisted staged diff (Add/Delete/Replace, multivalue-aware, expected
version). API: `:update-attributes` with `USER_WRITABLE_ATTRIBUTES`
(`api/schemas/users.py`); no generic PATCH exists. Owner: services track
(diff/verify), this track (route + allowlist guard tests).
