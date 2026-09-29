# Step 15 — Controlled user/group/OU CRUD

Create/rename/move/delete with naming preflight, GUID-invariance verify, and
conditional compensations; deletes approval-gated. API: `api/routes/
{accounts,groups,ous}.py` (full §8.3 surface). Owner: services track
(mutations), this track (routes + HTTP contract tests).
