# Step 11 — Unlock

Controlled `lockoutTime` mutation with verify; already-unlocked = NO_OP.
API: `POST /users/{guid}:unlock`. Owner: services track (mutation), this
track (route + tests).
