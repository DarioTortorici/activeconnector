# Authority matrix (Step 20, cloud integration)

The cloud-side AuthorityResolver routes per (target, capability, attribute).
The on-prem connector never decides Entra convergence.

| Authority | Who acts | Connector view |
|---|---|---|
| Entra/MCP | Trusted Agent → MCP Entra | not involved |
| On-prem | Worker → AD, verified same-DC | `AD_VERIFIED` + redacted evidence |
| Hybrid | Worker commits, cloud polls Entra | `WAITING_ENTRA_SYNC` (cloud-side) |
| Unsupported | rejected at catalog | `CAPABILITY_NOT_ALLOWED` |
| HITL | approval first (risky caps) | `APPROVAL_REQUIRED` until approved |

Rules: only the Trusted Agent invokes; Action Catalog owns risk/idempotency/
rollback metadata; the cloud never sends raw LDAP; Entra polling uses
configurable timeouts + escalation (no hardcoded sync times); connector
states map 1:1 into the MWA ticket machine (`AD_VERIFIED` →
`WAITING_ENTRA_SYNC` → `ENTRA_CONVERGED`/`FAILED`/`EXPIRED`/`ESCALATED`).
