# Capability catalog (operating plan §7, condensed)

Common rules for every capability: specific validated input (`extra="forbid"`),
allowlisted capability id, target inside managed Base DN/OU, objectGUID for
mutations on existing objects, DN resolved immediately before execution,
privileged-group/account protection, application control **and** AD ACLs,
same-DC read-after-write, mandatory idempotency key, before/requested/after
audit, no secrets in logs/audit/responses.

## R0/R1 — discovery & read (LOW risk, idempotent)

| Capability | Scope | Notes |
|---|---|---|
| `connector.health.read` | `ad.health.read` | anonymous redacted liveness |
| `connector.readiness.read` | `ad.readiness.read` | 200 ready / 503 fail-closed |
| `directory.rootdse.read` | `ad.discovery.read` | redacted RootDSE per domain |
| `directory.capabilities.read` | `ad.discovery.read` | allowlisted ids per domain |
| `user.resolve` / `group.resolve` | `ad.user.read` / `ad.group.read` | exactly 0/1, else 404/409 |
| `user.get` / `group.get` | `ad.user.read` / `ad.group.read` | allowlisted projection |
| `user.search` / `group.search` | `ad.user.read` / `ad.group.read` | predefined profiles, signed page tokens |
| `group.members.list` | `ad.group.members.read` | paging, unresolved refs flagged |

## MVP — account & membership

| Capability | Scope | Risk | Verify / rollback |
|---|---|---|---|
| `group.member.add` | `ad.group.member.write` | MEDIUM/HIGH, idempotent (present=NO_OP) | same-DC re-read; conditional remove |
| `group.member.remove` | `ad.group.member.write` | HIGH, idempotent (absent=NO_OP) | same-DC re-read; conditional add |
| `account.unlock` | `ad.account.unlock` | MEDIUM, idempotent | unlock state verify; no rollback |
| `account.password.reset` | `ad.account.password.reset` | CRITICAL, per-operation idempotency | indirect safe verify; LDAPS-only; no rollback |
| `account.password.force_change` | `ad.account.password.force_change` | HIGH, state-idempotent | pwdLastSet verify |

## GA — lifecycle (all HITL/approval-gated as marked)

`account.enable`/`account.disable` (`ad.account.state.write`),
`user.create`/`user.attributes.update`/`user.rename`/`user.move`/`user.delete`,
`group.create`/`group.attributes.update`/`group.rename`/`group.move`/`group.delete`,
`ou.create`/`ou.rename`/`ou.move`/`ou.delete` (empty-only, `require_empty=true`).

## Operations & audit

`operation.get` / `operation.list` (`ad.operation.read`, allowlisted filters),
`audit.get` (`ad.audit.read`), `audit.export` (`ad.audit.export`, admin approval).

## Excluded (Step 23)

`nTSecurityDescriptor`, ACE/delegation management, generic ACL writes:
disabled by default, separate threat model + ADR required. No generic
`/ldap`, `/query`, `/powershell`, `/commands`, `/shell`, or PATCH endpoints.
