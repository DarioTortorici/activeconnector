# API reference (Step 17)

Base path `/api/v1`, envelope `schema_version: "1.0"`. Interactive schema:
`GET /api/v1/docs` (Swagger), machine schema: `GET /api/v1/openapi.json`.

## Conventions

- Auth: `Authorization: Bearer <JWT>` (allowlisted iss/aud), `X-Tenant-ID`
  and `X-Connector-ID` must match token/local binding on every call.
- Mutations additionally require `Idempotency-Key`, `X-Ticket-ID`,
  and (when sent) a fresh `X-Request-Timestamp`/`X-Request-Nonce`.
- Correlation: send `X-Correlation-ID`; it is echoed on every response.
- HTTP semantics: `200` verified sync result, `202` really queued
  (`operation_id` + `status_url`), `4xx` caller/policy, `5xx` classified
  dependency/internal. Commit-then-verify-failure is `502`
  `FAILED_VERIFICATION` with redacted evidence.
- Errors use the stable `ErrorResponse` envelope (`code/category/retryable/
  remediation`); raw LDAP text never crosses the API boundary.
- Search paging uses HMAC-signed opaque `page_token`s (tampering = 400).

## Endpoints

```text
GET  /api/v1/health
GET  /api/v1/readiness
GET  /api/v1/domains/{domain_id}/rootdse
GET  /api/v1/domains/{domain_id}/capabilities
POST /api/v1/users:resolve
POST /api/v1/groups:resolve
GET  /api/v1/users/{object_guid}
GET  /api/v1/groups/{object_guid}
POST /api/v1/users:search
POST /api/v1/groups:search
GET  /api/v1/groups/{object_guid}/members

POST /api/v1/groups/{group_guid}/members:add
POST /api/v1/groups/{group_guid}/members:remove
POST /api/v1/users/{user_guid}:unlock
POST /api/v1/users/{user_guid}:reset-password
POST /api/v1/users/{user_guid}:force-password-change
POST /api/v1/users/{user_guid}:enable
POST /api/v1/users/{user_guid}:disable
POST /api/v1/users/{user_guid}:update-attributes
POST /api/v1/users/{user_guid}:rename
POST /api/v1/users/{user_guid}:move
POST /api/v1/users
DELETE /api/v1/users/{user_guid}

POST /api/v1/groups
POST /api/v1/groups/{group_guid}:update-attributes
POST /api/v1/groups/{group_guid}:rename
POST /api/v1/groups/{group_guid}:move
DELETE /api/v1/groups/{group_guid}

POST /api/v1/ous
POST /api/v1/ous/{ou_guid}:rename
POST /api/v1/ous/{ou_guid}:move
DELETE /api/v1/ous/{ou_guid}

GET /api/v1/operations/{operation_id}
POST /api/v1/operations:search
GET /api/v1/audit/{audit_id}
POST /api/v1/audit:export
```

There is no `/ldap`, `/query`, `/powershell`, `/commands`, `/shell`, or
generic `PATCH /objects/{id}` — by design.
