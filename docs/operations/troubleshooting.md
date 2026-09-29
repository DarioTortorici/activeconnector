# Troubleshooting (Step 21)

| Symptom | Likely cause | Action |
|---|---|---|
| `401 AUTHENTICATION_FAILED` | expired/wrong-aud token, stale timestamp | renew token, check clock skew |
| `403 TENANT_BINDING_MISMATCH` | header vs token vs local connector drift | align X-Tenant-ID/X-Connector-ID |
| `403 CALLER_FORBIDDEN` | missing scope | grant scope, never bypass |
| `403 PROTECTED_TARGET` | privileged/protected object | use exception workflow, not force |
| `409 IDEMPOTENCY_COLLISION` | key reused, payload changed | new key or original payload |
| `409 CONCURRENT_MODIFICATION` | stale `expected_version` | re-read, retry with fresh token |
| `502 FAILED_VERIFICATION` | commit ok, verify failed | incident-response path, no blind retry |
| `503 LDAP_UNAVAILABLE` | DC down / network | check DC, LDAPS cert, firewall 636 |
| `503 LDAPS_CERTIFICATE_INVALID` | expired/untrusted/host-mismatch cert | renew/fix chain; never downgrade |
| `429 RATE_LIMITED` | burst over budget | back off per Retry-After |
| `413 PAYLOAD_TOO_LARGE` | body > 1 MiB | paging/projection, shrink payload |
| Readiness 503 `ldap_connectivity` | gateway down | DC/LDAPS checks above |
| Readiness 503 stores/transport | store/relay unwired or corrupt | logs + backup-restore |
| DLQ growing | poison/malformed/binding failures | inspect `reason`, fix producer |
| Worker silent, queue growing | crash loop on receive | logs `worker loop fault`, relay creds |

Clock skew: keep the host on NTP; JWT leeway and request skew windows are
bounded and fail closed — widening them needs a security ADR.
