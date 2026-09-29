# Threat model — MWA AD Connector

## Asset

- Account/gruppi/OU in AD (integrità, disponibilità); credenziali (password/unicodePwd) e token; service account/gMSA; trust store LDAPS e chiavi mTLS/JWT; Operation Store (dedup/stati) e Audit Store (non-ripudio); config per profilo (Base DN, OU, DC, anchor); health/metrics (disponibilità senza leakage).

## Attori

- MWA Trusted Agent + Action Catalog (unico chiamante legittimo remoto); operatori/approvatori HITL; service account AD delegato/gMSA (least privilege); attaccanti: rete (MitM/replay), agente compromesso, insider, malware host, DC malevolo/non disponibile, client che tenta privilege escalation o cross-tenant.

## Trust boundary

Cliente ↔ connettore ↔ foresta/dominio (per dettaglio vedi `trust-boundaries.md`): rete esterna non fidata; host connettore semitfidato; DC fidato solo entro TLS+ACL; cloud fidato solo con JWT/mTLS + tenant/connector binding + anti-replay.

## Abusi e mitigazioni

| Abuso | Mitigazione |
|---|---|
| Ingress verso cliente / esposizione LDAP | Outbound-only (ADR 0002); nessuna porta inbound; no LDAP verso Internet (threat: scansione/bypass) |
| Operazione su target sbagliato (rename/move, DN riusato) | objectGUID stabile + resolve pre-esecuzione + pinning stesso DC + read-after-write; ambiguità terminale (ADR 0003) |
| Furto/riuso credenziali servizio | gMSA o account dedicato least-privilege, deny interattivo, deleghe solo OU gestite; mai Domain Admin/GenericAll; secret in vault, rotazione, mai in log/audit/response (Step 18, §11.4–11.5) |
| Attacco fuori scope (OU non gestita, attributi arbitrari) | Scope Base DN/OU allowlist, attribute/object-class allowlist, protected targets, deny-by-default; doppio controllo policy + ACL AD (ADR 0005) |
| LDAP/PowerShell/shell arbitrari, PATCH generico | Solo capability allowlisted, `extra="forbid"`; vietati `/ldap`, `/query`, `/powershell`, `/commands`, `/shell`; nessun filtro LDAP raw dal cloud |
| Replay/spoofing/tenant-confusion | JWT (issuer/audience) + mTLS dove applicabile, nonce monouso con TTL, timestamp entro skew, binding tenant/connector, scope check, payload/rate limit (Step 8) |
| Doppia mutazione (retry/at-least-once, crash) | Idempotenza `(tenant, connector, key)` atomica, hash canonico, collision detection, state machine atomica (ADR 0006/0008) |
| Falso successo (commit senza verifica, sync presunta) | `FAILED_VERIFICATION` distinto da `FAILED`; evidenze redatte; convergenza Entra solo cloud-side con timeout configurabile, mai hardcoded |
| Manomissione audit / leakage secret | Audit hash-chained/firmato, export redatto e approvato, redaction in log/metrics/tracing/exception/response; secret scan in CI (ADR 0008) |
| Diagnostica che espone interni | Health/readiness pubblici senza DN, hostname, thumbprint completi; readiness fail-closed se operare non è sicuro |

## Esclusioni consapevoli (rischio residuo)

- nTSecurityDescriptor/deleghe generalizzate: modulo post-GA disabilitato di default, con ADR/threat model dedicati (Step 23).
- Multi-forest complesso, HA distribuita, writeback specifici: non supportati finché non validati in lab dedicato.
- Kerberos/gMSA/LDAPS: efficaci solo dopo validazione lab (cert valida/scaduta/non-trusted; bind ripetibile; renewal gMSA).

## Validazione

Review architetto + security; aggiornare il modello a ogni cambio di trust boundary (DoD globale); negative suite §10.1 come regressione permanente.
