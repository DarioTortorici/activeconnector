# Trust boundaries — MWA AD Connector

Ogni record, comando e configurazione porta boundary espliciti: `customer_id`, `tenant_id`, `connector_id`, `forest_id`, `domain_id`. Single-customer possibile al bootstrap, ma campi sempre popolati e validati.

| Confine | Dentro | Fuori / non fidato | Regole di attraversamento |
|---|---|---|---|
| Rete cliente ↔ Internet/cloud | Host connettore, DC, bus endpoint outbound | Internet, chiamanti anonimi | Solo outbound; JWT/mTLS, tenant/connector binding, anti-replay, payload/rate limit; nessuna inbound |
| Cloud MWA ↔ worker on-prem | Envelope firmato, ticket/correlation, approval context | Payload LDAP raw, PowerShell, shell, attributi arbitrari | Solo capability allowlisted `/api/v1`, `extra="forbid"`; envelope `1.0` validato; dedup + DLQ |
| Connettore ↔ foresta/dominio AD | Base DN/OU gestite, DC selezionato, service account/gMSA | OU unmanaged, domini/forest non configurati | Scope check prima di LDAP; resolve GUID→DN; pinning stesso DC per commit+verify |
| Processo servizio ↔ secrets/PKI | Vault, machine store, trust chain lab | Log, audit, response, fixture, exception | Redaction totale secret; LDAPS con fail-closed su cert invalido; rotazione documentata |
| Tenant/connector ↔ storage | Operation/Audit Store partizionati per boundary | Cross-tenant read/write | Unicità `(tenant, connector, key)`; `operation.get/list` e `audit.*` filtrati per boundary e ruolo |
| On-prem ↔ Entra | `entra_evidence_hint` redatta verso cloud | Verdetti di convergenza on-prem | Convergenza solo via poller cloud-side con timeout/escalation configurabili |

Cross-domain/cross-forest non supportato in MVP: richiesta che lo implica → rifiuto + stop condition (§17.2). Moduli post-GA (deleghe, multi-forest, HA) richiedono ADR e threat model dedicati e restano disabilitati di default.
