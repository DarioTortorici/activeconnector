# Glossario — MWA AD Connector

| Termine | Definizione |
|---|---|
| AuthorityResolver | Componente cloud-side deterministico che assegna ogni (target, capability, attributo) a Entra, AD on-prem, ibrida, non supportata o HITL. |
| Base DN / Managed OU | Radici e OU allowlisted per profilo; solo target interni sono operabili. |
| Capability | Operazione specifica, versionata e allowlisted (es. `group.member.add`); mai LDAP/PowerShell generici. |
| Command envelope | Messaggio versionato (`1.0`) con capability, boundary, idempotency key, nonce, timestamp, approval context. |
| DC pinning | Commit e read-after-write eseguiti sullo stesso DC per verifica deterministica. |
| DirectoryGateway | Porta astratta che isola la libreria LDAP dal dominio; unico punto di accesso LDAP. |
| Disposition | Esito applicativo: `APPLIED`, `NO_OP`, `REJECTED`, `QUEUED`, `PARTIALLY_OBSERVED`. |
| gMSA | Group Managed Service Account; credenziali gestite/rotate da AD, senza password statica. |
| HITL | Human-in-the-loop: approval obbligatoria per capability rischiose. |
| Idempotency key | Chiave unica per `(tenant, connector, key)`; stessa key + payload diverso = collisione. |
| objectGUID | Identificatore AD immutabile; identità primaria per mutazioni. |
| Read-after-write | Rilettura verificante sullo stesso DC dopo commit; produce `VerificationEvidence`. |
| Source anchor | Attributo di correlazione AD↔Entra; strategia configurabile per profilo, mai assunta globalmente. |
| Staged diff | Diff minimo Add/Delete/Replace con trattamento separato dei multivalore. |
| Stati on-prem/cloud | On-prem: RECEIVED…AD_VERIFIED/FAILED(_VERIFICATION); cloud: WAITING_ENTRA_SYNC…ENTRA_CONVERGED/EXPIRED/ESCALATED. |
| VerificationEvidence | Prova redatta di verifica (tipo, DC, observed/expected, match, hash attributi). |
