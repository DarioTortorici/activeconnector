# ADR 0005 — Capability API allowlisted e versionate

Stato: Approvata (Piano §7, §8).

## Contesto

Un'API generica (LDAP raw, PowerShell, shell, PATCH attributi arbitrari) permetterebbe all'agente/LLM di eseguire operazioni non autorizzate. MWA richiede Action Catalog con server, rischio, idempotenza e rollback imposti dal catalogo, non dall'LLM.

## Decisione

- [DECISIONE] Solo capability specifiche, versionate, allowlisted (`connector.health.read`, `user.resolve/get/search`, `group.*`, `account.unlock/enable/disable`, `password.reset/force_change`, `user/group/ou` lifecycle, `operation.*`, `audit.*`). Catalogo MVP/GA/Post-GA per Piano §7.
- [DECISIONE] Base path `/api/v1`, envelope `schema_version: "1.0"`; breaking change = nuova major; campi sconosciuti rifiutati (`extra="forbid"`, nessun parametro extra).
- [DECISIONE] Regole comuni: scope OAuth/app per capability, target in Base DN/OU gestita, objectGUID per mutazioni, DN risolto pre-esecuzione, protezione privileged, doppio controllo (policy applicativa + ACL AD), read-after-write stesso DC, idempotency key obbligatoria, audit before/after, nessun secret in log/audit/response.
- [REQUISITO/FATTO] Vietati: `/ldap`, `/query`, `/powershell`, `/commands`, `/shell`, `PATCH /objects/{id}` generico, query LDAP dal cloud, PowerShell remoto, shell execution, GUI, ACL generalizzate in MVP.

## Conseguenze

- Positive: deny-by-default, decisioni spiegabili/auditabili, HITL per capability rischiose.
- Negative: ogni nuovo attributo/operazione richiede estensione catalogo + ADR + test; meno flessibilità ad hoc.

## Validazione

- Metodo: policy engine test (fuori OU, gruppo privilegiato, capability ignota, approval mancante, dry-run — Step 7); security suite (Step 8).
- Exit criterion: deny-by-default dimostrato; nessun endpoint generico esistente.
