# ADR 0006 — State machine operativa cloud/on-prem

Stato: Approvata (Piano §3.3–§3.5).

## Contesto

Commit AD e convergenza Entra sono eventi distinti e asincroni (via Entra Connect/Cloud Sync). Confonderli causa falsi successi; serve distinguere verifica AD locale da convergenza cloud, con responsabilità esplicite e semantica HTTP coerente.

## Decisione

- [DECISIONE] Stati on-prem: `RECEIVED → AUTHORIZED → EXECUTING → AD_COMMITTED → AD_VERIFIED`, oppure `FAILED` / `FAILED_VERIFICATION`. Stati cloud: `WAITING_ENTRA_SYNC → ENTRA_CONVERGED | FAILED | EXPIRED | ESCALATED`.
- [DECISIONE] Transizioni atomiche; audit prima della mutazione, dopo commit e dopo verifica; timeout/escalation parte dei requisiti MWA.
- [DECISIONE] Commit + verifica fallita = `FAILED_VERIFICATION` (502 `AD_COMMITTED_VERIFICATION_FAILED`), mai semplice errore pre-commit; includere evidenze redatte.
- [DECISIONE] Semantica HTTP: 200 verificata con corpo, 204 verificata senza corpo, 202 solo se realmente accodato (con `operation_id` + status URL), 4xx richiesta/policy, 5xx dipendenza LDAP/storage.

## Conseguenze

- Positive: cloud monitora convergenza separatamente; diagnosi precisa di commit vs verifica vs sync.
- Negative: client devono gestire polling `operation.get` e stati cloud; nessun successo sincrono presunto.

## Validazione

- Metodo: test state machine, crash-tra-stati, commit-poi-verifica-fallita, mapping stati connettore↔MWA (Step 9/10/20).
- Exit criterion: nessuna regressione terminale; dedup e recovery dimostrati.
