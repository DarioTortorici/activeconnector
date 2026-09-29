# ADR 0008 — Operation store, idempotenza e audit tamper-evident

Stato: Approvata come direzione; meccanismo tamper-evident da validare (Piano §2.2, §6.9, Step 9).

## Contesto

Delivery at-least-once, retry e crash richiedono dedup atomica e storicizzazione verificabile. Log incompleti o manomissibili violano requisiti MWA (audit completo, immutabile, esportabile) e impediscono incident response.

## Decisione

- [DECISIONE] `OperationRecord` con unicità `(tenant_id, connector_id, idempotency_key)`; hash canonico richiesta; stessa key + payload diverso = `IDEMPOTENCY_COLLISION` (409); nessuna retrocessione da stato terminale; prenotazione atomica prima dell'esecuzione.
- [DECISIONE] Audit before/requested/after (prima mutazione, dopo commit, dopo verifica); hash-chaining o firma (meccanismo [DA VALIDARE] con test di manomissione); export firmato/redatto e limitato; accesso in lettura auditato.
- [DECISIONE] Redazione obbligatoria: mai password, unicodePwd, token Kerberos, secret in record/log/audit/response/exception/tracing; error contract tipizzato (codice/categoria/retryable/remediation), testo LDAP libero solo in log protetti.
- [DECISIONE] Retention e migrazioni versionate; recovery dimostrabile (store unavailable/audit append failure = stop, mai skip silenzioso).

## Conseguenze

- Positive: una sola esecuzione per key; alterazioni rilevabili; compliance.
- Negative: overhead storage/firma; export richiede approval amministrativa.

## Validazione

- Metodo: fault test (collisione key, crash tra stati, concurrent claims, audit tampering, redaction scan, migration test — Step 9).
- Exit criterion: dedup + recovery dimostrati; secret-leakage scan verde.
