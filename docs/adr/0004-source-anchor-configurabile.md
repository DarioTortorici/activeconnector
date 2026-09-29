# ADR 0004 — Source anchor configurabile

Stato: Aperta / da scoprire per profilo (Piano §2.2, §17.2).

## Contesto

La correlazione AD ↔ Entra dipende dalla source anchor del tenant (spesso `ms-DS-ConsistencyGuid` o `objectGUID`, ma non universalmente `base64(objectGUID)` come `onPremisesImmutableId`). Assumerla globalmente causerebbe mismatch di convergenza e routing errato.

## Decisione

- [REQUISITO/FATTO] Vietata l'assunzione universale `onPremisesImmutableId == base64(objectGUID)`.
- [DECISIONE] Source anchor strategy esplicita per profilo cliente/tenant/foresta/dominio in `config/profiles.py`; nessun hardcoding di tenant, domini, OU, DC o anchor.
- [DECISIONE] Verifica di convergenza Entra solo cloud-side (poller configurabile, timeout/escalation); l'on-prem restituisce solo `entra_evidence_hint`, mai verdetti Entra.
- [DA VALIDARE] Strategia di discovery per profilo (Step 4); tempi di sync Entra non hardcodificabili, solo config cloud + timeout test.

## Conseguenze

- Positive: nessun cross-tenant leakage, convergenza monitorata correttamente per profilo.
- Negative: onboarding richiede discovery documentata per ogni tenant; stop condition se anchor ignota o in conflitto.

## Validazione

- Metodo: config cliente + discovery documentata (Step 4); poller cloud test con timeout/escalation (Step 20).
- Exit criterion: strategia esplicita per profilo; zero assunzioni globali nel codice.
