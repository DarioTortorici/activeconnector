# ADR 0001 — Architettura esagonale / layered

Stato: Approvata (Step 0 baseline). Da riconfermare via import-boundary test allo Step 2.

## Contesto

Il connettore AD on-premises deve isolare la logica di dominio da FastAPI, storage e libreria LDAP, per permettere contract test con fake, sostituibilità del trasporto e verifica indipendente di policy, audit e idempotenza. [REQUISITO/FATTO] Il piano prescrive Python 3.11+, src layout, separazione domain/services/API/infrastructure, uv, Ruff 120, mypy strict, pytest (Piano §2.1, §5).

## Decisione

- [DECISIONE] Adottare architettura esagonale/layered: `domain` → `application` → `policy` → `api` / `infrastructure` / `security` / `operations` / `config` / `entrypoints` secondo struttura §5.
- [DECISIONE] La libreria LDAP non è parte del dominio: è incapsulata in un adapter di `DirectoryGateway` (porta astratta in `application/ports`).
- [DECISIONE] Il trasporto bus/relay è dietro porta `command_transport`; il core non importa SDK di trasporto.
- [DECISIONE] File idealmente ≤400 righe, no god files; API pubbliche con docstring Google Style, type hint completi, mypy strict.

## Conseguenze

- Positive: testabilità (fake in-memory), sostituibilità LDAP/trasporto/storage, enforcement policy indipendente da AD.
- Negative: più boilerplate (porte, adapter, mapper); richiede import-boundary test per impedire dipendenze inverse.
- Vincoli: `domain` e `application` non devono importare FastAPI, `ldap3` né SDK di trasporto. Violazione = CI rossa.

## Validazione

- Metodo: import-boundary test (Step 2); `ruff`, `mypy strict`, CI bloccante.
- Exit criterion: suite domain/contract verde; nessun import vietato; package avviabile con OpenAPI valido (Step 1).
