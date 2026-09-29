# Step 0 — ADR iniziali, threat model, provenance e contratti

Obiettivo: congelare boundary, rischi e decisioni prima del codice (branch `docs/step-0-foundation`).

## Attività svolte

- Documentati asset, attori, trust boundary e abusi (`architecture/threat-model.md`, `trust-boundaries.md`).
- Registrato OpenRSAT come reference comportamentale, non sorgente da tradurre (`provenance/openrsat-review.md`).
- Definite capability MVP/GA/Post-GA (ADR 0005), stati e responsabilità cloud/on-prem (ADR 0006), identity via objectGUID (ADR 0003), source anchor configurabile (ADR 0004), outbound-only (ADR 0002), esagonale (ADR 0001), libreria da validare (ADR 0007), storage/audit (ADR 0008).
- Registrato glossario e backlog decisioni aperte.

## Deliverable

Baseline documentale: `docs/adr/0001–0008`, `docs/architecture/{overview,threat-model,trust-boundaries}.md`, `docs/provenance/openrsat-review.md`, `docs/{glossary,backlog}.md`, questo file.

## Test / quality gate

- Markdown links e lint documentale; secret scan (nessun secret/dato cliente nei doc).
- Review threat model da architetto + security.

## Accettazione

ADR approvati; nessuna decisione critica implicita; licenza/provenance approvata da legal.

## Non fatto (vietato in Step 0)

Bootstrap applicativo, selezione non provata della libreria LDAP, endpoint o adapter.

## Checkpoint umano

Approvazione architetto, security e legal/provenance prima dello Step 1.
