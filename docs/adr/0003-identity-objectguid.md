# ADR 0003 — Identità stabile via objectGUID

Stato: Approvata (Piano §2.2, §6.2).

## Contesto

Il DN cambia con rename/move; usarlo come identità primaria causa TOCTOU, ambiguità e operazioni sul target sbagliato. AD fornisce `objectGUID` immutabile, adatto come chiave stabile.

## Decisione

- [REQUISITO/FATTO] `objectGUID` è l'identificatore stabile; obbligatorio per mutazioni su oggetti esistenti.
- [DECISIONE] Risoluzione GUID → DN immediatamente prima dell'esecuzione; `expected_dn` solo safeguard, mai identità primaria.
- [DECISIONE] Identificatori alternativi (UPN, sAMAccountName, mail, DN, group name) solo allowlisted, normalizzati, con escaping LDAP; query profile predefiniti, mai filtri LDAP raw dal chiamante.
- [DECISIONE] Ambiguità (0→NOT_FOUND, >1→AMBIGUOUS_TARGET) è errore terminale, mai euristica first-match. Cambio DN tra resolve ed execute → stop/rifiuto sicuro (stop condition §17.2).
- [DA VALIDARE] Precedenza esatta dei resolver e policy di rename concorrente (Step 6, test injection/Unicode/rename-tra-resolve).

## Conseguenze

- Positive: rename/move sicuri, verifica read-after-write affidabile, DC pinning coerente per GUID.
- Negative: lookup aggiuntivo per ogni mutazione; chiamanti devono fornire/corredare il GUID.
- Invarianti `ObjectReference`: `object_guid` oppure coppia identificatore/valore; `domain_id`/`forest_id` obbligatori.

## Validazione

- Metodo: test E2E rename/move (GUID invariato, nuovo DN verificato); test zero/uno/molti; LDAP injection suite.
- Exit criterion: nessun input diventa filtro raw; ambiguità sempre rifiutata.
