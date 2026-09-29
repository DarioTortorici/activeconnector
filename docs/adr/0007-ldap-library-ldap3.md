# ADR 0007 — Libreria LDAP: candidatura ldap3 da validare

Stato: Da validare (spike obbligatorio, Piano §2.2, Step 3). Nessun supporto dichiarato senza evidenza.

## Contesto

`pyproject.toml` candida `ldap3>=2.9.1`, ma la scelta concreta dipende dallo spike su DC reale (LDAPS, bind, paging, ModifyDN, unicodePwd, binari, controlli AD, timeout/cancel). Dichiarare supporto su sola documentazione è vietato.

## Decisione

- [DA VALIDARE] `ldap3` come adapter di `DirectoryGateway` solo se lo spike dimostra tutte le primitive MVP; in caso contrario stop condition e rivalutazione.
- [DECISIONE] Spike isolato in `spikes/ldap/` (fuori dal package produttivo): LDAPS + cert validation (valida/scaduta/non-trusted), simple bind sotto TLS, Kerberos da host domain-joined, gMSA se disponibile, paged search oltre page size, Add/Modify/Delete/ModifyDN, unicodePwd su canale protetto, attributi binari (objectGUID/SID lossless), controlli AD (matrice OID/comportamento/fallback), timeout/cancel, DC pinning per mutazione/verifica.
- [DECISIONE] Nessuna chiamata blocking diretta in codice async: adapter/thread strategy esplicita se la libreria è sincrona.

## Conseguenze

- Positive: scelta basata su evidenze riproducibili; gap/workaround approvati prima del codice produttivo.
- Negative: Step 5+ bloccati finché lo spike non è approvato da security + AD engineer.

## Validazione

- Metodo: prove positive/negative su DC lab, packet/log review senza secret; report firmato con matrice supportato/non-supportato/incerto.
- Exit criterion: adapter scelto o stop; error mapping preliminare (result code + subcode AD + fase resolve/preflight/commit/verify).
