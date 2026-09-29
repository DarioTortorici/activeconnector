# Provenance review — OpenRSAT

## Natura del progetto

[REQUISITO/FATTO] OpenRSAT è un client desktop LDAP scritto in Object Pascal/Lazarus, non un server API. Rilevanti solo comportamenti osservabili di core/trasporto LDAP; GUI esclusa.

## Uso consentito (reference comportamentale)

[DECISIONE] OpenRSAT è esclusivamente reference comportamentale per: Search, Add, Modify, Delete, ModifyDN, paging, reset password (unicodePwd su canale protetto), unlock (lockoutTime), userAccountControl, pwdLastSet, error mapping, read-after-write, staged diff Add/Delete/Replace con multivalore separati.

## Divieti

- Vietati copia, fork, porting/traduzione meccanica, dipendenze da Lazarus/Object Pascal, GUI desktop nel prodotto.
- Nessun riuso di snippet/algoritmi senza provenienza documentabile e approvazione legal; licenza e compatibilità da registrare prima di qualsiasi riuso (checkpoint Step 0: architetto + security + legal).

## Matrice comportamenti → capability

| Comportamento osservato | Riuso nel connettore |
|---|---|
| Paged search con cookie | `user/group.search`, `members.list` con page token firmato |
| unicodePwd su canale protetto | `account.password.reset` solo LDAPS, password mai loggata |
| lockoutTime / UAC / pwdLastSet | `account.unlock`, `enable/disable`, `force_change` con verifica |
| ModifyDN intra-dominio | `rename`/`move` con GUID invariato e DN verificato |
| Staged diff minimo | `*.attributes.update` con comparatori dedicati |
| Error mapping + read-after-write | Error taxonomy stabile (§8.7–8.8) + `VerificationEvidence` stesso DC |

## Stato licenza

[DA VALIDARE] Licenza OpenRSAT e compatibilità MIT da confermare con legal prima di qualsiasi derivazione; fino ad approvazione: osservazione comportamentale soltanto.
