# Backlog — dopo Step 0

## Decisioni aperte (da validare negli step indicati)

- [ ] Libreria LDAP concreta (Step 3): spike ldap3 vs alternative; matrice primitive; LDAPS/Kerberos/gMSA/paging/ModifyDN/unicodePwd/binari/controlli.
- [ ] LDAPS e cert validation fail-closed (Step 3/5).
- [ ] Kerberos host domain-joined + gMSA runtime (Step 3/18).
- [ ] Source anchor discovery per profilo (Step 4).
- [ ] Trasporto relay concreto e interoperabilità envelope (Step 16/20).
- [ ] Meccanismo audit tamper-evident: hash-chaining vs firma (Step 9).
- [ ] Operation store concreto e retention (Step 9).
- [ ] Container solo se gMSA/Kerberos/LDAPS non compromessi (Step 18).

## Epic 0 residuo (checkpoint umano)

- [ ] Approvazione ADR 0001–0008 da architetto + security.
- [ ] Approvazione provenance/licenza OpenRSAT da legal.
- [ ] Congelamento capability MVP/GA/Post-GA e API vietate.

## Collegamento issue tracker (§15)

Epic 1 (bootstrap/CI) sbloccato dopo approvazione Step 0; Epic 2 (domain/porte) dopo Step 1; Epic 3 (spike) dopo Step 2 + lab minimo. Nessuna implementazione anticipata.
