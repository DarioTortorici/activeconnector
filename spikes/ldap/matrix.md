# LDAP Primitive Support Matrix (Step 3 evidence log)

Record one row per primitive after running the spike scripts against the lab DC.
Status values: `supported` | `not-supported` | `uncertain`. Never declare support
without reproducible evidence.

| Primitive | Status | Evidence (date, DC, script, result) | Notes |
|---|---|---|---|
| LDAPS bind (valid CA) | uncertain | — | run `test_bind.py` |
| LDAPS cert expired rejected (fail-closed) | uncertain | — | negative test required |
| LDAPS cert untrusted rejected (fail-closed) | uncertain | — | negative test required |
| Simple bind under TLS | uncertain | — | |
| Kerberos bind (domain-joined) | uncertain | — | needs kinit + SASL_GSSAPI host |
| gMSA bind (no static secret) | uncertain | — | service must run as gMSA |
| RootDSE read | uncertain | — | `get_rootdse` on pinned DC |
| Capabilities compare | uncertain | — | paging + LDAPS + functional level |
| Paged search (no loss/dup) | uncertain | — | run `test_paging.py` over >page-size dataset |
| objectGUID binary read + LE→UUID | uncertain | — | verify against known GUID |
| SID binary → string | uncertain | — | verify against known SID |
| userAccountControl → enabled/locked | uncertain | — | |
| pwdLastSet FILETIME | uncertain | — | 0 / max = never |
| memberOf / member range retrieval | uncertain | — | large groups need range option |
| Add (user/group/OU) | uncertain | — | non-goal for Step 5 read-only |
| Modify (staged Add/Delete/Replace) | uncertain | — | Steps 10–14 |
| Delete (incl. require_empty OU) | uncertain | — | Steps 14–15 |
| ModifyDN rename intra-domain | uncertain | — | GUID invariant + new DN verified |
| ModifyDN move intra-domain | uncertain | — | GUID invariant + new DN verified |
| unicodePwd reset (LDAPS only) | uncertain | — | Step 12; secret never logged |
| lockoutTime=0 unlock | uncertain | — | Step 11 |
| Controls: paged (1.2.840.113556.1.4.319) | uncertain | — | required |
| Controls: SD flags (1.2.840.113556.1.4.801) | not-supported | — | forbidden in MVP (Step 7.6) |
| Controls: DirSync (1.2.840.113556.1.4.841) | not-supported | — | not required |
| Timeout / cancel behavior | uncertain | — | connect + operation timeouts |
| DC pinning commit+verify same DC | uncertain | — | evidence must report same DC |
