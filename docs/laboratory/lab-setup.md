# Lab setup (Step 19)

Isolated lab domain only (e.g. `lab.example.test`). Never production.

## Topology

- 1× Windows Server VM promoted to DC + integrated DNS (snapshot S1).
- 1× domain-joined app host for the connector (Kerberos/gMSA tests).
- Optional: 2nd DC (replication/failure tests), relay/bus test endpoint.

## OU & objects

```text
DC=lab,DC=example,DC=test
├── OU=Managed (Users, Groups, ServiceAccounts, Lifecycle)
└── OU=Unmanaged (Users, Groups)   # negative tests: out-of-scope denials
```

Seed: enabled/disabled/lockable/password-reset/unicode users, an Unmanaged
user, global/universal/domain-local groups, nested groups, a cycle scenario,
a simulated protected group, empty + non-empty OUs, colliding names,
multi-value attributes. Scripts must confirm the lab domain, stay inside lab
OUs, be idempotent, and never touch real privileged groups.

## Service identity

- Phase A: dedicated non-interactive account, no admin memberships, delegations
  only on Managed OUs, secret in vault with rotation.
- Phase B: gMSA authorized on the app host only; repeat bind/restart/renewal.
- Never Domain Admin. Least privilege + defense in depth are exit criteria.

## Minimum delegations (Managed scope)

Attribute reads, `member` write on managed groups, `lockoutTime`,
password reset, `pwdLastSet`, controlled `userAccountControl`, allowlisted
attributes, create/delete per class in authorized OUs, ModifyDN/move where
needed. No GenericAll, no domain control.

## PKI / LDAPS

Lab-only CA, server-auth cert on the DC (check SAN/hostname), trust chain on
the connector host. Test matrix: valid, hostname mismatch, untrusted CA,
expired, revocation (if available). Capture metadata only — no passwords.

## Snapshots

S0 clean OS → S1 DC/DNS → S2 OU seed → S3 LDAPS → S4 delegations → S5 gMSA →
S6 optional Entra Connect. Coordinate multi-DC restores; stop and escalate if
restore is not reproducible.
