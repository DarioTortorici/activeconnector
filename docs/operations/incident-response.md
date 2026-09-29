# Incident response (Step 21)

Severity follows impact on identity writes; verification failures outrank
pre-commit errors (a commit may already have happened).

## FAILED_VERIFICATION (502)

1. Fetch `GET /api/v1/operations/{id}` — redacted evidence shows what the
   same-DC re-read observed.
2. Compare against the change ticket; do NOT blindly retry the mutation
   (it may already be applied — retry risks a duplicate side effect).
3. If AD state is correct, close as verify-gap and file a bug; if AD state
   is wrong, run the documented compensation for that capability, then
   re-verify manually before closing.

## Suspected secret leakage

1. Quarantine the artifact (log file, export, ticket attachment).
2. Rotate the exposed credential out-of-band; search audit for its use.
3. Root-cause the emitter (logging, evidence, error detail) and add a
   regression test scanning for the canary before re-enabling.

## DC / transport outage

- `LDAP_UNAVAILABLE`/`LDAP_TIMEOUT` are retryable: the worker backs off with
  jitter under a retry budget; no operator action until the budget exhausts
  and the DLQ grows.
- Transport outage: messages stay queued at the relay (at-least-once);
  on recovery the worker dedups by idempotency key — no double mutation.

## Privileged-target attempt

`PROTECTED_TARGET` denials are expected control behavior. Repeated attempts
from one caller = escalate to security (possible confused/malicious client).

## Contacts

Owner: Identity Platform on-call. Escalation: Security IR, then CAB for
customer-impacting rollbacks. All actions reference ticket + correlation ids.
