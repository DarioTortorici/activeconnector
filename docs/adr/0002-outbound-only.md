# ADR 0002 — Trasporto outbound-only

Stato: Approvata (decisione vincolante, Piano §2.2, §3.1).

## Contesto

Il connettore opera in reti cliente che non possono aprire porte inbound. Il cloud (MWA Trusted Agent → Action Catalog → bus/relay) deve recapitare comandi senza esporre LDAP verso Internet né richiedere connettività inbound al cliente.

## Decisione

- [REQUISITO/FATTO] Nessuna porta inbound richiesta presso il cliente; nessuna esposizione diretta di LDAP verso cloud/Internet.
- [DECISIONE] Worker on-prem con polling/ricezione outbound da bus/relay; envelope validato localmente (versione, timestamp, nonce, tenant/customer/connector, capability, payload).
- [DECISIONE] Trasporto concreto (Service Bus/relay) sostituibile dietro porta `command_transport`; semantica at-least-once con dedup via idempotency key, retry con backoff/jitter, dead-letter e poison-message handling (Step 16). Concreto: `ServiceBusRelay` (Azure Service Bus) è cablato nel worker quando
 `MWA_AD_SERVICEBUS_ENABLED=true`; `InMemoryRelay` resta il default lab/single-host.
- [REQUISITO] L'envelope di comando deve restare interoperabile tra implementazioni del relay (Step 16/20).

## Conseguenze

- Positive: superficie d'attacco ridotta, nessun firewall inbound, disaccoppiamento cloud/on-prem.
- Negative: latenza di polling, necessità di dedup/DLQ, correlazione ticket/operation più complessa.
- Vietato: endpoint `/ldap`, `/query`, `/powershell`, `/commands`, `/shell`; polling generalizzato Entra dall'on-prem.

## Validazione

- Metodo: prototipo worker + security review; test duplicate delivery, crash dopo commit, transport outage (Step 16).
- Exit criterion: zero porte inbound; retry non causa doppia mutazione; core non importa SDK trasporto.
