# Setup Active Directory — guida operativa

Guida per collegare il connettore a un dominio Active Directory reale (lab o
produzione) e verificarne il funzionamento. Il dominio di laboratorio è
descritto in [`docs/laboratory/lab-setup.md`](../laboratory/lab-setup.md).
Per il laboratorio `corp.test.local` già configurato e i comandi di test
pronti all'uso: [`lab-corp-test-local.md`](lab-corp-test-local.md).

> Il connettore è **outbound-only**: apre solo connessioni LDAPS verso il DC
> configurato, non espone endpoint LDAP/PowerShell/shell e non accetta filtri
> LDAP grezzi. Il testo LDAP non viene mai restituito ai chiamanti.

## 1. Prerequisiti

- Python 3.11+ e `uv` installati sull'host del connettore.
- DC raggiungibile sulla porta 636 (LDAPS) con certificato server valido.
- CA emittente esportata in un file PEM leggibile dal processo.
- Service account con le deleghe minime descritte in
  `docs/laboratory/lab-setup.md` (mai Domain Admin).
- Una directory di stato scrivibile (SQLite: operazioni e audit).

## 2. Variabili d'ambiente `MWA_AD_*`

Le impostazioni sono caricate fail-fast all'avvio: se manca un campo
obbligatorio o è incoerente, il processo non parte.

| Variabile | Obbligatoria | Descrizione | Esempio |
|---|---|---|---|
| `MWA_AD_CUSTOMER_ID` | sì | Boundary cliente | `customer-lab` |
| `MWA_AD_TENANT_ID` | sì | Boundary tenant | `tenant-lab` |
| `MWA_AD_CONNECTOR_ID` | sì | Identità del connettore | `connector-lab-01` |
| `MWA_AD_FOREST_ID` | sì | Boundary foresta | `forest-lab` |
| `MWA_AD_DOMAIN_ID` | sì | Boundary dominio | `domain-lab` |
| `MWA_AD_BASE_DN` | sì | Radice ricerca/mutazioni | `DC=lab,DC=example,DC=test` |
| `MWA_AD_MANAGED_OUS` | sì | JSON array di OU gestite (sotto `base_dn`) | `["OU=Managed,DC=lab,DC=example,DC=test"]` |
| `MWA_AD_DC_HOST` | sì | Hostname/IP del DC preferito | `dc01.lab.example.test` |
| `MWA_AD_DC_PORT` | no | Porta LDAPS (default `636`) | `636` |
| `MWA_AD_USE_LDAPS` | no | Deve restare `true`: LDAP in chiaro è rifiutato | `true` |
| `MWA_AD_LDAPS_REQUIRE_CERT` | no | Validazione certificato fail-closed | `true` |
| `MWA_AD_TRUST_STORE_PATH` | sì con validazione | PEM della CA | `C:\ProgramData\MWA\tls\lab-ca.pem` |
| `MWA_AD_AUTH_MODE` | no | `simple`, `kerberos`, `gmsa` (default `gmsa`) | `simple` |
| `MWA_AD_BIND_USER` | con `simple` | UPN/DN dell'account di servizio | `svc-mwa@lab.example.test` |
| `MWA_AD_BIND_PASSWORD` | con `simple` | Segreto dell'account (mai loggato) | `REPLACE-WITH-LAB-SECRET` |
| `MWA_AD_SOURCE_ANCHOR_STRATEGY` | no | `objectGuid`, `msDsConsistencyGuid`, `objectSid`, `custom` | `objectGuid` |
| `MWA_AD_ENABLE_MUTATIONS` | no | Kill switch globale scritture | `true` |
| `MWA_AD_ENABLE_PASSWORD_RESET` | no | Kill switch reset password | `false` |
| `MWA_AD_VALIDATION_MODE_ONLY` | no | Forza dry-run su tutte le mutazioni | `true` |
| `MWA_AD_LOG_LEVEL` | no | Livello log | `INFO` |
| `MWA_AD_REQUEST_MAX_BYTES` | no | Limite payload (1024..1048576) | `1048576` |
| `MWA_AD_CLOCK_SKEW_SECONDS` | no | Skew tollerato (30..3600) | `60` |
| `MWA_AD_NONCE_TTL_SECONDS` | no | TTL riserva nonce (60..86400) | `300` |
| `MWA_AD_JWT_SECRET` | sì | Chiave HMAC token chiamanti (≥32 byte consigliati) | `REPLACE-WITH-LAB-JWT-SECRET` |
| `MWA_AD_JWT_ISSUER` | no | Issuer atteso (default `mwa-trusted-agent`) | `mwa-trusted-agent` |
| `MWA_AD_JWT_AUDIENCE` | no | Audience attesa (default `mwa-ad-connector`) | `mwa-ad-connector` |
| `MWA_AD_JWT_ALGORITHMS` | no | Algoritmi ammessi (JSON array) | `["HS256"]` |
| `MWA_AD_PAGE_TOKEN_SECRET` | sì | Chiave HMAC dei page token | `REPLACE-WITH-LAB-PAGE-TOKEN-SECRET` |
| `MWA_AD_API_HOST` | no | Bind API (default `127.0.0.1`) | `127.0.0.1` |
| `MWA_AD_API_PORT` | no | Porta API (default `8443`) | `8443` |
| `MWA_AD_RATE_LIMIT_CAPACITY` | no | Capacità burst token bucket | `100` |
| `MWA_AD_RATE_LIMIT_PER_SECOND` | no | Refill token bucket | `10.0` |
| `MWA_AD_STATE_DIR` | no | Directory SQLite stato/audit (default `.mwa-state`) | `C:\ProgramData\MWA\state` |
| `MWA_AD_LDAP_CONNECT_TIMEOUT_SECONDS` | no | Timeout connessione LDAPS | `10.0` |
| `MWA_AD_LDAP_OPERATION_TIMEOUT_SECONDS` | no | Timeout per operazione LDAPS | `30.0` |
| `MWA_AD_LDAP_POOL_SIZE` | no | Connessioni LDAPS concorrenti | `10` |

Template completo: `packaging/config-templates/connector.example.json` (valori
finti di laboratorio, mai segreti reali nel repository).

Generazione automatica dei valori: esegui su un host domain-joined

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\discover_ad_env.ps1 `
    -ExportCaTo C:\ProgramData\MWA\tls\domain-ca.pem -OutputPath .\mwa-ad-env.ps1 -Pause
```

Se la finestra si chiude subito usa `-Pause` (attende Invio) oppure avvia con
`powershell -NoExit -ExecutionPolicy Bypass -File ...`; con `-OutputPath` il
blocco viene salvato su file e rileggibile con `Get-Content .\mwa-ad-env.ps1`.

Lo script e' **read-only** (non modifica AD): rileva dominio, Base DN, DC
preferito, porta 636, certificato LDAPS (subject/SAN/scadenza), catena di trust
ed esporta la CA in PEM; elenca le OU sotto il Base DN e suggerisce la OU gestita
(`-ManagedOuHint`, default `Managed`); genera nuovi `JWT_SECRET` e
`PAGE_TOKEN_SECRET`; stampa (e opzionalmente salva con `-OutputPath`) il blocco
`$env:MWA_AD_*` pronto da incollare sull'host connettore.

Esempio PowerShell:

```powershell
$env:MWA_AD_CUSTOMER_ID = "customer-lab"
$env:MWA_AD_TENANT_ID = "tenant-lab"
$env:MWA_AD_CONNECTOR_ID = "connector-lab-01"
$env:MWA_AD_FOREST_ID = "forest-lab"
$env:MWA_AD_DOMAIN_ID = "domain-lab"
$env:MWA_AD_BASE_DN = "DC=lab,DC=example,DC=test"
$env:MWA_AD_MANAGED_OUS = '["OU=Managed,DC=lab,DC=example,DC=test"]'
$env:MWA_AD_DC_HOST = "dc01.lab.example.test"
$env:MWA_AD_TRUST_STORE_PATH = "C:\ProgramData\MWA\tls\lab-ca.pem"
$env:MWA_AD_AUTH_MODE = "simple"
$env:MWA_AD_BIND_USER = "svc-mwa@lab.example.test"
$env:MWA_AD_BIND_PASSWORD = "<da vault>"
$env:MWA_AD_JWT_SECRET = "<da vault>"
$env:MWA_AD_PAGE_TOKEN_SECRET = "<da vault>"
$env:MWA_AD_STATE_DIR = "C:\ProgramData\MWA\state"
```

Note operative:

- In questa build l'unica modalità di bind cablata è `MWA_AD_AUTH_MODE=simple`
  con `bind_user`/`bind_password` su LDAPS; Kerberos/gMSA sono documentati ma
  non ancora attivi nell'adapter (il bind fallisce con errore esplicito).
- `MWA_AD_VALIDATION_MODE_ONLY` è `true` di default: tutte le mutazioni sono
  forzate a dry-run. Per eseguire scritture reali impostarlo a `false` solo
  dopo aver verificato gli smoke test read-only.
- `MWA_AD_JWT_SECRET` e `MWA_AD_PAGE_TOKEN_SECRET`: usare almeno 32 byte
  casuali (HS256); non riutilizzare segreti di altri ambienti.
- L'API locale ascolta in HTTP su `127.0.0.1` (TLS/mTLS da terminare a monte);
  il traffico LDAP verso AD è sempre LDAPS.

## 3. Trust store e LDAPS

1. Esportare la CA del dominio in PEM (Base64) sul DC:
   `certutil -ca.cert C:\temp\lab-ca.pem`.
2. Copiare il PEM sull'host del connettore e verificarne la leggibilità:
   `Get-Content $env:MWA_AD_TRUST_STORE_PATH | Select-Object -First 1`
   deve iniziare con `-----BEGIN CERTIFICATE-----`.
3. Lasciare `MWA_AD_LDAPS_REQUIRE_CERT=true`: un certificato non attendibile,
   scaduto o con hostname non corrispondente blocca la connessione
   (`LDAPS_CERTIFICATE_INVALID`). **Non** disattivare la validazione e non
   declassare a LDAP in chiaro: la porta 389 è rifiutata per design.
4. Il reset password (`account.password.reset`) richiede **obbligatoriamente**
   LDAPS e il kill switch `MWA_AD_ENABLE_PASSWORD_RESET=true`: su canale non
   cifrato la scrittura viene rifiutata prima di toccare AD.

## 4. Validazione della configurazione

```powershell
uv run python scripts/validate_config.py
```

Verifica OU duplicate/fuori scope, trust store leggibile e combinazioni
pericolose; stampa un riepilogo **redatto** (host, utente e segreti mascherati).
Exit code `0` = valida, `1` = configurazione non valida.

## 5. Smoke test read-only

```powershell
uv run python scripts/lab_smoke.py
uv run python scripts/lab_smoke.py --resolve-user jdoe@lab.example.test
uv run python scripts/lab_smoke.py --resolve-group "GRP-Operators"
uv run python scripts/lab_smoke.py --list-members 7e565f72-8274-4cb8-b77a-7dad17a1b432
```

Il comando esegue bind LDAPS, RootDSE, capabilities e (su richiesta) risoluzione
e lista membri. **Non esegue alcuna mutazione**; output redatto; exit code
non-zero al primo errore.

## 6. Avvio dell'API

```powershell
uv run python -m mwa_ad_connector.entrypoints.api
```

L'entrypoint carica `ConnectorSettings()` fail-fast, valida la configurazione,
costruisce il runtime (gateway LDAPS, store SQLite in `state_dir`, policy,
servizi) e avvia uvicorn su `api_host:api_port`. Allo shutdown chiude gli store.

Health check anonimo: `GET /api/v1/health`. Readiness autenticata:
`GET /api/v1/readiness` (200 ready / 503 non ready).

## 7. Token di test

```powershell
uv run python scripts/mint_token.py --subject ops@lab.example.test `
    --tenant-id tenant-lab --customer-id customer-lab `
    --connector-id connector-lab-01 `
    --scopes ad.discovery.read,ad.user.read,ad.group.member.write --ttl-seconds 900
```

Stampa **solo** il token; il segreto è letto da `MWA_AD_JWT_SECRET`. I claim
`tenant_id`, `customer_id`, `connector_id` devono coincidere con header e
configurazione del connettore. Il token va trattato come una credenziale.

## 8. Esempi curl

Header obbligatori per ogni chiamata autenticata:

| Header | Valore |
|---|---|
| `Authorization` | `Bearer <token>` |
| `X-Tenant-ID` | tenant del token / configurazione |
| `X-Connector-ID` | `connector_id` del connettore |
| `X-Request-Timestamp` | ISO-8601 UTC corrente (finestra skew) |
| `X-Request-Nonce` | valore monouso per richiesta |
| `X-Correlation-ID` | id di correlazione per il tracing |
| `Idempotency-Key` | obbligatorio sulle mutazioni (univoco) |
| `X-Ticket-ID` | obbligatorio sulle mutazioni |

```bash
BASE=http://127.0.0.1:8443/api/v1
TOKEN="<token da mint_token.py>"
TENANT=tenant-lab
CONNECTOR=connector-lab-01
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NONCE=$(uuidgen)
CORR=$(uuidgen)
AUTH=(-H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: $TENANT" \
      -H "X-Connector-ID: $CONNECTOR" -H "X-Request-Timestamp: $NOW" \
      -H "X-Request-Nonce: $NONCE" -H "X-Correlation-ID: $CORR")

# Health (anonimo)
curl http://127.0.0.1:8443/api/v1/health

# Readiness
curl "${AUTH[@]}" "$BASE/readiness"

# RootDSE
curl "${AUTH[@]}" "$BASE/domains/domain-lab/rootdse"

# Resolve utente
curl "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"object_type":"USER","domain_id":"domain-lab","identifier_type":"SAM_ACCOUNT_NAME","identifier_value":"jdoe"}' \
  "$BASE/users:resolve"

# Aggiungi un membro a un gruppo (con Idempotency-Key e X-Ticket-ID)
curl "${AUTH[@]}" -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" -H "X-Ticket-ID: TICKET-123" \
  -d '{"member_guid":"91faf0e8-cfb6-49ea-80a7-e621986443f8"}' \
  "$BASE/groups/7e565f72-8274-4cb8-b77a-7dad17a1b432/members:add"
```

Risposte: `200` verificato, `202` accodato, `502` commit eseguito ma verifica
fallita (richiede triage), errori con envelope stabile
`{"error":{"code":...,"category":...,"retryable":...,"correlation_id":...}}`.

## 9. Troubleshooting

| Sintomo | Causa probabile | Azione |
|---|---|---|
| `LDAPS_CERTIFICATE_INVALID` / handshake SSL fallito | CA non nel trust store, certificato scaduto o hostname non in SAN | Riesportare la CA, verificare SAN/hostname del DC, controllare `MWA_AD_TRUST_STORE_PATH`. Mai declassare a chiaro. |
| `AUTHENTICATION_FAILED` con timestamp | Clock skew tra host connettore e client oltre `clock_skew_seconds` | Sincronizzare NTP su entrambi gli host; rigenerare `X-Request-Timestamp`. |
| `403 TENANT_BINDING_MISMATCH` | `X-Tenant-ID`/`X-Connector-ID` non coincidono con token e configurazione | Riallineare claim del token, header e `MWA_AD_TENANT_ID`/`MWA_AD_CONNECTOR_ID`. |
| `403 CALLER_FORBIDDEN` | Scope mancante nel token | Rigenerare il token con gli scope richiesti dall'endpoint (es. `ad.group.member.write`). |
| `403 CAPABILITY_NOT_ALLOWED` / `TARGET_OUT_OF_SCOPE` / `PROTECTED_TARGET` | Kill switch, OU fuori scope o target privilegiato | Verificare `MWA_AD_ENABLE_MUTATIONS`, `managed_ous`, e che il target non sia un gruppo/account protetto. |
| `409 APPROVAL_REQUIRED` | Capability approvativa senza contesto di approvazione | Inviare `approval` valido (approvatori e timestamp freschi) o usare un flusso approvato. |
| `503 LDAP_UNAVAILABLE` / readiness non ready | DC irraggiungibile, credenziali bind errate o store non scrivibile | Verificare connettività 636, `bind_user`/`bind_password`, permessi su `state_dir`; ricontrollare i check di `/readiness`. |
| `504 LDAP_TIMEOUT` | DC lento o troppo carico | Ritentare con backoff; alzare `ldap_operation_timeout_seconds` solo dopo analisi. |
| `409 LDAP_CONSTRAINT_VIOLATION` | Vincolo AD (es. ciclo di annidamento gruppi, OU non vuota) | Correggere la richiesta; per le OU usare `require_empty=false` solo se autorizzati. |

Per incidenti e ripristino: [`docs/operations/runbook.md`](runbook.md),
[`docs/operations/incident-response.md`](incident-response.md),
[`docs/operations/backup-restore.md`](backup-restore.md).
