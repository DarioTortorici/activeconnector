# Runbook lab — connettore MWA su `corp.test.local`

Guida operativa **specifica per questo laboratorio**, per riconfigurare da zero o
riprendere i test dopo un reset. Complementa (non sostituisce)
[`ad-setup.md`](ad-setup.md) (procedura generica) e
[`../laboratory/lab-setup.md`](../laboratory/lab-setup.md) (topologia lab).

- Nessun segreto è riportato qui: le password restano nel vault (account
  `svc-mwa`) e nel file env locale `C:\ProgramData\MWA\mwa-ad-env.ps1`.
- Tutto è **solo laboratorio**: mai applicare questi passaggi a domini reali.

## 1. Topologia attuale

| Elemento | Valore |
|---|---|
| Dominio | `corp.test.local` |
| DC | `DC01` — NIC "Ethernet" `10.0.0.10/24` (rete privata **non** raggiungibile dal connettore), NIC "Ethernet 2" `172.17.68.172/20` (Hyper-V Default Switch, **raggiungibile**) |
| Host connettore | `CLU102053` (Windows), repo in questa cartella, `uv` + Python 3.12 |
| Connettore | `customer-lab` / `tenant-lab` / `connector-corp-01` / `forest-corp` / `domain-corp` |
| Base DN | `DC=corp,DC=test,DC=local` |
| OU gestita | `OU=Managed,DC=corp,DC=test,DC=local` |
| OU create sul DC | `Managed` (Users, Groups, ServiceAccounts, Lifecycle), `Unmanaged` (Users, Groups) |
| Account servizio | `svc-mwa@corp.test.local` (in `OU=ServiceAccounts,OU=Managed`) — password nel vault |
| Certificato LDAPS | self-signed `CN=DC01.corp.test.local`, thumbprint `8EA40DBB330DAFF94F3AE784D14B5D7927DA3F21`, scadenza 2028-09-29, trusted in `LocalMachine\Root` + lettura chiave a `SYSTEM` |
| Trust store connettore | `C:\ProgramData\MWA\tls\domain-ca.pem` |
| File env connettore | `C:\ProgramData\MWA\mwa-ad-env.ps1` (da ricaricare con `. C:\ProgramData\MWA\mwa-ad-env.ps1`) |
| Stato SQLite | `C:\ProgramData\MWA\state` |
| Risoluzione nome | file `hosts` su CLU102053: `172.17.68.172  DC01.corp.test.local DC01` |
| Oggetti di test | `jdoe` (OU=Users\Managed) guid `ad3e3006-dc80-46ff-b258-e438ce494c11`; `GRP-Test-Connector` (OU=Groups\Managed) guid `a77ce8ed-1268-4f86-b575-f44ce1b135de` |

Nota: il DNS normale del connettore (Wi-Fi/rete aziendale) **non** risolve
`corp.test.local`; per questo il record è nel file `hosts` puntato alla NIC
raggiungibile del DC.

## 2. Ricostruzione da zero (se resetti lab o cambi macchina)

### Fase A — sul DC (PowerShell amministratore)

1. Struttura OU (idempotente):
   ```powershell
   $base = "DC=corp,DC=test,DC=local"
   $ous = @(
     @{ Name='Managed';         Path=$base },
     @{ Name='Users';           Path="OU=Managed,$base" },
     @{ Name='Groups';          Path="OU=Managed,$base" },
     @{ Name='ServiceAccounts'; Path="OU=Managed,$base" },
     @{ Name='Lifecycle';       Path="OU=Managed,$base" },
     @{ Name='Unmanaged';       Path=$base },
     @{ Name='Users';           Path="OU=Unmanaged,$base" },
     @{ Name='Groups';          Path="OU=Unmanaged,$base" }
   )
   foreach ($ou in $ous) {
     $dn = "OU=$($ou.Name),$($ou.Path)"
     if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
       New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path
     }
   }
   ```

2. Certificato LDAPS (script del repo, copiato sul DC):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\dc_ldaps_cert.ps1 -TrustForLdaps -RestartService -Pause
   ```
   - opzioni: `-Ensure` crea il self-signed se manca; `-TrustForLdaps` lo mette in
     `LocalMachine\Root` e concede la chiave a SYSTEM; `-RestartService` riavvia NTDS
     (breve disconnessione RDP, normale); il PEM viene salvato sul Desktop.
   - controlli: `Get-WinEvent -LogName 'Directory Service' -MaxEvents 10 | Where-Object Id -eq 1220`
     non deve avere eventi nuovi; l'handshake locale deve risultare OK.

3. Account di servizio (non admin):
   ```powershell
   $pwd = Read-Host -AsSecureString "Password conforme per svc-mwa"
   New-ADUser -Name "svc-mwa" -SamAccountName "svc-mwa" `
     -UserPrincipalName "svc-mwa@corp.test.local" `
     -Path "OU=ServiceAccounts,OU=Managed,DC=corp,DC=test,DC=local" `
     -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $true
   Get-ADPrincipalGroupMembership svc-mwa | Select-Object Name   # solo Domain Users
   ```
   Se `New-ADUser` fallisce per la password, l'oggetto può restare creato e
   disabilitato: usa `Set-ADAccountPassword -Identity svc-mwa -Reset -NewPassword ...`
   + `Enable-ADAccount -Identity svc-mwa`.

4. Deleghe su `OU=Managed` (console `dsa.msc` → tasto destro su **Managed** →
   *Delega controllo* → aggiungi `svc-mwa`):
   - **già fatta**: *Modifica dell'appartenenza a un gruppo* → abilita `group.member.add` / `group.member.remove`
   - **da fare** (vedi §5 per la mappa capability → delega)

5. Oggetti di test:
   ```powershell
   $pwd = Read-Host -AsSecureString "Password iniziale jdoe"
   New-ADUser -Name "jdoe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@corp.test.local" `
     -Path "OU=Users,OU=Managed,DC=corp,DC=test,DC=local" -AccountPassword $pwd -Enabled $true
   New-ADGroup -Name "GRP-Test-Connector" -SamAccountName "GRP-Test-Connector" `
     -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Managed,DC=corp,DC=test,DC=local"
   "GRUPPO_GUID = " + (Get-ADGroup "GRP-Test-Connector").ObjectGuid.Guid
   "UTENTE_GUID = " + (Get-ADUser jdoe).ObjectGuid.Guid
   ```

### Fase B — sul connettore (CLU102053)

1. Risoluzione nome (PowerShell admin, una volta sola):
   ```powershell
   Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`n172.17.68.172`tDC01.corp.test.local DC01"
   Clear-DnsClientCache
   Test-NetConnection DC01.corp.test.local -Port 636 -InformationLevel Quiet   # True
   ```
   Se punta alla NIC sbagliata (es. `10.0.0.10`) il TCP non risponde: correggi l'entry
   (la NIC `172.17.68.172` è la Default Switch, raggiungibile; la `10.0.0.10` no).

2. Trust store: copia il PEM dal Desktop del DC:
   ```powershell
   New-Item -ItemType Directory -Force C:\ProgramData\MWA\tls | Out-Null
   Copy-Item \\DC01\C$\Users\Administrator\Desktop\dc-ldaps-cert.pem C:\ProgramData\MWA\tls\domain-ca.pem -Force
   ```

3. File env (crea/aggiorna, poi ricarica). I segreti vanno generati e conservati:
   ```powershell
   New-Item -ItemType Directory -Force C:\ProgramData\MWA | Out-Null
   $content = @'
   $env:MWA_AD_CUSTOMER_ID = "customer-lab"
   $env:MWA_AD_TENANT_ID = "tenant-lab"
   $env:MWA_AD_CONNECTOR_ID = "connector-corp-01"
   $env:MWA_AD_FOREST_ID = "forest-corp"
   $env:MWA_AD_DOMAIN_ID = "domain-corp"
   $env:MWA_AD_BASE_DN = "DC=corp,DC=test,DC=local"
   $env:MWA_AD_MANAGED_OUS = '["OU=Managed,DC=corp,DC=test,DC=local"]'
   $env:MWA_AD_DC_HOST = "DC01.corp.test.local"
   $env:MWA_AD_DC_PORT = "636"
   $env:MWA_AD_USE_LDAPS = "true"
   $env:MWA_AD_LDAPS_REQUIRE_CERT = "true"
   $env:MWA_AD_TRUST_STORE_PATH = "C:\ProgramData\MWA\tls\domain-ca.pem"
   $env:MWA_AD_AUTH_MODE = "simple"
   $env:MWA_AD_BIND_USER = "svc-mwa@corp.test.local"
   $env:MWA_AD_BIND_PASSWORD = "__DAL_VAULT__"
   $env:MWA_AD_SOURCE_ANCHOR_STRATEGY = "objectGuid"
   $env:MWA_AD_ENABLE_MUTATIONS = "true"
   $env:MWA_AD_ENABLE_PASSWORD_RESET = "false"
   $env:MWA_AD_VALIDATION_MODE_ONLY = "true"
   $env:MWA_AD_STATE_DIR = "C:\ProgramData\MWA\state"
   $env:MWA_AD_JWT_SECRET = "__JWT__"
   $env:MWA_AD_JWT_ISSUER = "mwa-trusted-agent"
   $env:MWA_AD_JWT_AUDIENCE = "mwa-ad-connector"
   $env:MWA_AD_PAGE_TOKEN_SECRET = "__PAGE__"
   $env:MWA_AD_API_HOST = "127.0.0.1"
   $env:MWA_AD_API_PORT = "8443"
   $env:MWA_AD_LOG_LEVEL = "INFO"
   $env:MWA_AD_REQUEST_MAX_BYTES = "1048576"
   $env:MWA_AD_CLOCK_SKEW_SECONDS = "60"
   $env:MWA_AD_NONCE_TTL_SECONDS = "300"
   $env:MWA_AD_RATE_LIMIT_CAPACITY = "100"
   $env:MWA_AD_RATE_LIMIT_PER_SECOND = "10.0"
   $env:MWA_AD_LDAP_CONNECT_TIMEOUT_SECONDS = "10.0"
   $env:MWA_AD_LDAP_OPERATION_TIMEOUT_SECONDS = "30.0"
   $env:MWA_AD_LDAP_POOL_SIZE = "10"
   '@
   # genera i due segreti e sostituisci i placeholder:
   $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $b = New-Object byte[] 48
   $rng.GetBytes($b); $jwt = [Convert]::ToBase64String($b)
   $rng.GetBytes($b); $page = [Convert]::ToBase64String($b)
   $content = $content.Replace('__JWT__', $jwt).Replace('__PAGE__', $page)
   Set-Content -Path C:\ProgramData\MWA\mwa-ad-env.ps1 -Value $content -Encoding ASCII
   notepad C:\ProgramData\MWA\mwa-ad-env.ps1   # inserisci la password di svc-mwa al posto di __DAL_VAULT__
   ```
   (in alternativa: `uv run python scripts/discover_ad_env.ps1 -OutputPath C:\ProgramData\MWA\mwa-ad-env.ps1 -ExportCaTo ...` rigenera il blocco completo)

4. Rilancia sempre in ogni nuovo terminale:
   ```powershell
   . C:\ProgramData\MWA\mwa-ad-env.ps1
   ```

## 3. Verifica di connettività (in ordine)

```powershell
. C:\ProgramData\MWA\mwa-ad-env.ps1
uv run python scripts/validate_config.py      # configurazione valida, output redatto
uv run python scripts/diag_ldaps.py           # [1/3] TCP, [2/3] TLS, [3/3] bind
uv run python scripts/lab_smoke.py            # ping + RootDSE + capabilities (read-only)
uv run python scripts/lab_smoke.py --resolve-user jdoe
uv run python scripts/diag_entry.py jdoe      # forma entry + esito mapping (diagnostica)
```

Esiti attesi: `configuration_valid`, `[3/3] LDAP bind : OK`, `"ok": true`,
RootDSE con i naming contexts, resolve con `object_guid`.

## 4. API: avvio e comandi di test

Terminale 1:
```powershell
. C:\ProgramData\MWA\mwa-ad-env.ps1
uv run python -m mwa_ad_connector.entrypoints.api      # HTTP su 127.0.0.1:8443
```

Terminale 2 (preparazione):
```powershell
. C:\ProgramData\MWA\mwa-ad-env.ps1
$token = (uv run python scripts/mint_token.py --subject ops@corp.test.local `
  --tenant-id tenant-lab --customer-id customer-lab --connector-id connector-corp-01 `
  --scopes ad.readiness.read,ad.discovery.read,ad.user.read,ad.group.read,ad.group.member.write,ad.operation.read `
  --ttl-seconds 900).Trim()
$base = "http://127.0.0.1:8443/api/v1"
$headers = @{
  Authorization = "Bearer $token"
  "X-Tenant-ID" = "tenant-lab"
  "X-Connector-ID" = "connector-corp-01"
  "X-Request-Timestamp" = (Get-Date).ToUniversalTime().ToString("o")
  "X-Request-Nonce" = [guid]::NewGuid().ToString("N")
  "X-Correlation-ID" = [guid]::NewGuid().ToString("N")
}
Invoke-RestMethod -Uri "$base/readiness" -Headers $headers
```

Read (nessun Idempotency-Key/X-Ticket-ID):
```powershell
$body = '{"object_type":"USER","domain_id":"domain-corp","identifier_type":"SAM_ACCOUNT_NAME","identifier_value":"jdoe"}'
Invoke-RestMethod -Method Post -Uri "$base/users:resolve" -Headers $headers -ContentType "application/json" -Body $body
```

Mutazioni (servono `Idempotency-Key` **nuovo a ogni tentativo** e `X-Ticket-ID`):
```powershell
$groupGuid  = "a77ce8ed-1268-4f86-b575-f44ce1b135de"
$memberGuid = "ad3e3006-dc80-46ff-b258-e438ce494c11"
$mut = $headers + @{ "Idempotency-Key" = [guid]::NewGuid().ToString("N"); "X-Ticket-ID" = "LAB-010" }
$body = @{ member_guid = $memberGuid; member_type = "USER" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$base/groups/$groupGuid/members:add" -Headers $mut -ContentType "application/json" -Body $body
```
Esiti: `200 AD_VERIFIED` + `disposition APPLIED` (o `NO_OP` se già membro),
`502 FAILED_VERIFICATION` se commit ok ma verifica fallita (richiede triage).

> **Attenzione**: `X-Request-Timestamp` vale solo 60 secondi. Non riusare lo
> stesso `$headers` dopo qualche minuto: l'API risponde
> `AUTHENTICATION_FAILED: X-Request-Timestamp outside the allowed skew window`.
> Rigenera timestamp e nonce a ogni chiamata — usa l'helper:

```powershell
function Invoke-MwaApi {
  param([string]$Method, [string]$Path, $Body, [hashtable]$Extra)
  $headers["X-Request-Timestamp"] = (Get-Date).ToUniversalTime().ToString("o")
  $headers["X-Request-Nonce"] = [guid]::NewGuid().ToString("N")
  $h = if ($Extra) { $headers + $Extra } else { $headers }
  if ($null -ne $Body) {
    Invoke-RestMethod -Method $Method -Uri "$base$Path" -Headers $h -ContentType "application/json" -Body ($Body | ConvertTo-Json)
  } else {
    Invoke-RestMethod -Method $Method -Uri "$base$Path" -Headers $h
  }
}
# rimozione (NON inviare member_type: MemberRemoveRequest ha extra=forbid)
Invoke-MwaApi POST "/groups/$groupGuid/members:remove" @{ member_guid = $memberGuid } @{ "Idempotency-Key" = "lab-remove-001"; "X-Ticket-ID" = "LAB-011" }
# aggiunta
Invoke-MwaApi POST "/groups/$groupGuid/members:add" @{ member_guid = $memberGuid; member_type = "USER" } @{ "Idempotency-Key" = "lab-add-002"; "X-Ticket-ID" = "LAB-012" }
```

`NO_OP` è idempotenza, non un errore: add su membro presente = `NO_OP`,
remove su membro assente = `NO_OP` (sempre `AD_VERIFIED` + `matched: true`).

Consultazione operazione/audit:
```powershell
Invoke-RestMethod -Uri "$base/operations/<operation_id>" -Headers $headers
```

### Modalità dry-run / scritture reali

- `MWA_AD_VALIDATION_MODE_ONLY="true"` → tutte le mutazioni vengono forzate a dry-run.
- Per scritture reali: portalo a `"false"` nel file env, **ricarica** (`. ...`) e
  **riavvia l'API** (le impostazioni si leggono allo startup).
- `MWA_AD_ENABLE_MUTATIONS=false` è il kill switch globale; `MWA_AD_ENABLE_PASSWORD_RESET`
  abilita il reset password (richiede LDAPS + approval).

## 5. Capability: stato e deleghe

| Capability | Delega ADUC su OU=Managed | Stato |
|---|---|---|
| `group.member.add` / `group.member.remove` | *Modifica dell'appartenenza a un gruppo* | **fatta e verificata E2E** (ciclo APPLIED add/remove + NO_OP idempotente) |
| `account.unlock` | custom task → *User objects* → Property-specific → Read/Write **lockoutTime** | **fatta e verificata E2E** (APPLIED su jdoe bloccato) |
| `account.password.reset` | *Reimpostare le password utente e richiedere il cambio password all'accesso successivo* | **da riprendere**: primo tentativo in dry-run (`AUTHORIZED`/`NO_OP` ⇒ l'API vedeva `VALIDATION_MODE_ONLY=true`); verificare flag/riavvio e ritentare con key nuova |
| `account.password.force_change` | custom task → *User objects* → Read/Write **pwdLastSet** | **fatta e verificata E2E** (APPLIED, pwdLastSet→0) |
| `account.enable` / `account.disable` | custom task → *User objects* → Read/Write **userAccountControl** | **fatta e verificata E2E** (APPLIED; approval mode REQUIRED con oggetto `approval`) |
| `user.attributes.update` | custom task → *User objects* → Read/Write degli attributi allowlisted (`displayName`, `givenName`, `sn`, `description`, `title`, `department`, `company`, `telephoneNumber`, `mobile`, `mail`, `streetAddress`, `l`, `st`, `postalCode`, `c`, `co`, `countryCode`, `employeeID`, `employeeType`, `manager`, `info`) | **fatta e verificata E2E** (APPLIED su `displayName`) |
| `user.create` / `user.delete` | *Creazione, eliminazione e gestione di account utente* | **fatta e verificata E2E** (create/rename/move/delete, delete con approval) |
| `user.rename` / `user.move` | diritti create/delete child + write `name` (se `403 LDAP_INSUFFICIENT_ACCESS`, custom task con Create/Delete child su OU destinazione) | **fatta e verificata E2E** (rename + move verso `OU=Lifecycle`) |
| `group.create` / `group.delete` / `group.attributes.update` | *Creazione, eliminazione e gestione di gruppi* (+ custom Read/Write per `displayName`, `description`, `mail`, `info`, `managedBy`) | **fatta e verificata E2E** (create/attrs/rename/move/delete; delete con approval) |
| `group.rename` / `group.move` | come user rename/move | **fatta e verificata E2E** |
| `ou.create` / `ou.rename` / `ou.move` / `ou.delete` | custom task → *Organizational Unit objects* → Create/Delete (+ ACE classe `organizationalUnit` via script se il wizard non basta) | **fatta e verificata E2E** (create/rename/move/delete APPLIED; move/delete con approval) |
| Read (`user.resolve`, `user.get`, `search`, `members.list`, RootDSE) | letture consentite agli utenti autenticati | **fatte e verificate** |
| `operation.get` / `audit.get` / `audit.export` | nessuna ACL AD | da verificare |

Promemoria errori tipici: senza delega → `403 LDAP_INSUFFICIENT_ACCESS`;
target fuori OU gestita → `403 TARGET_OUT_OF_SCOPE`; gruppo/account protetto →
`403 PROTECTED_TARGET`; approvazione mancante → `409 APPROVAL_REQUIRED`;
`Idempotency-Key` riusata su operazione FAILED → replay `REJECTED` (usa una chiave nuova).

## 6. Cosa resta da testare (checklist)

- [x] `group.member.remove` con `APPLIED` + verifica `Get-ADGroupMember` (fatto: ciclo add→remove→add APPLIED)
- [ ] replay idempotente: stessa `Idempotency-Key` → stesso `operation_id`, nessuna doppia scrittura
- [ ] dry-run: `VALIDATION_MODE_ONLY=true` → 202 senza modifiche AD
- [x] `account.unlock` su un utente bloccato (fatto: APPLIED; blocco via policy + tentativi errati, non scrivibile direttamente)
- [x] `account.password.force_change` (fatto: APPLIED, pwdLastSet→0)
- [ ] `account.password.reset` (LDAPS + `ENABLE_PASSWORD_RESET=true` + approval) — **da riprendere** (primo tentativo dry-run; controllare `VALIDATION_MODE_ONLY` e riavvio API, poi key nuova)
- [x] `account.enable` / `account.disable` (fatto: APPLIED + approval context; verificare anche il negativo 409 senza approval)
- [x] `user.attributes.update` su attributi allowlisted (fatto: APPLIED su `displayName`; ridiff con stessa key → replay)
- [x] `user.create` / `user.rename` / `user.move` / `user.delete` (fatto: ciclo completo APPLIED, delete con approval)
- [x] `group.create` / `group.attributes.update` / `group.rename` / `group.move` / `group.delete` (fatto: ciclo completo APPLIED, delete con approval)
- [x] `ou.create` / `ou.rename` / `ou.move` / `ou.delete` (fatto: ciclo completo APPLIED, move/delete con approval)
- [ ] casi negativi: target in `OU=Unmanaged`, gruppo protetto (`Domain Admins`), replay di nonce, tenant mismatch
- [ ] `operation.get`/`operation.list` e `audit.get`/`audit.export`
- [ ] grep dei log: nessun segreto (password bind, password reset, JWT) in log/audit/risposte
- [ ] worker outbound (Step 16) end-to-end con relay di test
- [ ] dopo i test: riportare `MWA_AD_VALIDATION_MODE_ONLY="true"`

## 7. Cronologia dei bug trovati e corretti in lab

Tutti trovati proprio grazie a questo lab e coperti da test di regressione
(`uv run pytest tests/unit tests/contract tests/security tests/e2e -q`):

1. **Paging vuoto** — `ldap3.paged_search(generator=True)` restituisce dict grezzi,
   il codice si aspettava oggetti `Entry` → ogni ricerca paginata tornava vuota.
   Fix: paging a cookie con normalizzazione dei dict (`infrastructure/ldap/core.py`).
2. **`CaseInsensitiveDict`** — le mappe attributi di ldap3 non sono `dict`;
   il check `isinstance(attrs, dict)` le scartava → entry "vuote".
   Fix: `collections.abc.Mapping` in normalizzazione e mapping.
3. **`objectGUID` in forma `{guid}`** — ldap3 formatta il GUID come stringa
   graffata; il parser bytes-only falliva ("objectGUID must be 16 bytes").
   Fix: `parse_object_guid` condiviso (entry mapping, membri, resolve-by-DN).
4. **`pwdLastSet`/attributi vuoti** — `pwdLastSet` arriva come datetime (veniva
   ignorato) e gli attributi vuoti come `[]` (diventavano la stringa `"[]"`).
   Fix: passthrough datetime, sequenze vuote → `None`.
5. **Commit-ok/verify-fail classificato come errore pre-commit** — un
   `VerificationFailedError` dopo il commit usciva come 400; ora è
   `FAILED_VERIFICATION` (502) con transizione `EXECUTING→FAILED_VERIFICATION`.
6. **Rilevazione lockout sbagliata** — `locked` era derivato da un bit UAC
   (0x0010) che i lockout reali non settano; ldap3 formatta `lockoutTime=0`
   come `datetime(1601-01-01)`. Ora `locked` = `lockoutTime > epoch` (+ bit
   legacy), così l'unlock su un account davvero bloccato non risponde più
   `NO_OP`. In lab il blocco si provoca solo con tentativi errati: AD vieta di
   scrivere `lockoutTime` a valori non-zero (`Set-ADUser`/ADSI danno errore 87/E_FAIL).
7. **Scope route ≠ scope catalogo policy** — enable/disable chiedeva
   `ad.account.state.write` sulla route e `ad.account.enable/disable` nel
   catalogo; rename/move utente lo stesso con `ad.user.lifecycle.write`.
   Allineati ai valori canonici del piano §12 (altrimenti doppio scope nel
   token per far passare entrambi i controlli).
8. **Replay idempotente senza DC persistito** — il replay di una
   `Idempotency-Key` già registrata ricostruiva `source_dc=""` (il record
   persistito non salva `selected_dc`) e pydantic rifiutava il `MutationResult`
   ("String should have at least 1 character"). Ora il replay usa il DC del
   servizio come fallback (`or "unknown"`), con test di regressione.
9. **`group.create` → 500 INTERNAL_ERROR** — `groupType` è un intero
   (`-2147483646` = global security) e la creazione faceva `list(int)` →
   `TypeError`. Ora i valori scalari vengono normalizzati in lista
   (`_add_values`) per user/group/OU; l'handler 500 logga anche il traceback
   per diagnosi future.

## 8. Troubleshooting (errori realmente incontrati)

| Sintomo | Causa | Fix |
|---|---|---|
| La finestra si chiude e non vedi l'output | script lanciato con doppio click | `-Pause` oppure `powershell -NoExit -ExecutionPolicy Bypass -File ...`; `-OutputPath` per salvare |
| `trust store not readable` | PEM assente sul connettore | copia `dc-ldaps-cert.pem` in `C:\ProgramData\MWA\tls\domain-ca.pem` |
| Handshake TLS "forcibly closed" / evento 1220 | certificato assente/non trusted/senza permessi chiave | `dc_ldaps_cert.ps1 -TrustForLdaps -RestartService` |
| `getaddrinfo failed` | il connettore non risolve `DC01.corp.test.local` | entry nel file `hosts` verso `172.17.68.172` |
| TCP 636/389 chiuso verso `10.0.0.10` | NIC sbagliata (rete privata non raggiungibile) | usa `172.17.68.172` nell'entry hosts |
| `New-ADUser`: password policy / "esiste già" | password debole; oggetto creato e disabilitato | `Set-ADAccountPassword -Reset` + `Enable-ADAccount` |
| `TARGET_NOT_FOUND` con messaggio sul tipo identificatore | utente assente o ricerca paginata rotta (bug 1) | crea l'utente / applica i fix |
| `skipping unmappable ... entry` nei log | mapping entry→modello (bug 2-4) | aggiorna il repo e riavvia |
| `REQUEST_INVALID: objectGUID must be 16 bytes` | parsing GUID legacy (bug 3) | aggiorna il repo e riavvia l'API |
| `disposition NO_OP` inatteso | membro già presente (es. tentativo precedente già committato) | comportamento corretto/idempotente; verifica con `Get-ADGroupMember` |
| `403 LDAP_INSUFFICIENT_ACCESS` | delega mancante per la capability | aggiungi la delega in §5 |
| `$env:MWA_AD_*` spariate | sono di sessione | `. C:\ProgramData\MWA\mwa-ad-env.ps1` in ogni terminale |
| `AUTHENTICATION_FAILED: X-Request-Timestamp outside the allowed skew window` | `$headers` riusato con timestamp vecchio (>60 s) | rigenera `X-Request-Timestamp`/`X-Request-Nonce` a ogni chiamata (helper `Invoke-MwaApi` in §4) |
| `422/REQUEST_INVALID` sul remove dei membri | body del remove contiene `member_type` (extra=forbid) | invia solo `member_guid` |
| `Set-ADUser ... lockoutTime` errore 87 o ADSI `E_FAIL` | AD vieta la scrittura di `lockoutTime` non-zero (solo `0` = unlock è permesso) | per bloccare: `Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 ...` + 6 `net use` con password errata verso `\\DC01\IPC$` |
| `Set-ADDefaultDomainPasswordPolicy` errore 87 | manca `-Identity` e/o `LockoutDuration < LockoutObservationWindow` | `-Identity "corp.test.local" -LockoutDuration 01:00:00 -LockoutObservationWindow 00:15:00` |
| unlock risponde `NO_OP` | l'account non era bloccato al momento della chiamata (blocco auto-scaduto) | rifai il lockout e richiama subito; durata ≥ 15 min per non correre |
| `403 CALLER_FORBIDDEN: Missing required scopes` | il token non ha lo scope canonico (route e/o catalogo) | riemetti il token con lo scope della capability (tabella §5; valori piano §12) |
| `409 APPROVAL_REQUIRED` | capability con approval mode REQUIRED senza oggetto `approval` | aggiungi `approval` (approval_id, approved_by, approved_at fresco) nel body |
| `REQUEST_INVALID: 1 validation error for MutationResult ... source_dc` | replay di una key già registrata (bug storico, corretto) | aggiorna il repo e riavvia l'API; per rieseguire davvero usa una **key nuova** |
| `500 INTERNAL_ERROR: internal connector error` | eccezione non mappata (es. bug su valore scalare nel create) | guarda il traceback nel log dell'API (`unhandled connector error` + correlation_id), aggiorna il repo e riavvia; retry con key nuova |
| `ou.create` 403 nonostante la delega | l'ACE per la classe `organizationalUnit` manca (il wizard a volte non la applica) | aggiungi CreateChild/DeleteChild per `organizationalUnit` via ADSI (`ObjectSecurity.AddAccessRule` + `CommitChanges`) e verifica con `dsacls ... \| findstr /i organizationalUnit` |

## 9. Riferimenti utili

- Script: `scripts/dc_ldaps_cert.ps1`, `scripts/discover_ad_env.ps1`,
  `scripts/diag_ldaps.py`, `scripts/diag_entry.py`, `scripts/lab_smoke.py`,
  `scripts/mint_token.py`, `scripts/validate_config.py`
- Doc: [`ad-setup.md`](ad-setup.md), [`runbook.md`](runbook.md),
  [`../laboratory/lab-setup.md`](../laboratory/lab-setup.md)
- Suite di test senza lab: `uv run pytest tests/unit tests/contract tests/security tests/e2e -q`
- Test lab-gated: `MWA_AD_LAB=1 uv run pytest tests/integration -q` (quando il lab è attivo)
