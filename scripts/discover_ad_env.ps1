<#
.SYNOPSIS
    Rilevamento read-only dell'ambiente AD per compilare le variabili MWA_AD_* (Step 1 di ad-setup.md).

.DESCRIPTION
    Da eseguire su un host domain-joined (o sul DC). Non modifica AD e non legge
    segreti esistenti. Rileva:
      - dominio DNS/NetBIOS e Base DN (RootDSE defaultNamingContext, fallback dal nome DNS)
      - domain controller preferito e raggiungibilita' della porta 636 (LDAPS)
      - certificato server LDAPS del DC (subject, SAN, scadenza) e validazione stretta
      - catena di trust e CA radice, con esportazione PEM opzionale (-ExportCaTo)
      - elenco delle OU sotto il Base DN e suggerimento della OU gestita (-ManagedOuHint)
      - generazione di JWT_SECRET e PAGE_TOKEN_SECRET nuovi (CSPRNG)
    Stampa un blocco PowerShell pronto da incollare con le variabili MWA_AD_*.

.PARAMETER ManagedOuHint
    Nome (ultimo RDN) della OU da suggerire come gestita. Default: Managed.

.PARAMETER DcHost
    DC da sondare (FQDN o IP). Se omesso usa il DC preferito del dominio.

.PARAMETER OutputPath
    Se specificato, salva il blocco MWA_AD_* nel file indicato (ASCII).

.PARAMETER ExportCaTo
    Se specificato, esporta la CA radice della catena LDAPS in PEM nel percorso indicato.

.PARAMETER Pause
    Attende Invio prima di uscire, cosi' la finestra non si chiude (utile in doppio click
    o con "Esegui con PowerShell").

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\discover_ad_env.ps1
    powershell -ExecutionPolicy Bypass -File .\scripts\discover_ad_env.ps1 `
        -ExportCaTo C:\ProgramData\MWA\tls\domain-ca.pem -OutputPath .\mwa-ad-env.ps1 -Pause

.NOTES
    Solo lettura. Il blocco generato contiene segreti NUOVI: trattalo come credenziale.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ManagedOuHint = 'Managed',
    [string]$DcHost = '',
    [string]$OutputPath = '',
    [string]$ExportCaTo = '',
    [switch]$Pause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Wait-IfPaused {
    if ($Pause) {
        Write-Host ''
        Read-Host 'Premi Invio per chiudere' | Out-Null
    }
}

trap {
    Write-Host ''
    Write-Host "ERRORE: $($_.Exception.Message)" -ForegroundColor Red
    Wait-IfPaused
    exit 1
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    }
    catch { return $false }
    finally { $client.Close() }
}

function New-RandomSecret {
    param([int]$Bytes = 48)
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buffer)
}

function Export-PemCertificate {
    param([byte[]]$RawData, [string]$Path)
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $base64 = [Convert]::ToBase64String($RawData)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
        [void]$builder.AppendLine($base64.Substring($i, [Math]::Min(64, $base64.Length - $i)))
    }
    [void]$builder.AppendLine('-----END CERTIFICATE-----')
    [IO.File]::WriteAllText($Path, $builder.ToString(), [Text.Encoding]::ASCII)
}

function Get-LdapsInfo {
    param([string]$ComputerName)
    $info = [ordered]@{
        Reachable      = $false
        StrictOk       = $false
        StrictError    = ''
        Subject        = ''
        Issuer         = ''
        NotAfter       = ''
        San            = ''
        Thumbprint     = ''
        RootSubject    = ''
        RootThumbprint = ''
        RootRaw        = $null
    }
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect($ComputerName, 636, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { return $info }
        $tcp.EndConnect($async)
        $info.Reachable = $true

        $permissive = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $sslPolicyErrors) return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $permissive)
        $ssl.AuthenticateAsClient($ComputerName)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $info.Subject = $cert.Subject
        $info.Issuer = $cert.Issuer
        $info.NotAfter = $cert.NotAfter.ToString('yyyy-MM-dd')
        $info.Thumbprint = $cert.Thumbprint
        $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        if ($sanExt) {
            $info.San = (($sanExt.Format($true) -split "`r?`n") | Where-Object { $_ -and $_.Trim() }) -join '; '
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        [void]$chain.Build($cert)
        if ($chain.ChainElements.Count -gt 0) {
            $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
            $info.RootSubject = $root.Subject
            $info.RootThumbprint = $root.Thumbprint
            $info.RootRaw = $root.RawData
        }
        $ssl.Dispose()

        $tcp2 = New-Object System.Net.Sockets.TcpClient($ComputerName, 636)
        try {
            $ssl2 = New-Object System.Net.Security.SslStream($tcp2.GetStream(), $false)
            $ssl2.AuthenticateAsClient($ComputerName)
            $info.StrictOk = $true
            $ssl2.Dispose()
        }
        catch {
            $info.StrictOk = $false
            $info.StrictError = $_.Exception.Message
        }
        finally { $tcp2.Close() }
    }
    catch { $info.StrictError = $_.Exception.Message }
    finally { $tcp.Close() }
    return $info
}

function Get-DirectoryOus {
    param([string]$Server, [string]$BaseDn)
    $result = @()
    $rsat = Get-Command -Name Get-ADOrganizationalUnit -ErrorAction SilentlyContinue
    if ($rsat) {
        try {
            $result = @(Get-ADOrganizationalUnit -Server $Server -SearchBase $BaseDn -Filter * |
                Select-Object -ExpandProperty DistinguishedName)
            return $result
        }
        catch { }
    }
    try {
        Add-Type -AssemblyName System.DirectoryServices
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$BaseDn")
        $searcher.Filter = '(objectClass=organizationalUnit)'
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 500
        $result = @($searcher.FindAll() | ForEach-Object { [string]$_.Properties['distinguishedname'][0] })
    }
    catch { }
    return $result
}

# ---------------------------------------------------------------- preflight ----
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    Write-Error "Questo host non e' domain-joined (PartOfDomain=false). Esegui lo script su un membro del dominio o sul DC."
    exit 1
}

Write-Section 'Dominio'
$domain = $null
try {
    Add-Type -AssemblyName System.DirectoryServices
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
}
catch {
    Write-Error "Impossibile contattare il dominio AD: $($_.Exception.Message)"
    exit 1
}
$dnsRoot = $domain.Name
$netbios = $env:USERDOMAIN
Write-Host "DNS root      : $dnsRoot"
Write-Host "NetBIOS       : $netbios"
Write-Host "Host          : $($cs.Name)"

if (-not $DcHost) {
    $DcHost = ''
    $nltest = Get-Command -Name nltest -ErrorAction SilentlyContinue
    if ($nltest) {
        try {
            $hits = @(& nltest /dsgetdc:$dnsRoot 2>$null | Select-String -Pattern 'DC:\s*\\\\(.+)')
            if ($hits.Count -gt 0) { $DcHost = $hits[0].Matches[0].Groups[1].Value.Trim() }
        }
        catch { }
    }
    if (-not $DcHost) {
        try { if ($domain.PdcRoleOwner) { $DcHost = $domain.PdcRoleOwner.Name } } catch { }
    }
}
if (-not $DcHost) {
    Write-Error "Nessun DC rilevato. Passa -DcHost <fqdn>."
    exit 1
}
Write-Host "DC preferito  : $DcHost"
try {
    $others = @($domain.DomainControllers | ForEach-Object { $_.Name } | Where-Object { $_ -and $_ -ne $DcHost })
    if ($others.Count -gt 0) { Write-Host "Altri DC      : $($others -join ', ')" }
}
catch { }

$baseDn = ''
try {
    $rootDse = [ADSI]"LDAP://$DcHost/RootDSE"
    if ($rootDse.defaultNamingContext) { $baseDn = [string]$rootDse.defaultNamingContext }
}
catch { }
if (-not $baseDn) {
    $baseDn = ($dnsRoot.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    Write-Warning "RootDSE non leggibile in anonimo: Base DN calcolato dal nome DNS ($baseDn)."
}
Write-Host "Base DN       : $baseDn"

# ------------------------------------------------------------------- LDAPS ----
Write-Section 'LDAPS (porta 636) e certificato'
$ldaps = Get-LdapsInfo -ComputerName $DcHost
if ($ldaps.Reachable) {
    Write-Host 'Porta 636     : raggiungibile' -ForegroundColor Green
    Write-Host "Subject       : $($ldaps.Subject)"
    Write-Host "SAN           : $($ldaps.San)"
    Write-Host "Scadenza      : $($ldaps.NotAfter)"
    if ($ldaps.StrictOk) {
        Write-Host 'Validazione   : OK (catena e hostname validi da questo host)' -ForegroundColor Green
    }
    else {
        Write-Host 'Validazione   : FALLITA da questo host' -ForegroundColor Yellow
        Write-Host "                $($ldaps.StrictError)" -ForegroundColor Yellow
        if ($ldaps.StrictError -match 'forcibly closed|transport connection|reset|received an unexpected EOF') {
            Write-Host '                Handshake TLS interrotto dal DC: LDAPS non sta servendo un certificato valido.' -ForegroundColor Yellow
            Write-Host '                Sul DC esegui: scripts/dc_ldaps_cert.ps1 -Ensure -RestartService' -ForegroundColor Yellow
        }
        else {
            Write-Host '                Causa tipica: CA non nel trust store. Usa -ExportCaTo e imposta MWA_AD_TRUST_STORE_PATH.' -ForegroundColor Yellow
        }
    }
    if ($ldaps.San) {
        $sanOk = $ldaps.San -match [regex]::Escape($DcHost.Split('.')[0])
        if (-not $sanOk) {
            Write-Warning "Il SAN non sembra contenere il nome del DC ('$DcHost'): possibile hostname mismatch."
        }
    }
    else {
        Write-Host 'Certificato   : non leggibile (handshake fallito prima dello scambio del certificato)' -ForegroundColor Yellow
    }
    Write-Host "CA radice     : $($ldaps.RootSubject)"
}
else {
    Write-Host 'Porta 636     : NON raggiungibile' -ForegroundColor Red
    Write-Warning 'LDAPS non attivo sul DC: il connettore rifiuta LDAP in chiaro. Abilita un certificato server (AD CS o CA lab) e riprova.'
}

$caExported = ''
if ($ExportCaTo -and $ldaps.RootRaw) {
    Export-PemCertificate -RawData $ldaps.RootRaw -Path $ExportCaTo
    $caExported = $ExportCaTo
    Write-Host "CA esportata  : $ExportCaTo" -ForegroundColor Green
}
elseif ($ExportCaTo) {
    Write-Warning 'CA NON esportata: catena LDAPS non recuperabile (LDAPS raggiungibile? certificato presente?). Risolvi e rilancia con -ExportCaTo.'
}
else {
    Write-Warning 'CA non esportata: aggiungi -ExportCaTo <percorso.pem> e rilancia (il file PEM deve esistere sull host connettore).'
}

# ---------------------------------------------------------------------- OU ----
Write-Section "OU sotto il Base DN (suggerita: *$ManagedOuHint*)"
$ous = @(Get-DirectoryOus -Server $DcHost -BaseDn $baseDn)
$managedOu = ''
if ($ous.Count -gt 0) {
    foreach ($ou in $ous) { Write-Host "  $ou" }
    $match = $ous | Where-Object { $_ -match "(?i)^OU=$([regex]::Escape($ManagedOuHint))," -or $_ -match "(?i),OU=$([regex]::Escape($ManagedOuHint))," }
    if ($match) { $managedOu = @($match)[0] }
}
else {
    Write-Warning 'Nessuna OU elencabile (permessi insufficienti o dominio vuoto). Compila MWA_AD_MANAGED_OUS a mano.'
}
if (-not $managedOu) {
    $managedOu = "OU=$ManagedOuHint,$baseDn"
    Write-Warning "OU '$ManagedOuHint' non trovata: placeholder generato, correggilo prima dell'uso."
}

# --------------------------------------------------------------- env block ----
Write-Section 'Blocco MWA_AD_* da incollare (su PowerShell dell host connettore)'
$shortName = $dnsRoot.Split('.')[0]
$jwtSecret = New-RandomSecret -Bytes 48
$pageSecret = New-RandomSecret -Bytes 48
$stateDir = 'C:\ProgramData\MWA\state'
$trustStore = if ($caExported) { $caExported } else { 'C:\ProgramData\MWA\tls\domain-ca.pem' }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# ---- MWA AD Connector: configurazione rilevata il $(Get-Date -Format 'yyyy-MM-dd HH:mm') ----")
$lines.Add('# Personalizza i campi [SCEGLI]; i segreti generati sono NUOVI: trattali come credenziali.')
$lines.Add('')
$lines.Add('$env:MWA_AD_CUSTOMER_ID = "customer-lab"                  # [SCEGLI] boundary cliente MWA')
$lines.Add('$env:MWA_AD_TENANT_ID = "tenant-lab"                      # [SCEGLI] boundary tenant MWA')
$lines.Add("`$env:MWA_AD_CONNECTOR_ID = ""connector-$shortName-01""      # [SCEGLI] identita' del connettore")
$lines.Add("`$env:MWA_AD_FOREST_ID = ""forest-$shortName""               # [SCEGLI] boundary foresta")
$lines.Add("`$env:MWA_AD_DOMAIN_ID = ""domain-$shortName""               # [SCEGLI] boundary dominio")
$lines.Add("`$env:MWA_AD_BASE_DN = ""$baseDn""")
$lines.Add("`$env:MWA_AD_MANAGED_OUS = '[""$managedOu""]'")
$lines.Add("`$env:MWA_AD_DC_HOST = ""$DcHost""")
$lines.Add('$env:MWA_AD_DC_PORT = "636"')
$lines.Add('$env:MWA_AD_USE_LDAPS = "true"')
$lines.Add('$env:MWA_AD_LDAPS_REQUIRE_CERT = "true"')
$trustNote = if ($caExported) { '' } else { '  # ATTENZIONE: PEM non esportato, copialo o rilancia con -ExportCaTo' }
$lines.Add("`$env:MWA_AD_TRUST_STORE_PATH = ""$trustStore""$trustNote")
$lines.Add('$env:MWA_AD_AUTH_MODE = "simple"                          # unica modalita'' attiva in questa build')
$lines.Add("`$env:MWA_AD_BIND_USER = ""svc-mwa@$dnsRoot""              # [SCEGLI] service account dedicato (mai Domain Admin)")
$lines.Add('$env:MWA_AD_BIND_PASSWORD = "[DA-VAULT]"                  # segreto: non committare')
$lines.Add('$env:MWA_AD_SOURCE_ANCHOR_STRATEGY = "objectGuid"')
$lines.Add('$env:MWA_AD_ENABLE_MUTATIONS = "true"')
$lines.Add('$env:MWA_AD_ENABLE_PASSWORD_RESET = "false"               # true solo con LDAPS e approval')
$lines.Add('$env:MWA_AD_VALIDATION_MODE_ONLY = "true"                 # false per scritture reali')
$lines.Add("`$env:MWA_AD_STATE_DIR = ""$stateDir""")
$lines.Add('$env:MWA_AD_LOG_LEVEL = "INFO"')
$lines.Add('$env:MWA_AD_REQUEST_MAX_BYTES = "1048576"')
$lines.Add('$env:MWA_AD_CLOCK_SKEW_SECONDS = "60"')
$lines.Add('$env:MWA_AD_NONCE_TTL_SECONDS = "300"')
$lines.Add("`$env:MWA_AD_JWT_SECRET = ""$jwtSecret""")
$lines.Add('$env:MWA_AD_JWT_ISSUER = "mwa-trusted-agent"')
$lines.Add('$env:MWA_AD_JWT_AUDIENCE = "mwa-ad-connector"')
$lines.Add("`$env:MWA_AD_PAGE_TOKEN_SECRET = ""$pageSecret""")
$lines.Add('$env:MWA_AD_API_HOST = "127.0.0.1"')
$lines.Add('$env:MWA_AD_API_PORT = "8443"')
$lines.Add('$env:MWA_AD_RATE_LIMIT_CAPACITY = "100"')
$lines.Add('$env:MWA_AD_RATE_LIMIT_PER_SECOND = "10.0"')
$lines.Add('$env:MWA_AD_LDAP_CONNECT_TIMEOUT_SECONDS = "10.0"')
$lines.Add('$env:MWA_AD_LDAP_OPERATION_TIMEOUT_SECONDS = "30.0"')
$lines.Add('$env:MWA_AD_LDAP_POOL_SIZE = "10"')

$block = $lines -join [Environment]::NewLine
Write-Host ''
Write-Host $block -ForegroundColor Gray

if ($OutputPath) {
    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    [IO.File]::WriteAllText($OutputPath, $block + [Environment]::NewLine, [Text.Encoding]::ASCII)
    Write-Host ''
    Write-Host "Blocco salvato in: $OutputPath" -ForegroundColor Green
}

Write-Section 'Prossimi passi (host connettore)'
Write-Host '  1. Copia il blocco sopra nelle variabili d''ambiente dell''host connettore.'
Write-Host '  2. uv run python scripts/validate_config.py'
Write-Host '  3. uv run python scripts/lab_smoke.py'
Write-Host '  4. uv run python -m mwa_ad_connector.entrypoints.api'
Write-Host 'Guida completa: docs/operations/ad-setup.md'

Wait-IfPaused
exit 0
