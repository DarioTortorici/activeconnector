<#
.SYNOPSIS
    Diagnostica (e opzionalmente crea) il certificato server LDAPS di un Domain Controller.

.DESCRIPTION
    Da eseguire SUL Domain Controller, PowerShell come amministratore.
    Default read-only: elenca i certificati del LocalMachine\My con SAN, EKU,
    scadenza e presenza chiave privata, e indica se esiste un certificato
    adatto a LDAPS per il FQDN del DC.
    Con -Ensure crea un certificato self-signed (solo laboratorio) se manca.
    Con -RestartService riavvia il servizio AD DS (NTDS) per far rilevare il
    certificato (breve indisponibilita' del DC).
    Con -ExportPublicPem esporta il certificato pubblico in PEM quando e'
    self-signed (nel lab la radice di fiducia e' il certificato stesso).

.PARAMETER Fqdn
    FQDN che deve comparire in SAN/CN del certificato. Default: FQDN del DC.

.PARAMETER Ensure
    Crea un certificato self-signed con Server Authentication se nessun
    certificato adatto esiste. SOLO LAB: non usare in produzione.

.PARAMETER RestartService
    Riavvia il servizio NTDS dopo la creazione del certificato.

.PARAMETER TrustForLdaps
    Rende il certificato utilizzabile da LDAPS: lo aggiunge a
    LocalMachine\Root (trusted) e concede a SYSTEM la lettura della chiave
    privata. Da usare con certificati self-signed (lab).

.PARAMETER ExportPublicPem
    Esporta il certificato pubblico in PEM nel percorso indicato. Default:
    Desktop dell'utente corrente (\dc-ldaps-cert.pem). Solo se self-signed;
    per CA aziendali esporta la radice dal connector host.

.PARAMETER Pause
    Attende Invio prima di uscire.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\dc_ldaps_cert.ps1
    powershell -ExecutionPolicy Bypass -File .\scripts\dc_ldaps_cert.ps1 `
        -Ensure -RestartService -ExportPublicPem C:\temp\dc-ldaps.cer.pem -Pause

.NOTES
    Diagnostica: non modifica nulla se -Ensure non e' specificato.
    Il riavvio di NTDS interrompe brevemente i servizi di directory del DC.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Fqdn = '',
    [switch]$Ensure,
    [switch]$RestartService,
    [switch]$TrustForLdaps,
    [string]$ExportPublicPem = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'dc-ldaps-cert.pem'),
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

function Get-SanNames {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $names = @()
    $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($ext) {
        $text = $ext.Format($true)
        foreach ($part in ($text -split "`r?`n")) {
            if ($part -match 'DNS Name=(.+)$') { $names += $Matches[1].Trim() }
        }
    }
    return $names
}

function Get-EkuOids {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $oids = @()
    $list = $Cert.EnhancedKeyUsageList
    for ($i = 0; $i -lt $list.Count; $i++) {
        $item = $list[$i]
        if ($item.PSObject.Properties.Match('ObjectId').Count -gt 0 -and $item.ObjectId) {
            $oids += [string]$item.ObjectId
        }
        elseif ($item.PSObject.Properties.Match('Value').Count -gt 0 -and $item.Value) {
            $oids += [string]$item.Value
        }
    }
    return $oids
}

function Test-ServerAuth {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $eku = @(Get-EkuOids -Cert $Cert)
    if ($eku.Count -eq 0) { return $true }
    return ($eku -contains '1.3.6.1.5.5.7.3.1')
}

function Export-PemCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$Path)
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $base64 = [Convert]::ToBase64String($Cert.RawData)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
        [void]$builder.AppendLine($base64.Substring($i, [Math]::Min(64, $base64.Length - $i)))
    }
    [void]$builder.AppendLine('-----END CERTIFICATE-----')
    [IO.File]::WriteAllText($Path, $builder.ToString(), [Text.Encoding]::ASCII)
}

function Grant-PrivateKeyToSystem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $granted = $false
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        if ($rsa -and ($rsa -is [System.Security.Cryptography.RSACng])) {
            $keyPath = Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\{0}" -f $rsa.Key.UniqueName)
            if (Test-Path -LiteralPath $keyPath) {
                $acl = Get-Acl -LiteralPath $keyPath
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    'NT AUTHORITY\SYSTEM', 'Read', 'Allow')
                $acl.AddAccessRule($rule) | Out-Null
                Set-Acl -LiteralPath $keyPath -AclObject $acl
                $granted = $true
            }
        }
    }
    catch { }
    if (-not $granted) {
        try {
            $container = $Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
            $keyPath = Join-Path $env:ProgramData ("Microsoft\Crypto\RSA\MachineKeys\{0}" -f $container)
            if (Test-Path -LiteralPath $keyPath) {
                $acl = Get-Acl -LiteralPath $keyPath
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    'NT AUTHORITY\SYSTEM', 'Read', 'Allow')
                $acl.AddAccessRule($rule) | Out-Null
                Set-Acl -LiteralPath $keyPath -AclObject $acl
                $granted = $true
            }
        }
        catch { }
    }
    return $granted
}

# ------------------------------------------------------------- DC preflight ----
$ntds = Get-Service -Name NTDS -ErrorAction SilentlyContinue
if (-not $ntds) {
    Write-Host 'ERRORE: servizio NTDS non trovato: questo non sembra un Domain Controller.' -ForegroundColor Red
    Wait-IfPaused
    exit 1
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Sessione NON elevata: la lettura del LocalMachine\My puo'' fallire e -Ensure non puo'' creare certificati.'
}

if (-not $Fqdn) {
    $Fqdn = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
}
Write-Host "DC            : $([System.Net.Dns]::GetHostName())"
Write-Host "FQDN atteso   : $Fqdn"
Write-Host "Servizio NTDS : $($ntds.Status)"

# ---------------------------------------------------------------- inventory ----
Write-Host ''
Write-Host '== Certificati in LocalMachine\My' -ForegroundColor Cyan
$certificates = @(Get-ChildItem Cert:\LocalMachine\My)
if ($certificates.Count -eq 0) {
    Write-Host '  (nessun certificato nel Personal del computer)' -ForegroundColor Yellow
}
$suitable = @()
foreach ($cert in $certificates) {
    try {
        $san = @(Get-SanNames -Cert $cert)
        $serverAuth = Test-ServerAuth -Cert $cert
        $expired = $cert.NotAfter -le (Get-Date)
        $nameMatch = ($san -contains $Fqdn) -or ($cert.Subject -match [regex]::Escape("CN=$Fqdn"))
        $ok = $cert.HasPrivateKey -and (-not $expired) -and $serverAuth -and $nameMatch
        if ($ok) { $suitable += $cert }
        Write-Host ('  [{0}] {1}' -f $(if ($ok) { 'OK' } else { '--' }), $cert.Subject)
        Write-Host ("       thumbprint: {0}" -f $cert.Thumbprint)
        Write-Host ("       scadenza  : {0}   chiave privata: {1}   serverAuth: {2}" -f $cert.NotAfter.ToString('yyyy-MM-dd'), $cert.HasPrivateKey, $serverAuth)
        Write-Host ("       SAN       : {0}" -f $(if ($san.Count -gt 0) { $san -join ', ' } else { '(nessuna)' }))
        if ($ok) { Write-Host ("       idoneo    : SAN/CN coprono {0}" -f $Fqdn) -ForegroundColor Green }
    }
    catch {
        Write-Host ('  [??] {0}' -f $cert.Subject) -ForegroundColor Yellow
        Write-Host ("       analisi fallita: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}
Write-Host ''
if ($suitable.Count -gt 0) {
    Write-Host "Certificati idonei per LDAPS: $($suitable.Count)" -ForegroundColor Green
}
else {
    Write-Host 'Nessun certificato idoneo per LDAPS.' -ForegroundColor Yellow
}

# ------------------------------------------------------------------- ensure ----
if ($suitable.Count -eq 0 -and $Ensure) {
    Write-Host ''
    Write-Host "== Creazione certificato self-signed per $Fqdn (solo LAB)" -ForegroundColor Cyan
    $newCert = New-SelfSignedCertificate `
        -DnsName $Fqdn `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(2)
    Write-Host "Creato: $($newCert.Thumbprint)" -ForegroundColor Green
    $suitable = @($newCert)
}
elseif ($suitable.Count -eq 0) {
    Write-Host ''
    Write-Host 'Suggerimento: rilancia con -Ensure -RestartService per creare un certificato self-signed (solo lab),'
    Write-Host 'oppure richiedi un certificato Server Authentication alla CA aziendale per il DC.'
}

if ($TrustForLdaps -and $suitable.Count -gt 0) {
    $chosen = $suitable[0]
    Write-Host ''
    Write-Host '== Trust LDAPS (self-signed)' -ForegroundColor Cyan
    try {
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
        $rootStore.Open('ReadWrite')
        $already = $rootStore.Certificates.Find('FindByThumbprint', $chosen.Thumbprint, $false).Count -gt 0
        if (-not $already) { $rootStore.Add($chosen) }
        $rootStore.Close()
        Write-Host 'Certificato presente in LocalMachine\Root (trusted).' -ForegroundColor Green
    }
    catch {
        Write-Warning "Aggiunta a LocalMachine\Root fallita: $($_.Exception.Message)"
    }
    $keyOk = Grant-PrivateKeyToSystem -Cert $chosen
    if ($keyOk) {
        Write-Host 'Chiave privata: accesso in lettura concesso a SYSTEM.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Chiave privata: impossibile concedere accesso via script; usa certlm.msc > Gestisci chiave privata (aggiungi SYSTEM, Read).'
    }
    if ($chosen.Issuer -eq $chosen.Subject) {
        Write-Host 'Nota: su un DC il Root store viene sincronizzato dal dominio; per uso stabile pubblica la CA in AD (certutil -dspublish).' -ForegroundColor Yellow
    }
}

if ($suitable.Count -gt 0) {
    if ($RestartService) {
        Write-Warning 'Riavvio del servizio NTDS (AD DS): il DC sara'' brevemente indisponibile.'
        Restart-Service -Name NTDS -Force
        Start-Sleep -Seconds 15
        Write-Host "NTDS: $((Get-Service -Name NTDS).Status)"
    }
    else {
        Write-Host 'Nota: se LDAPS non risponde, riavvia il servizio directory: Restart-Service NTDS -Force' -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------- export ----
if ($ExportPublicPem -and $suitable.Count -gt 0) {
    $chosen = $suitable[0]
    if ($chosen.Issuer -eq $chosen.Subject) {
        Export-PemCertificate -Cert $chosen -Path $ExportPublicPem
        Write-Host "Certificato self-signed esportato in: $ExportPublicPem" -ForegroundColor Green
        Write-Host 'Copia questo PEM sull''host connettore e usa quel percorso come MWA_AD_TRUST_STORE_PATH.'
    }
    else {
        Write-Warning ("Il certificato e'' emesso da una CA ({0}): NON esportare la foglia." -f $chosen.Issuer)
        Write-Warning 'Sull''host connettore usa scripts/discover_ad_env.ps1 -ExportCaTo per esportare la CA radice dalla catena LDAPS.'
    }
}

# ------------------------------------------------------------ local LDAPS ----
Write-Host ''
Write-Host '== Verifica locale handshake LDAPS (dal DC stesso)' -ForegroundColor Cyan
$localOk = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect($Fqdn, 636, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne(5000)) {
        $tcp.EndConnect($async)
        $permissive = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $sslPolicyErrors) return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $permissive)
        $ssl.AuthenticateAsClient($Fqdn)
        $remote = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        Write-Host "Handshake OK  : $($remote.Subject)" -ForegroundColor Green
        $ssl.Dispose()
        $localOk = $true
    }
    else {
        Write-Host 'TCP 636: timeout (servizio in avvio?)' -ForegroundColor Yellow
    }
    $tcp.Close()
}
catch {
    Write-Host "Handshake LDAPS fallito: $($_.Exception.Message)" -ForegroundColor Yellow
}
if (-not $localOk -and $suitable.Count -gt 0) {
    Write-Host 'LDAPS non risponde: riavvia il servizio directory (Restart-Service NTDS -Force) e riesegui lo script.' -ForegroundColor Yellow
}

Wait-IfPaused
exit 0
