# Configure the app VM: prereqs, repo, connector env, CA trust, connector service.
param(
    [string]$BindPassword,
    [string]$JwtSecret,
    [string]$PageTokenSecret,
    [string]$CaPemB64
)
$ErrorActionPreference = 'Stop'

# 1) DC resolution (VNet DNS already points at the DC; hosts as belt and braces)
$hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
$entry = '10.20.1.4    DC01.corp.test.local DC01'
$hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
if ($hostsContent -notmatch 'DC01\.corp\.test\.local') { Add-Content $hostsPath $entry }

# 2) Prerequisites: git, Python 3.12, uv
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    $g = "$env:TEMP\Git-Setup.exe"
    Invoke-WebRequest 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe' -OutFile $g
    Start-Process $g '/VERYSILENT /NORESTART' -Wait
    $env:Path = "C:\Program Files\Git\cmd;$env:Path"
}
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    $p = "$env:TEMP\python-setup.exe"
    Invoke-WebRequest 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe' -OutFile $p
    Start-Process $p '/quiet InstallAllUsers=1 PrependPath=1' -Wait
    $env:Path = "C:\Program Files\Python312;C:\Program Files\Python312\Scripts;$env:Path"
}
py -m pip install --upgrade pip uv

# 3) Repo (public; carries the read-projection fix)
if (-not (Test-Path 'C:\src\activeconnector\pyproject.toml')) {
    New-Item -ItemType Directory 'C:\src' -Force | Out-Null
    git clone https://github.com/DarioTortorici/activeconnector.git C:\src\activeconnector
} else {
    git -C C:\src\activeconnector pull --ff-only
}
Set-Location C:\src\activeconnector
uv sync

# 4) Config (secrets arrive only via protected extension settings, never the repo)
New-Item -ItemType Directory 'C:\ProgramData\MWA\tls', 'C:\ProgramData\MWA\state' -Force | Out-Null
[IO.File]::WriteAllBytes('C:\ProgramData\MWA\tls\domain-ca.pem', [Convert]::FromBase64String($CaPemB64))

$envTemplate = @'
$env:MWA_AD_CUSTOMER_ID = "customer-lab"
$env:MWA_AD_TENANT_ID = "tenant-lab"
$env:MWA_AD_CONNECTOR_ID = "connector-corp-01"
$env:MWA_AD_FOREST_ID = "forest-corp"
$env:MWA_AD_DOMAIN_ID = "domain-corp"
$env:MWA_AD_BASE_DN = "DC=corp,DC=test,DC=local"
$env:MWA_AD_MANAGED_OUS = '["OU=Managed,DC=corp,DC=test,DC=local","OU=Utenti-Test,DC=corp,DC=test,DC=local"]'
$env:MWA_AD_DC_HOST = "DC01.corp.test.local"
$env:MWA_AD_DC_PORT = "636"
$env:MWA_AD_USE_LDAPS = "true"
$env:MWA_AD_LDAPS_REQUIRE_CERT = "true"
$env:MWA_AD_TRUST_STORE_PATH = "C:\ProgramData\MWA\tls\domain-ca.pem"
$env:MWA_AD_AUTH_MODE = "simple"
$env:MWA_AD_BIND_USER = "svc-mwa@corp.test.local"
$env:MWA_AD_BIND_PASSWORD = "__BIND_PASSWORD__"
$env:MWA_AD_SOURCE_ANCHOR_STRATEGY = "objectGuid"
$env:MWA_AD_ENABLE_MUTATIONS = "true"
$env:MWA_AD_ENABLE_PASSWORD_RESET = "false"
$env:MWA_AD_VALIDATION_MODE_ONLY = "false"
$env:MWA_AD_STATE_DIR = "C:\ProgramData\MWA\state"
$env:MWA_AD_LOG_LEVEL = "INFO"
$env:MWA_AD_REQUEST_MAX_BYTES = "1048576"
$env:MWA_AD_CLOCK_SKEW_SECONDS = "60"
$env:MWA_AD_NONCE_TTL_SECONDS = "300"
$env:MWA_AD_JWT_SECRET = "__JWT_SECRET__"
$env:MWA_AD_JWT_ISSUER = "mwa-trusted-agent"
$env:MWA_AD_JWT_AUDIENCE = "mwa-ad-connector"
$env:MWA_AD_PAGE_TOKEN_SECRET = "__PAGE_TOKEN_SECRET__"
$env:MWA_AD_API_HOST = "127.0.0.1"
$env:MWA_AD_API_PORT = "8443"
$env:MWA_AD_RATE_LIMIT_CAPACITY = "100"
$env:MWA_AD_RATE_LIMIT_PER_SECOND = "10.0"
$env:MWA_AD_LDAP_CONNECT_TIMEOUT_SECONDS = "10.0"
$env:MWA_AD_LDAP_OPERATION_TIMEOUT_SECONDS = "30.0"
$env:MWA_AD_LDAP_POOL_SIZE = "10"
'@
$envContent = $envTemplate.Replace('__BIND_PASSWORD__', $BindPassword).Replace('__JWT_SECRET__', $JwtSecret).Replace('__PAGE_TOKEN_SECRET__', $PageTokenSecret)
Set-Content 'C:\ProgramData\MWA\mwa-ad-env.ps1' $envContent -Encoding UTF8

# 5) Connector as a scheduled task (SYSTEM, at startup) + start now
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `". 'C:\ProgramData\MWA\mwa-ad-env.ps1'; & 'C:\src\activeconnector\.venv\Scripts\python.exe' -m mwa_ad_connector.entrypoints.api`"" `
    -WorkingDirectory 'C:\src\activeconnector'
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'MWA-AD-Connector' `
    -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName 'MWA-AD-Connector'

# 6) Wait for health
for ($i = 0; $i -lt 30; $i++) {
    try {
        $h = Invoke-RestMethod 'http://127.0.0.1:8443/api/v1/health' -TimeoutSec 5
        if ($h.status -eq 'HEALTHY') { Write-Host 'connector HEALTHY'; break }
    } catch { }
    Start-Sleep -Seconds 10
}
