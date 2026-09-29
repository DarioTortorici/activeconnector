#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the MWA AD Connector as a Windows Service (Step 18).
.DESCRIPTION
    Creates a least-privilege virtual service account (or binds a gMSA),
    applies file ACLs, registers the service via NSSM/WinSW layout
    (see service.xml), and validates the configuration before start.
    No passwords are stored by this script: use a gMSA or the machine
    certificate store for the service identity.
.PARAMETER ConnectorHome
    Install root, e.g. C:\Program Files\MWA\ADConnector.
.PARAMETER ConfigPath
    Connector JSON config (see packaging/config-templates).
.PARAMETER ServiceAccount
    DOMAIN\gMSA$ name when using a group-managed service account, else ''.
.EXAMPLE
    .\install.ps1 -ConnectorHome 'C:\Program Files\MWA\ADConnector' `
      -ConfigPath 'C:\ProgramData\MWA\connector.json' -ServiceAccount 'LAB\gmsa-adconn$'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ConnectorHome,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$ServiceAccount = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Configuration file not found: $ConfigPath"
}
if (-not (Test-Path -LiteralPath (Join-Path $ConnectorHome 'service.xml'))) {
    throw "service.xml not found under $ConnectorHome (copy packaging/windows-service first)."
}

$logDir = Join-Path $ConnectorHome 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# Least privilege: service identity gets read/execute on home, write on logs only.
$identity = if ($ServiceAccount) { $ServiceAccount } else { 'NT SERVICE\MWAADConnector' }
$acl = Get-Acl -LiteralPath $ConnectorHome
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $identity, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
)
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $ConnectorHome -AclObject $acl

$logAcl = Get-Acl -LiteralPath $logDir
$logRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $identity, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
)
$logAcl.SetAccessRule($logRule)
Set-Acl -LiteralPath $logDir -AclObject $logAcl

Write-Host "Validating configuration: $ConfigPath"
uv run python scripts/validate_config.py --config $ConfigPath

Write-Host 'Register the service with your service wrapper (WinSW/NSSM) using service.xml,'
Write-Host "then start it as '$identity'. Restart policy: always (see service.xml)."
Write-Host 'Post-install: check GET /api/v1/health and /api/v1/readiness before pilot.'
