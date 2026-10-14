# Verify the DC lab setup (run via az vm run-command on the DC).
# Prints machine-readable markers consumed by the deploy workflow.
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory
if (Get-ADUser tuser1 -ErrorAction SilentlyContinue) { 'TUSER1=OK' } else { 'TUSER1=MISSING' }
if (Get-ADUser svc-mwa -ErrorAction SilentlyContinue) { 'SVCMWA=OK' } else { 'SVCMWA=MISSING' }
if (Test-Path 'C:\temp\dc-ldaps-cert.pem') { 'PEM=OK' } else { 'PEM=MISSING' }
try {
    $sid = (Get-ADUser svc-mwa).SID.Value
    $ou = New-Object System.DirectoryServices.DirectoryEntry('LDAP://OU=Utenti-Test,DC=corp,DC=test,DC=local')
    $n = ($ou.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
          Where-Object { $_.IdentityReference.Value -eq $sid }).Count
    "ACE=$n"
}
catch { 'ACE=ERR' }
