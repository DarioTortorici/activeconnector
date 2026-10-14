# Part 2 (runs on the promoted DC, after reboot): OUs, users, group, LDAPS, delegation.
# Expects dc_ldaps_cert.ps1 and Grant-MwaDelegation.ps1 in the same download dir (fileUris).
param([string]$SvcPassword, [string]$TestPassword)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = 'DC=corp,DC=test,DC=local'

foreach ($ou in @('Managed', 'Utenti-Test', 'Gruppi-Test')) {
    $dn = "OU=$ou,$base"
    try { Get-ADOrganizationalUnit -Identity $dn | Out-Null }
    catch { New-ADOrganizationalUnit -Name $ou -ProtectedFromAccidentalDeletion $false }
}

$upn = 'svc-mwa@corp.test.local'
$svc = ConvertTo-SecureString $SvcPassword -AsPlainText -Force
if (Get-ADUser 'svc-mwa' -ErrorAction SilentlyContinue) {
    Set-ADAccountPassword 'svc-mwa' -Reset -NewPassword $svc
    Set-ADUser 'svc-mwa' -UserPrincipalName $upn -Enabled $true -PasswordNeverExpires $true
}
else {
    New-ADUser 'svc-mwa' -Path "OU=Managed,$base" -UserPrincipalName $upn `
        -AccountPassword $svc -Enabled $true -PasswordNeverExpires $true
}

$t = ConvertTo-SecureString $TestPassword -AsPlainText -Force
try { Get-ADUser 'tuser1' | Out-Null }
catch {
    New-ADUser 'TestUser1' -SamAccountName 'tuser1' -UserPrincipalName 'tuser1@corp.test.local' `
        -Path "OU=Utenti-Test,$base" -AccountPassword $t -Enabled $true
}

try { Get-ADGroup 'G-IT' | Out-Null }
catch { New-ADGroup 'G-IT' -GroupScope Global -Path "OU=Gruppi-Test,$base" }
Add-ADGroupMember 'G-IT' 'tuser1' -ErrorAction SilentlyContinue

& '.\dc_ldaps_cert.ps1' -Ensure -TrustForLdaps -RestartService `
    -ExportPublicPem 'C:\temp\dc-ldaps-cert.pem'

& '.\Grant-MwaDelegation.ps1' -OuDn "OU=Managed,$base"
& '.\Grant-MwaDelegation.ps1' -OuDn "OU=Utenti-Test,$base"

Write-Host 'DC bootstrap part 2 done'
