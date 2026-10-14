# Part 1 (runs on the fresh DC VM): install AD DS and promote a new lab forest.
# Ends with an automatic reboot; the extension reporting failure afterwards is expected.
param([string]$DsrmPassword)
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
$dsrm = ConvertTo-SecureString $DsrmPassword -AsPlainText -Force
Install-ADDSForest -DomainName 'corp.test.local' -DomainNetbiosName 'CORP' `
  -SafeModeAdministratorPassword $dsrm -Force
