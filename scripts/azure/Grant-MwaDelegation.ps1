# Grant svc-mwa Read/Write on the connector's writable USER attributes.
# Idempotent: skips property ACEs already granted. Paged schema read (no 1000-entry truncation).
param(
    [string]$Server = 'localhost',
    [string]$OuDn = 'OU=Utenti-Test,DC=corp,DC=test,DC=local',
    [string]$SvcSam = 'svc-mwa'
)
$ErrorActionPreference = 'Stop'

$attrs = @(
    'displayName', 'givenName', 'sn', 'mail', 'title', 'department', 'company',
    'telephoneNumber', 'mobile', 'physicalDeliveryOfficeName', 'description'
)

$sid = (New-Object System.Security.Principal.NTAccount($SvcSam)).Translate(
    [System.Security.Principal.SecurityIdentifier])

$rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE")
$schemaDn = [string]$rootDse.Properties['schemaNamingContext'][0]
$schema = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$schemaDn")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($schema)
$searcher.Filter = '(objectClass=attributeSchema)'
$searcher.PageSize = 500
$searcher.PropertiesToLoad.AddRange(@('lDAPDisplayName', 'schemaIDGUID')) | Out-Null

$propGuids = @{}
foreach ($result in $searcher.FindAll()) {
    $name = [string]$result.Properties['lDAPDisplayName'][0]
    if ($attrs -contains $name) {
        $bytes = [byte[]]$result.Properties['schemaIDGUID'][0]
        $propGuids[$name] = New-Object Guid (,$bytes)
    }
}
Write-Host ("resolved {0}/{1} attributes" -f $propGuids.Count, $attrs.Count)
foreach ($a in $attrs) { if (-not $propGuids.ContainsKey($a)) { Write-Warning "no schemaIDGUID for $a" } }

$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$OuDn")
$acl = $de.ObjectSecurity
$existing = @{}
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.IdentityReference.Value -eq $sid.Value -and $rule.ObjectType -ne [Guid]::Empty) {
        $existing[$rule.ObjectType.ToString()] = $true
    }
}
$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
$added = 0
foreach ($name in $attrs) {
    if (-not $propGuids.ContainsKey($name)) { continue }
    $guid = $propGuids[$name]
    if ($existing.ContainsKey($guid.ToString())) { Write-Host "  = already granted: $name"; continue }
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty,WriteProperty',
        [System.Security.AccessControl.AccessControlType]'Allow',
        $guid,
        $inheritance)
    $acl.AddAccessRule($rule)
    Write-Host "  + added: $name"
    $added++
}
$de.ObjectSecurity = $acl
$de.CommitChanges()
Write-Host "Done. ACE added: $added"
