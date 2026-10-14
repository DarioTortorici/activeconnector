# Verify the lab from the app VM: health, LDAPS, resolve, dry-run update.
param([string]$JwtSecret)
$ErrorActionPreference = 'Stop'

function New-MwaJwt([string]$secret) {
    $now = [DateTimeOffset]::UtcNow
    $b64 = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $header = & $b64 '{"alg":"HS256","typ":"JWT"}'
    $payloadObj = @{
        sub = 'identity-agent'; iss = 'mwa-trusted-agent'; aud = 'mwa-ad-connector'
        tenant_id = 'tenant-lab'; connector_id = 'connector-corp-01'
        scopes = @('ad.user.read', 'ad.user.attributes.write')
        iat = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(15).ToUnixTimeSeconds()
        jti = [guid]::NewGuid().ToString('N')
    }
    $payload = & $b64 ($payloadObj | ConvertTo-Json -Compress)
    $data = "$header.$payload"
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($secret))
    $sig = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($data))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "$data.$sig"
}

$h = Invoke-RestMethod 'http://127.0.0.1:8443/api/v1/health' -TimeoutSec 10
Write-Host ("health: " + $h.status)

$t = Test-NetConnection 'DC01.corp.test.local' -Port 636
Write-Host ("LDAPS 636: " + $t.TcpTestSucceeded)

$jwt = New-MwaJwt $JwtSecret
$headers = @{
    Authorization       = "Bearer $jwt"
    'X-Tenant-ID'       = 'tenant-lab'
    'X-Connector-ID'    = 'connector-corp-01'
    'X-Request-Timestamp' = [DateTime]::UtcNow.ToString('o')
    'X-Request-Nonce'   = [guid]::NewGuid().ToString('N')
    'X-Correlation-ID'  = [guid]::NewGuid().ToString('N')
}
$resolve = Invoke-RestMethod -Method Post 'http://127.0.0.1:8443/api/v1/users:resolve' `
    -Headers $headers -ContentType 'application/json' `
    -Body '{"object_type":"USER","domain_id":"domain-corp","identifier_type":"SAM_ACCOUNT_NAME","identifier_value":"tuser1"}'
Write-Host ("resolve object_guid: " + $resolve.object_guid)

$headers['Idempotency-Key'] = [guid]::NewGuid().ToString('N')
$headers['X-Ticket-ID'] = 'verify-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$dry = Invoke-RestMethod -Method Post ("http://127.0.0.1:8443/api/v1/users/$($resolve.object_guid):update-attributes") `
    -Headers $headers -ContentType 'application/json' `
    -Body '{"attributes":{"givenName":"Mario","sn":"Rossi"},"dry_run":true}'
Write-Host ("dry-run: " + $dry.state + " / " + $dry.disposition)
