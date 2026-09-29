# Windows Service packaging (Step 18)

Installs the connector as a Windows Service running under a least-privilege
identity (gMSA preferred, never Domain Admin, never a static password).

## Layout

```text
%CONNECTOR_HOME%\
  service.xml        # WinSW descriptor (this folder)
  install.ps1        # install + ACL + config validation
  venv\              # uv-managed virtualenv (uv sync --frozen)
  src\               # connector sources (or installed wheel)
  logs\              # service stdout + JSON logs (Modify for service identity)
```

## Install

```powershell
.\install.ps1 -ConnectorHome 'C:\Program Files\MWA\ADConnector' `
  -ConfigPath 'C:\ProgramData\MWA\connector.json' `
  -ServiceAccount 'LAB\gmsa-adconn$'
MWAADConnector.exe install
Start-Service MWAADConnector
```

## Harden

- Service account: gMSA authorized only on the connector host; deny
  interactive logon where applicable.
- File ACLs: service identity gets ReadAndExecute on the home, Modify on
  `logs` only (applied by `install.ps1`).
- TLS trust: install the lab/prod CA chain in the machine store; LDAPS
  certificate validation stays fail-closed (`ldaps_require_cert: true`).
- Restart policy: automatic with backoff (see `service.xml`); the worker
  shuts down gracefully (in-flight message completes before exit).

## Verify

```powershell
Invoke-RestMethod http://127.0.0.1:8443/api/v1/health
# readiness requires a token: 200 ready / 503 not ready (fail-closed)
```

## Uninstall

```powershell
Stop-Service MWAADConnector
MWAADConnector.exe uninstall
```
