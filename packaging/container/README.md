# Container packaging (Step 18, conditional)

The container image is **conditional**: adopt it only after validating that
LDAPS works from the target orchestrator without weakening authentication.
gMSA/Kerberos are not supported in this build (they fail fast at startup).
Otherwise use `packaging/windows-service`.

## Build

```powershell
docker build -f packaging/container/Dockerfile -t mwa-ad-connector:0.1.0 .
```

## Run (lab)

```powershell
docker run --rm -p 8443:8443 `
  -v C:\ProgramData\MWA\connector.json:C:\app\config\connector.json `
  mwa-ad-connector:0.1.0
```

## Pre-adoption checklist

- [ ] gMSA in-container is not supported in this build; only revisit if/when
      gMSA lands (a ccgmsa credential spec must then deliver working Kerberos
      tickets in-container).
- [ ] LDAPS trust chain validates (fail-closed) from inside the container.
- [ ] No secrets baked into layers (`docker history` shows none; config mounted).
- [ ] `/api/v1/health` and `/api/v1/readiness` behave as on the host install.
- [ ] Log shipping preserves redaction (no secret material in `docker logs`).

If any item fails, stop and keep the Windows Service packaging.
