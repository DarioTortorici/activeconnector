# MWA AD Connector container (Step 18, conditional)
#
# Adopt ONLY if gMSA/Kerberos/LDAPS validation passes for the target
# orchestrator (see packaging/container/README.md). Default remains the
# Windows Service packaging.

FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS base
SHELL ["powershell", "-Command"]

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY packaging/config-templates/connector.example.json ./config/connector.json

RUN pip install --no-cache-dir uv; `
    uv sync --frozen --no-dev; `
    New-Item -ItemType Directory -Path /app/logs -Force | Out-Null

ENV MWA_CONNECTOR_CONFIG=/app/config/connector.json
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 `
  CMD powershell -Command "try { (Invoke-RestMethod http://localhost:8443/api/v1/health).status -eq 'HEALTHY' } catch { exit 1 }"

ENTRYPOINT ["uv", "run", "python", "-m", "mwa_ad_connector.entrypoints.api"]
