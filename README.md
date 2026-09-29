# MWA AD Connector (on-prem)

Outbound-only on-premises Active Directory connector for MWA. Exposes allowlisted, versioned AD
capabilities over a local API and an outbound command worker. LDAP stays behind the
`DirectoryGateway` port; `objectGUID` is the stable identity; mutations are verified with
read-after-write on the pinned DC.

## Quickstart (Windows + Linux)

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```powershell
# Windows
.\scripts\bootstrap.ps1
```

```bash
# Linux
./scripts/bootstrap.sh
```

Manual:

```bash
uv sync --frozen --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest tests/unit tests/contract --cov=src/mwa_ad_connector --cov-report=term-missing --cov-fail-under=80
```

Validate configuration (fail-fast, redacted output):

```bash
uv run python scripts/validate_config.py --help
```

## Structure

- `src/mwa_ad_connector/domain/` — enums, errors, identifiers, objects, capabilities, operations, evidence, health.
- `src/mwa_ad_connector/application/ports/` — `DirectoryGateway`, operation/audit/transport/clock/nonce ports.
- `src/mwa_ad_connector/config/` — Pydantic Settings, domain/forest/connector profiles, startup validation.
- `tests/fakes/` — in-memory `FakeDirectoryGateway` for deterministic contract tests.
- `docs/` — architecture, ADRs, runbooks (Step 0 baseline).
- `scripts/` — bootstrap + config validation helpers.
- `packaging/` — Windows Service / container / config templates (later steps).

## Non-objectives (initial release)

No desktop GUI, no Lazarus/Pascal, no OpenRSAT port, no arbitrary LDAP query/PowerShell/shell
endpoints, no generic PATCH over LDAP attributes, no inbound ports, no Domain Admin requirement,
no `nTSecurityDescriptor`/ACL-delegation management, no on-prem Entra convergence verdicts, no
hardcoded sync timing, no universal source-anchor assumption, no multi-forest HA.
