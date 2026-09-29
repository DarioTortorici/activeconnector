"""Read-only lab smoke test against the configured AD.

This script **never mutates** the directory: it validates the configuration,
binds over LDAPS, reads RootDSE/capabilities, and optionally resolves a user
or group or lists group members. All output is redacted; failures exit non-zero.

Usage (PowerShell):
    $env:MWA_AD_JWT_SECRET = "lab-only-jwt-secret"
    $env:MWA_AD_PAGE_TOKEN_SECRET = "lab-only-page-secret"
    uv run python scripts/lab_smoke.py
    uv run python scripts/lab_smoke.py --resolve-user jdoe@lab.example.test
    uv run python scripts/lab_smoke.py --resolve-group "GRP-Operators"
    uv run python scripts/lab_smoke.py --list-members 7e565f72-8274-4cb8-b77a-7dad17a1b432
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mwa_ad_connector.api.dependencies import CallerContextFallback  # noqa: E402
from mwa_ad_connector.composition import build_runtime  # noqa: E402
from mwa_ad_connector.config.settings import ConnectorSettings  # noqa: E402
from mwa_ad_connector.config.validation import validate_startup  # noqa: E402
from mwa_ad_connector.security.redaction import redact_dict, redact_dn_for_logs  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Read-only smoke test against the configured AD (never mutates the directory)."
    )
    parser.add_argument("--resolve-user", default=None, help="UPN or sAMAccountName to resolve.")
    parser.add_argument("--resolve-group", default=None, help="Group name to resolve.")
    parser.add_argument("--list-members", default=None, help="Group objectGUID whose members are listed.")
    return parser.parse_args(argv)


def _emit(payload: Any) -> None:  # noqa: ANN401 - JSON-serializable diagnostics.
    """Write one redacted JSON document to stdout."""
    sys.stdout.write(json.dumps(payload, indent=2, default=str, ensure_ascii=False) + "\n")


def _redact_result(result: Any) -> Any:  # noqa: ANN401 - response-shaped mapping.
    """Redact DNs and sensitive keys from a capability result."""
    if not isinstance(result, dict):
        return result
    redacted = redact_dict(result)
    if isinstance(redacted.get("distinguished_name"), str):
        redacted["distinguished_name"] = redact_dn_for_logs(redacted["distinguished_name"])
    members = redacted.get("members")
    if isinstance(members, list):
        for member in members:
            if isinstance(member, dict) and isinstance(member.get("distinguished_name"), str):
                member["distinguished_name"] = redact_dn_for_logs(member["distinguished_name"])
    return redacted


def _caller(settings: ConnectorSettings) -> CallerContextFallback:
    """Build a local read-only caller context bound to this connector."""
    return CallerContextFallback(
        subject="lab-smoke",
        issuer="lab-smoke",
        audience=settings.connector_id,
        tenant_id=settings.tenant_id,
        customer_id=settings.customer_id,
        connector_id=settings.connector_id,
        scopes=[],
    )


async def _invoke(
    runtime: Any, caller: Any, capability: str, target: dict[str, Any], parameters: dict[str, Any]
) -> Any:  # noqa: ANN401
    """Execute one read capability and return the redacted result."""
    result = await runtime.api_service.execute_capability(
        capability=capability,
        target=target,
        parameters=parameters,
        caller=caller,
        idempotency_key=None,
        correlation_id="lab-smoke",
        ticket_id=None,
        dry_run=False,
    )
    return _redact_result(result)


async def _run(args: argparse.Namespace) -> int:
    """Run the read-only smoke sequence."""
    settings = ConnectorSettings()  # type: ignore[call-arg]
    validate_startup(settings)
    runtime = build_runtime(settings)
    caller = _caller(settings)
    try:
        _emit({"ping": await runtime.ping()})
        domain_target = {"domain_id": settings.domain_id}
        _emit({"directory.rootdse.read": await _invoke(runtime, caller, "directory.rootdse.read", domain_target, {})})
        _emit(
            {
                "directory.capabilities.read": await _invoke(
                    runtime, caller, "directory.capabilities.read", domain_target, {}
                )
            }
        )
        if args.resolve_user:
            value = str(args.resolve_user)
            identifier_type = "UPN" if "@" in value else "SAM_ACCOUNT_NAME"
            target = {
                "object_type": "USER",
                "domain_id": settings.domain_id,
                "identifier_type": identifier_type,
                "identifier_value": value,
            }
            _emit({"user.resolve": await _invoke(runtime, caller, "user.resolve", target, {})})
        if args.resolve_group:
            target = {
                "object_type": "GROUP",
                "domain_id": settings.domain_id,
                "identifier_type": "GROUP_NAME",
                "identifier_value": str(args.resolve_group),
            }
            _emit({"group.resolve": await _invoke(runtime, caller, "group.resolve", target, {})})
        if args.list_members:
            target = {"object_type": "GROUP", "object_guid": str(args.list_members)}
            _emit(
                {"group.members.list": await _invoke(runtime, caller, "group.members.list", target, {"page_size": 50})}
            )
        _emit({"mode": "read-only", "mutations_attempted": 0})
        return 0
    finally:
        runtime.close()


def main(argv: list[str] | None = None) -> int:
    """Run the smoke test.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Process exit code (0 success, 1 failure).
    """
    args = parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except Exception as exc:  # noqa: BLE001 - CLI boundary reports a redacted summary.
        code = getattr(exc, "code", None)
        sys.stderr.write(f"lab smoke failed: {type(exc).__name__}{f' ({code})' if code else ''}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
