"""Redaction for logs, audit and evidence (Steps 8-9).

Passwords, secrets and tokens must never appear in logs, audit entries,
responses or exceptions. DNs are partially masked: the leaf structure is
kept for debugging while naming values and non-DC components are hidden.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "***REDACTED***"

# Exact attribute names treated as secrets (AD + generic, case-insensitive).
PASSWORD_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "unicodepwd",
        "userpassword",
        "password",
        "newpassword",
        "currentpassword",
        "oldpassword",
        "confirmpassword",
        "secret",
        "clientsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "privatekey",
        "credential",
        "credentials",
    }
)

# Substring fragments that mark a key as sensitive (case-insensitive).
_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "unicodepwd",
    "secret",
    "token",
    "privatekey",
    "credential",
)


def is_sensitive_key(key: str) -> bool:
    """Return True when ``key`` names a secret-bearing field."""
    lowered = key.strip().lower()
    if lowered in PASSWORD_FIELD_NAMES:
        return True
    return any(fragment in lowered for fragment in _SENSITIVE_SUBSTRINGS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(str(key)) else _redact_value(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def redact_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` with secret-bearing values replaced.

    Matching is case-insensitive on keys and recursive through nested
    mappings and sequences. Non-sensitive values are preserved as-is.
    """
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        name = str(key)
        redacted[name] = REDACTED if is_sensitive_key(name) else _redact_value(value)
    return redacted


def redact_dn_for_logs(dn: str) -> str:
    """Mask a DN for logs: hide naming values, keep DC components.

    Example: ``CN=Jane Doe,OU=Users,DC=lab,DC=local`` becomes
    ``CN=***,OU=***,DC=lab,DC=local``. Unparseable input yields ``REDACTED-DN``.
    """
    if not dn or not dn.strip():
        return "REDACTED-DN"
    parts = [part.strip() for part in dn.split(",")]
    masked: list[str] = []
    for part in parts:
        rdn_type, sep, _value = part.partition("=")
        if not sep:
            return "REDACTED-DN"
        if rdn_type.strip().upper() == "DC":
            masked.append(part)
        else:
            masked.append(f"{rdn_type.strip().upper()}=***")
    return ",".join(masked)


def hash_value(value: str | bytes) -> str:
    """Return the SHA-256 hex digest of a single attribute value."""
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hashlib.sha256(raw).hexdigest()


def attribute_hashes(attributes: Mapping[str, Any]) -> dict[str, list[str]]:
    """Return SHA-256 digests per attribute for verification evidence.

    Lets the cloud confirm observed values without ever transmitting or
    storing the values themselves. Single values are normalized to lists
    and output order is deterministic.
    """
    digests: dict[str, list[str]] = {}
    for name, values in attributes.items():
        items: Sequence[Any] = values if isinstance(values, (list, tuple)) else [values]
        digests[str(name)] = sorted(hash_value(item if isinstance(item, (str, bytes)) else str(item)) for item in items)
    return digests
