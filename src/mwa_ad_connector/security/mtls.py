"""mTLS helpers: certificate thumbprint extraction and optional binding (Step 8)."""

from __future__ import annotations

import hashlib
import hmac


def extract_thumbprint(cert_der: bytes, *, algorithm: str = "sha256") -> str:
    """Return the lowercase hex digest of DER-encoded client certificate bytes.

    Args:
        cert_der: DER bytes of the peer certificate (as provided by the TLS layer).
        algorithm: Hash algorithm accepted by :mod:`hashlib` (default ``sha256``).

    Raises:
        ValueError: On empty certificate bytes or unknown hash algorithm.
    """
    if not cert_der:
        raise ValueError("empty certificate bytes")
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"unsupported thumbprint algorithm: {algorithm!r}") from exc
    digest.update(cert_der)
    return digest.hexdigest().lower()


def verify_mtls_binding(
    *,
    presented_thumbprint: str | None,
    expected_thumbprint: str | None,
    enforce: bool = False,
) -> bool:
    """Optionally verify that the presented client certificate matches the binding.

    Args:
        presented_thumbprint: Thumbprint extracted from the TLS peer certificate.
        expected_thumbprint: Thumbprint bound to the caller (e.g. from config).
        enforce: When True, a missing expected binding fails closed.

    Returns:
        True when no binding is configured (and not enforced) or when the
        presented thumbprint matches; False otherwise. Comparison is
        constant-time and case-insensitive.
    """
    if expected_thumbprint is None:
        return not enforce
    if presented_thumbprint is None:
        return False
    return hmac.compare_digest(presented_thumbprint.strip().lower(), expected_thumbprint.strip().lower())
