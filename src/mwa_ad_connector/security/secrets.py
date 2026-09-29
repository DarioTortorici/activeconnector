"""Secret handling: env/file loading, SecretStr use, clearable buffers (Step 8).

Secrets (e.g. the password-reset value) must live in memory for the
shortest possible time, never be logged, and be zeroed after use.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import SecretStr


class SecretError(Exception):
    """Raised when a secret cannot be loaded safely (fail-closed)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.code = "SECRET_LOAD_FAILED"


def read_secret_file(path: str | Path, *, encoding: str = "utf-8") -> SecretStr:
    """Read a secret from a file (Docker/K8s secret style).

    Only the file owner may read it; trailing newlines are stripped.
    Raises :class:`SecretError` when the file is missing or unreadable.
    """
    candidate = Path(path)
    try:
        text = candidate.read_text(encoding=encoding)
    except OSError as exc:
        raise SecretError(f"cannot read secret file {candidate}") from exc
    return SecretStr(text.strip())


def load_secret_from_env_or_file(
    env_var: str,
    *,
    file_env_var: str | None = None,
    encoding: str = "utf-8",
) -> SecretStr | None:
    """Load a secret from an env var or, preferentially, from a secret file.

    Args:
        env_var: Environment variable holding the raw secret value.
        file_env_var: Environment variable holding the secret *file path*.
            When set and non-empty it takes precedence over ``env_var``.
        encoding: Encoding used when reading the secret file.

    Returns:
        The secret, or None when neither source is configured.
    """
    file_holder = file_env_var or f"{env_var}_FILE"
    file_path = os.environ.get(file_holder, "").strip()
    if file_path:
        return read_secret_file(file_path, encoding=encoding)
    raw = os.environ.get(env_var, "")
    if not raw:
        return None
    return SecretStr(raw)


def clear_buffer(buffer: bytearray) -> None:
    """Zero a mutable buffer in place (best-effort secret hygiene)."""
    for index in range(len(buffer)):
        buffer[index] = 0


def reveal(secret: SecretStr | None) -> str | None:
    """Reveal a :class:`SecretStr` for immediate use at a trust boundary.

    Callers must not log, store or embed the returned value; prefer
    passing ``SecretStr`` through and revealing at the last moment.
    """
    return secret.get_secret_value() if secret is not None else None
