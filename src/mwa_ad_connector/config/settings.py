"""Secure configuration via Pydantic Settings (Step 4).

Fail-fast: missing boundaries, out-of-scope OUs, insecure channels,
incoherent auth settings or an enabled cloud relay without credentials raise
at startup before any LDAP bind. No production defaults for customer data,
DNs or secrets.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SourceAnchorStrategy = Literal["objectGuid", "msDsConsistencyGuid", "objectSid", "custom"]
AuthMode = Literal["simple", "kerberos", "gmsa"]

_REDACTED = "***REDACTED***"


class ConnectorSettings(BaseSettings):
    """Connector runtime settings loaded from environment / .env / files.

    Attributes:
        customer_id: Customer boundary (required, no default).
        tenant_id: Tenant boundary (required, no default).
        connector_id: Connector identity bound to tokens and envelopes.
        forest_id: Forest boundary.
        domain_id: Domain boundary.
        base_dn: Search/mutation root; all managed OUs must sit below it.
        managed_ous: Allowlisted OU DNs for every mutation scope check.
        dc_host: Pinned or preferred DC hostname (redacted in health output).
        dc_port: LDAP/LDAPS port.
        use_ldaps: Require LDAPS for all connections.
        ldaps_require_cert: Fail closed on untrusted/expired certificates.
        trust_store_path: PEM trust bundle path for LDAPS validation.
        auth_mode: LDAP bind mechanism.
        bind_user: Service account UPN/DN for simple bind (None for gMSA/Kerberos).
        bind_password: Service account secret (never logged).
        source_anchor_strategy: Explicit Entra source-anchor strategy per profile.
        enable_mutations: Master kill-switch for all write capabilities.
        enable_password_reset: Separate kill-switch for password reset.
        validation_mode_only: When True, force dry-run preflight for risky ops.
        log_level: Structured logging level label.
        request_max_bytes: Inbound payload limit.
        clock_skew_seconds: Allowed timestamp skew for envelopes/tokens.
        nonce_ttl_seconds: Anti-replay nonce reservation lifetime.
        jwt_secret: Caller-token HMAC key (required, never logged).
        jwt_issuer: Expected caller-token issuer.
        jwt_audience: Expected caller-token audience.
        jwt_algorithms: Allowlisted JWT signature algorithms.
        page_token_secret: HMAC key for opaque page tokens (required).
        api_host: API bind address.
        api_port: API bind port.
        rate_limit_capacity: Token-bucket burst capacity.
        rate_limit_per_second: Token-bucket refill rate.
        state_dir: Directory holding the SQLite operation/audit stores.
        ldap_connect_timeout_seconds: LDAPS TCP connect timeout.
        ldap_operation_timeout_seconds: LDAPS per-operation timeout.
        ldap_pool_size: Maximum concurrent LDAPS connections.
        servicebus_enabled: Select the Azure Service Bus relay over in-memory.
        servicebus_connection_string: Service Bus credential (never logged).
        servicebus_command_queue: Queue carrying inbound command envelopes.
        servicebus_result_queue: Queue carrying outbound operation results.
    """

    model_config = SettingsConfigDict(extra="forbid", env_prefix="MWA_AD_", env_nested_delimiter="__")

    customer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    connector_id: str = Field(min_length=1, max_length=128)
    forest_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    base_dn: str = Field(min_length=3, max_length=512)
    managed_ous: list[str] = Field(min_length=1)
    dc_host: str = Field(min_length=1, max_length=256)
    dc_port: int = Field(default=636, ge=1, le=65535)
    use_ldaps: bool = True
    ldaps_require_cert: bool = True
    trust_store_path: str | None = Field(default=None, max_length=1024)
    auth_mode: AuthMode = "gmsa"
    bind_user: str | None = Field(default=None, max_length=256)
    bind_password: SecretStr | None = None
    source_anchor_strategy: SourceAnchorStrategy = "objectGuid"
    enable_mutations: bool = True
    enable_password_reset: bool = False
    validation_mode_only: bool = True
    log_level: str = Field(default="INFO", max_length=16)
    request_max_bytes: int = Field(default=65536, ge=1024, le=1048576)
    clock_skew_seconds: int = Field(default=300, ge=30, le=3600)
    nonce_ttl_seconds: int = Field(default=600, ge=60, le=86400)
    jwt_secret: SecretStr
    jwt_issuer: str = Field(default="mwa-trusted-agent", max_length=256)
    jwt_audience: str = Field(default="mwa-ad-connector", max_length=256)
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["HS256"], min_length=1, max_length=4)
    page_token_secret: SecretStr
    api_host: str = Field(default="127.0.0.1", max_length=256)
    api_port: int = Field(default=8443, ge=1, le=65535)
    rate_limit_capacity: int = Field(default=100, ge=1, le=100000)
    rate_limit_per_second: float = Field(default=10.0, gt=0, le=100000)
    state_dir: str = Field(default=".mwa-state", max_length=1024)
    ldap_connect_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    ldap_operation_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    ldap_pool_size: int = Field(default=10, ge=1, le=1000)
    servicebus_enabled: bool = False
    servicebus_connection_string: SecretStr | None = None
    servicebus_command_queue: str = Field(default="ad-commands", min_length=1, max_length=256)
    servicebus_result_queue: str = Field(default="ad-results", min_length=1, max_length=256)

    @field_validator("base_dn", "managed_ous")
    @classmethod
    def _normalize_dn(cls, value: str | list[str]) -> str | list[str]:
        """Strip whitespace from DN inputs.

        Args:
            value: Single DN or list of DNs.

        Returns:
            Normalized DN value(s).
        """
        if isinstance(value, list):
            return [item.strip() for item in value]
        return value.strip()

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        """Uppercase the log level label.

        Args:
            value: Raw level label.

        Returns:
            Uppercase level label.
        """
        return value.upper()

    @model_validator(mode="after")
    def _check_fail_fast_invariants(self) -> Self:
        """Enforce cross-field security invariants at startup.

        Returns:
            The validated settings.

        Raises:
            ValueError: On scope incoherence or insecure/secret misuse.
        """
        base = self.base_dn.lower()
        for ou in self.managed_ous:
            if ou.lower() != base and not ou.lower().endswith("," + base):
                raise ValueError(f"managed OU outside base_dn: {ou}")
        if self.use_ldaps and self.dc_port not in (636, 3269):
            raise ValueError("LDAPS requires port 636 (or 3269 for GC SSL)")
        if not self.use_ldaps and self.enable_password_reset:
            raise ValueError("password reset requires LDAPS (use_ldaps=true)")
        if self.auth_mode == "simple" and not self.bind_user:
            raise ValueError("simple auth_mode requires bind_user")
        if self.auth_mode in ("kerberos", "gmsa") and self.bind_password is not None:
            raise ValueError(f"{self.auth_mode} auth_mode must not carry a static bind_password")
        if self.auth_mode == "simple" and self.bind_password is None:
            raise ValueError("simple auth_mode requires bind_password")
        if self.servicebus_enabled and self.servicebus_connection_string is None:
            raise ValueError("servicebus_enabled requires servicebus_connection_string")
        return self

    def model_dump_redacted(self) -> dict[str, object]:
        """Dump settings with secrets and host details redacted.

        Returns:
            Redacted settings mapping safe for logs/diagnostics.
        """
        data: dict[str, object] = self.model_dump(mode="python")
        data["bind_password"] = "***REDACTED***" if self.bind_password is not None else None
        data["dc_host"] = "***REDACTED***"
        data["bind_user"] = "***REDACTED***" if self.bind_user else None
        data["jwt_secret"] = _REDACTED
        data["page_token_secret"] = _REDACTED
        data["servicebus_connection_string"] = _REDACTED if self.servicebus_connection_string is not None else None
        return data


__all__ = ["AuthMode", "ConnectorSettings", "SourceAnchorStrategy"]
