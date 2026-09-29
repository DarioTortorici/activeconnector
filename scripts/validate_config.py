"""Validate connector configuration fail-fast with redacted output.

Usage:
    python scripts/validate_config.py [--schema-out PATH]

Loads ConnectorSettings from the environment, runs startup validation,
and prints a redacted summary. Exits non-zero on any violation.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mwa_ad_connector.config.schema import write_schema_file  # noqa: E402
from mwa_ad_connector.config.settings import ConnectorSettings  # noqa: E402
from mwa_ad_connector.config.validation import ConfigurationError, validate_startup  # noqa: E402

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate_config")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(description="Validate MWA AD connector configuration.")
    parser.add_argument("--schema-out", type=str, default=None, help="Write JSON schema to PATH and exit.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run configuration validation.

    Args:
        argv: Optional argument list for testing.

    Returns:
        Process exit code (0 valid, 1 invalid).
    """
    args = parse_args(argv)
    if args.schema_out:
        destination = write_schema_file(args.schema_out)
        logger.info("schema written to %s", destination)
        return 0
    try:
        settings = ConnectorSettings()  # type: ignore[call-arg]
    except Exception as exc:
        logger.error("settings load failed: %s", exc)
        return 1
    try:
        validate_startup(settings)
    except ConfigurationError as exc:
        logger.error("configuration invalid: %s", exc)
        return 1
    logger.info("configuration valid:\n%s", json.dumps(settings.model_dump_redacted(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
