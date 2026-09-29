"""JSON Schema export helpers for configuration and contracts."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mwa_ad_connector.config.settings import ConnectorSettings

logger = logging.getLogger(__name__)


def settings_json_schema() -> dict[str, Any]:
    """Return the JSON Schema for connector settings.

    Returns:
        JSON Schema mapping (secrets described, never populated).
    """
    return ConnectorSettings.model_json_schema()


def export_json_schema() -> dict[str, Any]:
    """Return the combined exportable schema document.

    Returns:
        Mapping with schema version and settings schema.
    """
    return {"schema_version": "1.0", "settings": settings_json_schema()}


def write_schema_file(path: str | Path) -> Path:
    """Write the schema document to disk.

    Args:
        path: Destination file path.

    Returns:
        Resolved destination path.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(export_json_schema(), indent=2) + "\n", encoding="utf-8")
    logger.info("schema_exported", extra={"path": str(destination)})
    return destination
