#!/usr/bin/env bash
# Bootstrap the MWA AD Connector dev environment on Linux/macOS.
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest tests/unit tests/contract --cov=src/mwa_ad_connector --cov-report=term-missing --cov-fail-under=80
