#Requires -Version 5.1
<#
.SYNOPSIS
  Bootstrap the MWA AD Connector dev environment on Windows.
.DESCRIPTION
  Installs uv (if missing), syncs dependencies, and runs the quality gate.
#>
$ErrorActionPreference = "Stop"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "Installing uv..."
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
}

uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest tests/unit tests/contract --cov=src/mwa_ad_connector --cov-report=term-missing --cov-fail-under=80
