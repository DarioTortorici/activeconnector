# Contributing

## Branches

- `feat/<step>-<topic>` for features, `fix/<topic>` for bug fixes, `docs/<topic>` for docs,
  `spike/<topic>` for time-boxed spikes (never merged to main as implementation).
- One step at a time per the operating plan; do not anticipate future steps.

## Before code

- Write or update the ADR first (`docs/adr/`), then the implementation doc
  (`docs/implementation/`), then code + tests.
- Small, verifiable PRs; consider splitting above ~500 changed lines.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
Example: `feat(step-2): add domain operation invariants`.

## Quality gate (must be green)

```bash
uv sync --frozen --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest tests/unit tests/contract --cov=src/mwa_ad_connector --cov-report=term-missing --cov-fail-under=80
```

Additional rules: full type hints, Google Style docstrings, no `print` (structured logging only),
Pydantic v2 with `extra="forbid"` on contracts, files ideally <400 lines.
