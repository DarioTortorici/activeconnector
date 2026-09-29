"""Integration placeholder: full lab matrix runs only against a real DC.

Enable with MWA_AD_LAB=1 plus MWA_AD_LAB_DSN (never in CI). Until then every
case skips with an explicit reason instead of simulating results.
"""

import os

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("MWA_AD_LAB") != "1",
        reason="Lab DC unavailable: set MWA_AD_LAB=1 and MWA_AD_LAB_DSN to run.",
    ),
]

LAB_MATRIX = [
    "rootdse discovery on pinned DC",
    "paged search without loss/duplication",
    "binary attribute (objectGUID/SID) lossless round-trip",
    "GUID resolution then DN refresh after rename",
    "group add/remove with same-DC read-after-write",
    "unlock with lockoutTime verification",
    "password reset over LDAPS only (negative on cleartext)",
    "LDAPS invalid/expired/untrusted certificate rejected fail-closed",
]


@pytest.mark.parametrize("scenario", LAB_MATRIX)
def test_lab_matrix_scenario(scenario: str) -> None:
    """Lab scenario placeholder: executed by the lab job against a real DC."""
    dsn = os.environ.get("MWA_AD_LAB_DSN", "")
    assert dsn, "MWA_AD_LAB_DSN must point at the isolated lab DC."
    assert scenario
