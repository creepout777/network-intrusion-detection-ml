"""Deterministic attack-family typing contract checks."""

import attack_typing_metadata_regression_check as checks


def test_attack_typing_regression_checks():
    assert checks.main() == 0
