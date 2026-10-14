from __future__ import annotations

from watchpost.detection.mitre import (
    TACTICS,
    TECHNIQUE_TACTICS,
    TECHNIQUES,
    technique_name,
    technique_tactics,
)


def test_every_named_technique_has_valid_tactics() -> None:
    assert set(TECHNIQUE_TACTICS) == set(TECHNIQUES)
    for tactics in TECHNIQUE_TACTICS.values():
        assert tactics
        assert set(tactics) <= set(TACTICS)


def test_sub_techniques_fall_back_to_their_parent() -> None:
    assert technique_tactics("T1110.001") == ("TA0006",)
    assert technique_tactics("T1110.999") == ("TA0006",)
    assert technique_name("T1110.999") == "Brute Force"
    assert technique_tactics("T9999") == ()
    assert technique_name("T9999") is None
