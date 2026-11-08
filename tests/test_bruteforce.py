"""Tests de la détection des attaques par force brute."""

import pytest

from log_engine.bruteforce import (
    detect_brute_force,
    group_attempts_by_ip,
    has_consecutive_failures,
)
from tests.test_aggregation import load_sample_records


def make_record(ip, event):
    """Crée un enregistrement de test."""
    return {"connection": (ip, 22, "TCP"), "event": event}


def test_group_attempts_by_ip():
    """Chaque IP garde sa propre suite d'échecs (True) et de succès (False)."""
    records = [
        make_record("1.1.1.1", "AUTH_FAILURE"),
        make_record("2.2.2.2", "AUTH_SUCCESS"),
        make_record("1.1.1.1", "HTTP_REQUEST"),
        make_record("1.1.1.1", "AUTH_SUCCESS"),
    ]
    assert group_attempts_by_ip(records) == {
        "1.1.1.1": [True, False],
        "2.2.2.2": [False],
    }


def test_threshold_reached():
    """Exactement threshold échecs d'affilée déclenchent la détection."""
    assert has_consecutive_failures([True, True, True], 3) is True


def test_threshold_not_reached():
    """Un échec de moins que le seuil ne déclenche rien."""
    assert has_consecutive_failures([True, True], 3) is False


def test_success_resets_the_streak():
    """Un succès au milieu remet le compteur à zéro."""
    assert (
        has_consecutive_failures([True, True, False, True, True], 3) is False
    )


def test_no_attempt():
    """Une liste vide ne déclenche rien."""
    assert has_consecutive_failures([], 3) is False


def test_other_ip_does_not_break_the_streak():
    """Un succès d'une autre IP n'interrompt pas la série d'un attaquant."""
    records = [
        make_record("6.6.6.6", "AUTH_FAILURE"),
        make_record("6.6.6.6", "AUTH_FAILURE"),
        make_record("1.1.1.1", "AUTH_SUCCESS"),
        make_record("6.6.6.6", "AUTH_FAILURE"),
    ]
    assert detect_brute_force(records, threshold=3) == {"6.6.6.6"}


def test_invalid_threshold():
    """Un seuil inférieur à 1 est refusé."""
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=0)


def test_detection_on_sample_files():
    """Le seuil change les IP détectées dans les fichiers d'exemple."""
    records = load_sample_records()
    assert detect_brute_force(records) == {"203.0.113.45"}
    assert detect_brute_force(records, threshold=3) == {
        "203.0.113.45",
        "198.51.100.23",
    }
    assert detect_brute_force(records, threshold=7) == set()
