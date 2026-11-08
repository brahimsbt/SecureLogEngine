"""Tests de la détection des attaques par force brute."""

import pytest

from log_engine.bruteforce import (
    describe_attacks,
    detect_brute_force,
    group_attempts_by_ip,
    has_consecutive_failures,
)
from log_engine.pipeline import DEFAULT_FILES, process_files


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
    records = list(process_files(DEFAULT_FILES))
    assert detect_brute_force(records) == {"203.0.113.45"}
    assert detect_brute_force(records, threshold=3) == {
        "203.0.113.45",
        "198.51.100.23",
    }
    assert detect_brute_force(records, threshold=7) == set()


def make_attempt(ip, event, user="admin"):
    """Crée une tentative de connexion de test avec un utilisateur."""
    return {"connection": (ip, 22, "TCP"), "event": event, "user": user}


def test_several_attackers_at_the_same_time():
    """Deux attaquants entremêlés sont détectés tous les deux."""
    records = []
    for i in range(3):
        records.append(make_attempt("6.6.6.6", "AUTH_FAILURE"))
        records.append(make_attempt("7.7.7.7", "AUTH_FAILURE"))
    assert detect_brute_force(records, threshold=3) == {"6.6.6.6", "7.7.7.7"}


def test_threshold_of_one():
    """Avec un seuil de 1, un seul échec suffit."""
    records = [make_attempt("6.6.6.6", "AUTH_FAILURE")]
    assert detect_brute_force(records, threshold=1) == {"6.6.6.6"}


def test_success_then_failures():
    """Des échecs après un succès sont comptés à partir de zéro."""
    records = [make_attempt("6.6.6.6", "AUTH_SUCCESS")]
    for i in range(3):
        records.append(make_attempt("6.6.6.6", "AUTH_FAILURE"))
    assert detect_brute_force(records, threshold=3) == {"6.6.6.6"}
    assert describe_attacks(records, threshold=3)[0]["succeeded"] is False


def test_attack_without_success():
    """Une attaque qui n'aboutit jamais est marquée comme échouée."""
    records = []
    for i in range(5):
        records.append(make_attempt("6.6.6.6", "AUTH_FAILURE", "root"))
    assert describe_attacks(records) == [
        {
            "ip": "6.6.6.6",
            "users": {"root"},
            "failures": 5,
            "succeeded": False,
        }
    ]


def test_attack_on_several_accounts():
    """Tous les comptes visés par l'attaquant sont listés."""
    records = [
        make_attempt("6.6.6.6", "AUTH_FAILURE", "admin"),
        make_attempt("6.6.6.6", "AUTH_FAILURE", "root"),
        make_attempt("6.6.6.6", "AUTH_FAILURE", "admin"),
    ]
    attack = describe_attacks(records, threshold=3)[0]
    assert attack["users"] == {"admin", "root"}
    assert attack["failures"] == 3


def test_describe_attacks_with_no_attack():
    """Aucune attaque détectée donne une liste vide."""
    assert describe_attacks([make_attempt("1.1.1.1", "AUTH_SUCCESS")]) == []


def test_describe_attacks_on_sample_files():
    """L'attaque de 203.0.113.45 sur admin a réussi après 6 échecs."""
    records = list(process_files(DEFAULT_FILES))
    assert describe_attacks(records) == [
        {
            "ip": "203.0.113.45",
            "users": {"admin"},
            "failures": 6,
            "succeeded": True,
        }
    ]
