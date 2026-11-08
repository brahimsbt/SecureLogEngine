"""Tests du comptage des événements."""

from collections import defaultdict

from log_engine.aggregation import (
    count_by_event,
    count_by_severity,
    count_by_user,
)
from log_engine.filters import keep_known_severity, remove_invalid
from log_engine.ingestion.readers import read_sources
from log_engine.normalizer import normalize_records
from log_engine.router import route_line

RECORDS = [
    {"user": "alice", "severity": "INFO", "event": "AUTH_SUCCESS"},
    {"user": "bob", "severity": "WARNING", "event": "AUTH_FAILURE"},
    {"user": "bob", "severity": "WARNING", "event": "AUTH_FAILURE"},
    {"user": None, "severity": "INFO", "event": "SERVICE_START"},
]


def test_count_by_user_ignores_none():
    """Chaque utilisateur est compté, les événements sans utilisateur non."""
    assert count_by_user(RECORDS) == {"alice": 1, "bob": 2}


def test_count_by_severity():
    """Les événements sont comptés par niveau de sévérité."""
    assert count_by_severity(RECORDS) == {"INFO": 2, "WARNING": 2}


def test_count_by_event():
    """Les événements sont comptés par type."""
    assert count_by_event(RECORDS) == {
        "AUTH_SUCCESS": 1,
        "AUTH_FAILURE": 2,
        "SERVICE_START": 1,
    }


def test_result_is_a_defaultdict():
    """Une clé absente vaut 0 au lieu de lever une KeyError."""
    counts = count_by_user(RECORDS)
    assert type(counts) is defaultdict
    assert counts["inconnu"] == 0


def test_empty_list_gives_empty_count():
    """Aucun enregistrement donne un comptage vide."""
    assert count_by_event([]) == {}


def load_sample_records():
    """Lit, route, filtre et normalise les trois fichiers d'exemple."""
    paths = [
        "data/samples/auth.log",
        "data/samples/app_events.jsonl",
        "data/samples/connections.csv",
    ]
    records = []
    for source, number, line in read_sources(paths):
        records.append(route_line(source, line))
    records = remove_invalid(records)
    records = normalize_records(records)
    records = keep_known_severity(records)
    return list(records)


def test_counts_on_sample_files():
    """Comptages obtenus sur les fichiers d'exemple."""
    records = load_sample_records()
    assert len(records) == 49
    assert count_by_user(records) == {
        "admin": 9,
        "bob": 6,
        "alice": 4,
        "root": 3,
        "carol": 3,
        "dave": 2,
    }
    assert count_by_severity(records) == {
        "INFO": 22,
        "WARNING": 22,
        "ERROR": 3,
        "CRITICAL": 2,
    }
    assert count_by_event(records)["AUTH_FAILURE"] == 12
