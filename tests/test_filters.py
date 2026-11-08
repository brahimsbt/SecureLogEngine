"""Tests du nettoyage des données."""

from log_engine.filters import (
    keep_known_severity,
    remove_empty_lines,
    remove_invalid,
)
from log_engine.ingestion.readers import read_sources
from log_engine.parsers import parse_text_line


def test_remove_empty_lines():
    """Les lignes vides ou faites d'espaces sont retirées."""
    lines = [
        ("auth.log", 1, "ligne 1"),
        ("auth.log", 2, ""),
        ("auth.log", 3, "   "),
        ("auth.log", 4, "ligne 4"),
    ]
    assert list(remove_empty_lines(lines)) == [
        ("auth.log", 1, "ligne 1"),
        ("auth.log", 4, "ligne 4"),
    ]


def test_remove_invalid():
    """filter(None, ...) retire les None et garde les dictionnaires."""
    records = [{"severity": "INFO"}, None, {"severity": "ERROR"}, None]
    assert list(remove_invalid(records)) == [
        {"severity": "INFO"},
        {"severity": "ERROR"},
    ]


def test_keep_known_severity():
    """Un niveau de sévérité inconnu est exclu."""
    records = [
        {"severity": "INFO"},
        {"severity": "DEBUG"},
        {"severity": "CRITICAL"},
        {"severity": "erreur"},
    ]
    assert list(keep_known_severity(records)) == [
        {"severity": "INFO"},
        {"severity": "CRITICAL"},
    ]


def test_filters_are_lazy():
    """filter() ne calcule rien tant qu'on ne demande pas d'élément."""
    result = remove_invalid([None, {"severity": "INFO"}])
    assert type(result) is filter
    assert next(result) == {"severity": "INFO"}


def test_cleaning_auth_log():
    """Sur auth.log : ligne vide, lignes invalides et niveaux mal écrits."""
    lines = remove_empty_lines(read_sources(["data/samples/auth.log"]))
    lines = list(lines)
    assert len(lines) == 25

    records = []
    for source, number, line in lines:
        records.append(parse_text_line(line))
    assert len(records) == 25

    records = keep_known_severity(remove_invalid(records))
    assert len(list(records)) == 21
