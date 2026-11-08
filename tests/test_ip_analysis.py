"""Tests de l'analyse des adresses IP."""

import pytest

from log_engine.ip_analysis import (
    active_ips,
    compare_with_blacklist,
    error_ips,
    load_blacklist,
)
from tests.test_aggregation import load_sample_records


def make_record(ip, severity):
    """Crée un enregistrement de test."""
    return {"connection": (ip, 22, "TCP"), "severity": severity}


RECORDS = [
    make_record("10.0.0.1", "INFO"),
    make_record("10.0.0.1", "INFO"),
    make_record("10.0.0.2", "WARNING"),
    make_record("10.0.0.3", "CRITICAL"),
]


def test_load_blacklist_returns_frozenset():
    """La blacklist est un frozenset de 4 adresses."""
    blacklist = load_blacklist("data/samples/blacklist.txt")
    assert type(blacklist) is frozenset
    assert blacklist == {
        "198.51.100.77",
        "203.0.113.10",
        "192.0.2.150",
        "192.0.2.99",
    }


def test_blacklist_cannot_be_modified():
    """Un frozenset ne peut pas être modifié."""
    blacklist = load_blacklist("data/samples/blacklist.txt")
    with pytest.raises(AttributeError):
        blacklist.add("1.2.3.4")


def test_load_blacklist_ignores_empty_lines(tmp_path):
    """Les lignes vides du fichier sont ignorées."""
    path = tmp_path / "blacklist.txt"
    path.write_text("1.1.1.1\n\n  2.2.2.2  \n", encoding="utf-8")
    assert load_blacklist(str(path)) == {"1.1.1.1", "2.2.2.2"}


def test_active_ips_are_unique():
    """Une IP vue plusieurs fois n'apparaît qu'une fois dans le set."""
    assert active_ips(RECORDS) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_error_ips_from_warning():
    """Par défaut, les IP à partir de WARNING sont retenues."""
    assert error_ips(RECORDS) == {"10.0.0.2", "10.0.0.3"}


def test_error_ips_with_other_minimum():
    """On peut choisir un autre niveau minimum."""
    assert error_ips(RECORDS, "CRITICAL") == {"10.0.0.3"}


def test_set_operations():
    """Les quatre opérations d'ensembles donnent les résultats attendus."""
    blacklist = frozenset({"1.1.1.1", "2.2.2.2"})
    active = {"2.2.2.2", "3.3.3.3"}
    errors = {"2.2.2.2", "3.3.3.3"}
    result = compare_with_blacklist(blacklist, active, errors)
    assert result["blacklisted_and_active"] == {"2.2.2.2"}
    assert result["suspects_not_blacklisted"] == {"3.3.3.3"}
    assert result["new_blacklist"] == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert result["in_only_one"] == {"1.1.1.1", "3.3.3.3"}


def test_analysis_on_sample_files():
    """Analyse des IP sur les fichiers d'exemple."""
    records = load_sample_records()
    blacklist = load_blacklist("data/samples/blacklist.txt")
    active = active_ips(records)
    errors = error_ips(records)
    result = compare_with_blacklist(blacklist, active, errors)

    assert len(active) == 10
    assert len(errors) == 8
    assert result["blacklisted_and_active"] == {"198.51.100.77", "192.0.2.150"}
    assert "203.0.113.45" in result["suspects_not_blacklisted"]
    assert len(result["new_blacklist"]) == 10
