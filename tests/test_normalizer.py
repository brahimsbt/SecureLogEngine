"""Tests de la normalisation des enregistrements."""

from log_engine.filters import (
    keep_known_severity,
    remove_empty_lines,
    remove_invalid,
)
from log_engine.ingestion.readers import read_sources
from log_engine.normalizer import normalize_record, normalize_records
from log_engine.parsers import parse_text_line


def make_record(severity, user, event):
    """Crée un enregistrement de test."""
    return {
        "severity": severity,
        "connection": ("10.0.0.22", 50990, "TCP"),
        "user": user,
        "event": event,
        "payload": {},
    }


def test_fields_are_uniformized():
    """Niveau et événement en majuscules, utilisateur en minuscules."""
    record = normalize_record(
        make_record(" warning ", " Bob ", "auth_failure")
    )
    assert record["severity"] == "WARNING"
    assert record["user"] == "bob"
    assert record["event"] == "AUTH_FAILURE"


def test_user_none_stays_none():
    """Un événement sans utilisateur garde None."""
    record = normalize_record(make_record("INFO", None, "SERVICE_START"))
    assert record["user"] is None


def test_summary_is_built_with_f_string():
    """Le résumé lisible est construit à partir des champs normalisés."""
    record = normalize_record(make_record("error", "Carol", "access_denied"))
    assert record["summary"] == "[ERROR] 10.0.0.22 carol ACCESS_DENIED"
    record = normalize_record(make_record("INFO", None, "SERVICE_START"))
    assert record["summary"] == "[INFO] 10.0.0.22 - SERVICE_START"


def test_original_record_is_not_modified():
    """La normalisation crée une copie et ne modifie pas l'original."""
    original = make_record("warning", "Bob", "auth_failure")
    normalize_record(original)
    assert original["severity"] == "warning"
    assert "summary" not in original


def test_normalize_records_uses_map():
    """normalize_records renvoie un objet map paresseux."""
    result = normalize_records([make_record("info", "A", "x")])
    assert type(result) is map
    assert next(result)["severity"] == "INFO"


def load_auth_records():
    """Lit et parse auth.log, puis retire les lignes vides et invalides."""
    lines = remove_empty_lines(read_sources(["data/samples/auth.log"]))
    records = []
    for source, number, line in lines:
        records.append(parse_text_line(line))
    return list(remove_invalid(records))


def test_without_normalization_dirty_lines_are_lost():
    """Sans normalisation, 'warning' et 'Info' sont rejetés par le filtre."""
    records = keep_known_severity(load_auth_records())
    assert len(list(records)) == 21


def test_with_normalization_dirty_lines_are_kept():
    """Avec normalisation avant le filtre, les 2 lignes sales sont gardées."""
    records = keep_known_severity(normalize_records(load_auth_records()))
    records = list(records)
    assert len(records) == 23
    bob_records = []
    for record in records:
        if record["user"] == "bob":
            bob_records.append(record["event"])
    assert bob_records == [
        "AUTH_FAILURE",
        "AUTH_SUCCESS",
        "AUTH_FAILURE",
        "AUTH_SUCCESS",
    ]
