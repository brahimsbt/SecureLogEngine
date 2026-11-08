"""Tests des constantes de models.py et des fichiers d'exemple."""

import csv
import json
from pathlib import Path

from log_engine.models import (
    CSV_COLUMNS,
    JSONL_REQUIRED_KEYS,
    KNOWN_EVENTS,
    SEVERITY_LEVELS,
    SUPPORTED_PROTOCOLS,
    TEXT_FIELDS,
    TEXT_SEPARATOR,
)

SAMPLES_DIR = Path("data/samples")


def test_severity_levels_are_ordered():
    """Les niveaux vont du moins grave au plus grave."""
    assert (
        SEVERITY_LEVELS["INFO"]
        < SEVERITY_LEVELS["WARNING"]
        < SEVERITY_LEVELS["ERROR"]
        < SEVERITY_LEVELS["CRITICAL"]
    )


def test_text_format_has_six_fields():
    """Le format texte compte six champs, du timestamp au payload."""
    assert len(TEXT_FIELDS) == 6
    assert TEXT_FIELDS[0] == "timestamp"
    assert TEXT_FIELDS[-1] == "payload"


def test_sample_files_exist():
    """Les quatre fichiers d'exemple sont présents."""
    for name in [
        "auth.log",
        "app_events.jsonl",
        "connections.csv",
        "blacklist.txt",
    ]:
        assert (SAMPLES_DIR / name).is_file()


def test_text_sample_follows_format():
    """Chaque ligne complète de auth.log respecte le format."""
    checked = 0
    with open(SAMPLES_DIR / "auth.log", encoding="utf-8") as file:
        for line in file:
            fields = line.rstrip("\n").split(TEXT_SEPARATOR, 5)
            if len(fields) != 6:
                continue
            assert fields[1].strip().upper() in SEVERITY_LEVELS
            assert fields[4].strip().upper() in KNOWN_EVENTS
            protocol = fields[2].split("/")[-1]
            assert protocol in SUPPORTED_PROTOCOLS
            checked += 1
    assert checked >= 20


def test_jsonl_sample_follows_format():
    """Chaque objet JSON complet utilise un niveau et un événement connus."""
    checked = 0
    with open(SAMPLES_DIR / "app_events.jsonl", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not JSONL_REQUIRED_KEYS.issubset(event):
                continue
            assert event["level"] in SEVERITY_LEVELS
            assert event["event"] in KNOWN_EVENTS
            checked += 1
    assert checked >= 10


def test_csv_sample_header():
    """L'en-tête du CSV correspond aux colonnes attendues."""
    with open(SAMPLES_DIR / "connections.csv", encoding="utf-8") as file:
        header = next(csv.reader(file))
    assert tuple(header) == CSV_COLUMNS
