"""Chaîne complète de traitement des logs, en flux."""

from log_engine.filters import (
    keep_known_severity,
    remove_empty_lines,
    remove_invalid,
)
from log_engine.ingestion.readers import read_sources
from log_engine.normalizer import normalize_records
from log_engine.router import route_line

DEFAULT_FILES = [
    "data/samples/auth.log",
    "data/samples/app_events.jsonl",
    "data/samples/connections.csv",
]


def process_files(paths: list[str]):
    """Lit, route, nettoie et normalise les logs sans tout charger en RAM."""
    lines = remove_empty_lines(read_sources(paths))
    records = map(lambda item: route_line(item[0], item[2]), lines)
    records = remove_invalid(records)
    records = normalize_records(records)
    return keep_known_severity(records)
