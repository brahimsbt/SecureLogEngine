"""Nettoyage des données avec filter() et des fonctions lambda."""

from log_engine.models import SEVERITY_LEVELS


def remove_empty_lines(lines):
    """Retire les lignes vides ou composées uniquement d'espaces."""
    return filter(lambda item: item[2].strip() != "", lines)


def remove_invalid(records):
    """Retire les lignes que le parseur n'a pas pu convertir (None)."""
    return filter(None, records)


def keep_known_severity(records):
    """Garde les enregistrements dont le niveau de sévérité est connu."""
    return filter(
        lambda record: record["severity"] in SEVERITY_LEVELS, records
    )
