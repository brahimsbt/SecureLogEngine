"""Comptage des événements avec defaultdict."""

from collections import defaultdict


def count_by_field(records, field: str):
    """Compte le nombre d'enregistrements pour chaque valeur d'un champ."""
    counts = defaultdict(int)
    for record in records:
        value = record[field]
        if value is None:
            continue
        counts[value] += 1
    return counts


def count_by_user(records):
    """Compte les événements de chaque utilisateur."""
    return count_by_field(records, "user")


def count_by_severity(records):
    """Compte les événements de chaque niveau de sévérité."""
    return count_by_field(records, "severity")


def count_by_event(records):
    """Compte les événements de chaque type."""
    return count_by_field(records, "event")
