"""Analyse des adresses IP avec set et frozenset."""

from log_engine.ingestion.readers import read_lines
from log_engine.models import SEVERITY_LEVELS


def load_blacklist(path: str):
    """Lit le fichier de blacklist et renvoie un frozenset d'adresses IP."""
    ips = set()
    for number, line in read_lines(path):
        ip = line.strip()
        if ip != "":
            ips.add(ip)
    return frozenset(ips)


def active_ips(records):
    """Renvoie l'ensemble des adresses IP présentes dans les logs."""
    ips = set()
    for record in records:
        ips.add(record["connection"][0])
    return ips


def error_ips(records, minimum: str = "WARNING"):
    """Renvoie les IP ayant généré un événement d'au moins ce niveau."""
    level = SEVERITY_LEVELS[minimum]
    ips = set()
    for record in records:
        if SEVERITY_LEVELS[record["severity"]] >= level:
            ips.add(record["connection"][0])
    return ips


def compare_with_blacklist(blacklist, active, errors):
    """Compare la blacklist aux IP des logs avec les opérations d'ensembles."""
    return {
        "blacklisted_and_active": blacklist & active,
        "suspects_not_blacklisted": errors - blacklist,
        "new_blacklist": blacklist | errors,
        "in_only_one": blacklist ^ active,
    }
