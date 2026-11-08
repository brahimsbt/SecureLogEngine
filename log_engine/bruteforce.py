"""Détection des attaques par force brute."""

from collections import defaultdict


def group_attempts_by_ip(records):
    """Regroupe, pour chaque IP, la suite de ses tentatives de connexion."""
    attempts = defaultdict(list)
    for record in records:
        event = record["event"]
        if event != "AUTH_FAILURE" and event != "AUTH_SUCCESS":
            continue
        ip = record["connection"][0]
        attempts[ip].append(event == "AUTH_FAILURE")
    return attempts


def has_consecutive_failures(attempts: list, threshold: int):
    """Vérifie si la liste contient au moins threshold échecs à la suite."""
    streak = 0
    index = 0
    while index < len(attempts):
        if attempts[index]:
            streak += 1
        else:
            streak = 0
        if streak >= threshold:
            break
        index += 1
    else:
        return False
    return True


def detect_brute_force(records, threshold: int = 5):
    """Renvoie l'ensemble des IP ayant trop d'échecs de connexion d'affilée."""
    if threshold < 1:
        raise ValueError("Le seuil doit être au moins égal à 1")

    suspects = set()
    for ip, ip_attempts in group_attempts_by_ip(records).items():
        if has_consecutive_failures(ip_attempts, threshold):
            suspects.add(ip)
    return suspects


def describe_attacks(records, threshold: int = 5):
    """Décrit chaque attaque détectée : comptes visés, échecs, réussite."""
    records = list(records)
    attacks = []
    for ip in sorted(detect_brute_force(records, threshold)):
        users = set()
        failures = 0
        succeeded = False
        for record in records:
            if record["connection"][0] != ip:
                continue
            if record["event"] == "AUTH_FAILURE":
                failures += 1
                if record["user"] is not None:
                    users.add(record["user"])
            elif record["event"] == "AUTH_SUCCESS" and failures >= threshold:
                succeeded = True
        attacks.append(
            {
                "ip": ip,
                "users": users,
                "failures": failures,
                "succeeded": succeeded,
            }
        )
    return attacks
