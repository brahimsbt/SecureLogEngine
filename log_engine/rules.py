"""Moteur de règles de sécurité modulaire."""

import logging

from log_engine.bruteforce import describe_attacks
from log_engine.ip_analysis import active_ips


def make_alert(rule: str, ip: str, message: str):
    """Crée une alerte sous forme de dictionnaire."""
    return {"rule": rule, "ip": ip, "message": message}


def rule_brute_force(records, **config):
    """Alerte sur les IP qui font trop d'échecs de connexion d'affilée."""
    threshold = config.get("threshold", 5)
    alerts = []
    for attack in describe_attacks(records, threshold):
        failures = attack["failures"]
        users = ", ".join(sorted(attack["users"]))
        if attack["succeeded"]:
            result = "attaque réussie"
        else:
            result = "attaque échouée"
        message = f"{failures} échecs sur {users} ({result})"
        alerts.append(make_alert("brute_force", attack["ip"], message))
    return alerts


def rule_blacklisted_ips(records, **config):
    """Alerte sur les IP de la blacklist présentes dans les logs."""
    blacklist = config.get("blacklist", frozenset())
    alerts = []
    for ip in sorted(blacklist & active_ips(records)):
        message = "IP blacklistée présente dans les logs"
        alerts.append(make_alert("blacklist", ip, message))
    return alerts


def rule_privilege_escalation(records, **config):
    """Alerte sur chaque élévation de privilèges."""
    alerts = []
    for record in records:
        if record["event"] == "PRIVILEGE_ESCALATION":
            ip = record["connection"][0]
            message = f"{record['user']} a obtenu des droits élevés"
            alerts.append(make_alert("privilege", ip, message))
    return alerts


def apply_security_rules(records, *args, **kwargs):
    """Applique chaque règle reçue et regroupe toutes les alertes."""
    records = list(records)
    alerts = []
    for rule in args:
        try:
            alerts.extend(rule(records, **kwargs))
        except Exception as error:
            logging.warning(f"Règle {rule.__name__} ignorée : {error}")
    return alerts
