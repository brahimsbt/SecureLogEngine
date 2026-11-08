"""Tests du moteur de règles de sécurité."""

from log_engine.ip_analysis import load_blacklist
from log_engine.pipeline import DEFAULT_FILES, process_files
from log_engine.rules import (
    apply_security_rules,
    make_alert,
    rule_blacklisted_ips,
    rule_brute_force,
    rule_privilege_escalation,
)


def make_record(ip, event, user="admin"):
    """Crée un enregistrement de test."""
    return {"connection": (ip, 22, "TCP"), "event": event, "user": user}


ATTACK = [
    make_record("6.6.6.6", "AUTH_FAILURE"),
    make_record("6.6.6.6", "AUTH_FAILURE"),
    make_record("6.6.6.6", "AUTH_FAILURE"),
    make_record("6.6.6.6", "AUTH_SUCCESS"),
    make_record("6.6.6.6", "PRIVILEGE_ESCALATION"),
]


def test_rule_brute_force_uses_threshold():
    """Le seuil est lu dans la configuration."""
    assert rule_brute_force(ATTACK) == []
    assert rule_brute_force(ATTACK, threshold=3) == [
        make_alert(
            "brute_force", "6.6.6.6", "3 échecs sur admin (attaque réussie)"
        )
    ]


def test_rule_brute_force_failed_attack():
    """Une attaque sans succès est signalée comme échouée."""
    records = ATTACK[:3]
    assert rule_brute_force(records, threshold=3) == [
        make_alert(
            "brute_force", "6.6.6.6", "3 échecs sur admin (attaque échouée)"
        )
    ]


def test_rule_blacklisted_ips():
    """Seules les IP blacklistées et présentes dans les logs sont signalées."""
    blacklist = frozenset({"6.6.6.6", "9.9.9.9"})
    alerts = rule_blacklisted_ips(ATTACK, blacklist=blacklist)
    assert alerts == [
        make_alert(
            "blacklist", "6.6.6.6", "IP blacklistée présente dans les logs"
        )
    ]


def test_rule_blacklisted_ips_without_blacklist():
    """Sans blacklist dans la configuration, aucune alerte."""
    assert rule_blacklisted_ips(ATTACK) == []


def test_rule_privilege_escalation():
    """Chaque élévation de privilèges donne une alerte."""
    assert rule_privilege_escalation(ATTACK) == [
        make_alert("privilege", "6.6.6.6", "admin a obtenu des droits élevés")
    ]


def test_engine_without_rules():
    """Sans règle, le moteur ne renvoie aucune alerte."""
    assert apply_security_rules(ATTACK) == []


def test_engine_applies_all_rules_in_order():
    """Les alertes de toutes les règles sont regroupées, dans l'ordre."""
    alerts = apply_security_rules(
        ATTACK, rule_privilege_escalation, rule_brute_force, threshold=3
    )
    rules = []
    for alert in alerts:
        rules.append(alert["rule"])
    assert rules == ["privilege", "brute_force"]


def test_engine_accepts_custom_function():
    """N'importe quelle fonction peut servir de règle, même une lambda."""
    alerts = apply_security_rules(
        ATTACK,
        lambda records, **config: [
            make_alert("custom", "-", f"{len(records)} événements")
        ],
    )
    assert alerts == [make_alert("custom", "-", "5 événements")]


def test_failing_rule_does_not_stop_the_others(caplog):
    """Une règle qui plante est signalée, les autres sont appliquées."""

    def broken_rule(records, **config):
        """Règle volontairement défectueuse."""
        raise KeyError("champ manquant")

    alerts = apply_security_rules(
        ATTACK, broken_rule, rule_privilege_escalation
    )
    assert len(alerts) == 1
    assert "broken_rule" in caplog.text


def test_engine_on_sample_files():
    """Alertes produites sur les fichiers d'exemple."""
    alerts = apply_security_rules(
        list(process_files(DEFAULT_FILES)),
        rule_brute_force,
        rule_blacklisted_ips,
        rule_privilege_escalation,
        threshold=5,
        blacklist=load_blacklist("data/samples/blacklist.txt"),
    )
    assert alerts == [
        make_alert(
            "brute_force",
            "203.0.113.45",
            "6 échecs sur admin (attaque réussie)",
        ),
        make_alert(
            "blacklist", "192.0.2.150", "IP blacklistée présente dans les logs"
        ),
        make_alert(
            "blacklist",
            "198.51.100.77",
            "IP blacklistée présente dans les logs",
        ),
        make_alert(
            "privilege", "203.0.113.45", "admin a obtenu des droits élevés"
        ),
    ]
