"""Interface en ligne de commande."""

import argparse
import logging

from log_engine import __version__
from log_engine.aggregation import (
    count_by_event,
    count_by_severity,
    count_by_user,
)
from log_engine.audit import export_audit_report
from log_engine.exceptions import LogEngineError
from log_engine.ip_analysis import (
    active_ips,
    compare_with_blacklist,
    error_ips,
    load_blacklist,
)
from log_engine.pipeline import DEFAULT_FILES, process_files
from log_engine.rules import (
    apply_security_rules,
    rule_blacklisted_ips,
    rule_brute_force,
    rule_privilege_escalation,
)

DEFAULT_BLACKLIST = "data/samples/blacklist.txt"


def build_parser():
    """Décrit les arguments acceptés par la ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="secure-log-engine",
        description="Analyse de fichiers de logs de sécurité.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        default=DEFAULT_FILES,
        help="fichiers de logs à analyser (par défaut : les exemples)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="nombre d'échecs consécutifs pour détecter une force brute",
    )
    parser.add_argument(
        "--blacklist",
        default=DEFAULT_BLACKLIST,
        help="fichier contenant les adresses IP blacklistées",
    )
    parser.add_argument(
        "--audit",
        help="fichier JSON où exporter l'audit des variables",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def format_counts(counts):
    """Transforme un comptage en texte, du plus grand au plus petit."""
    items = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    parts = []
    for name, count in items:
        parts.append(f"{name} {count}")
    return " | ".join(parts)


def format_ips(ips):
    """Transforme un ensemble d'adresses IP en texte trié."""
    if len(ips) == 0:
        return "aucune"
    return ", ".join(sorted(ips))


def print_report(records, ips, alerts):
    """Affiche le rapport d'analyse dans le terminal."""
    print("=== SecureLogEngine : rapport d'analyse ===")
    print(f"Événements analysés : {len(records)}")
    print(f"Par niveau : {format_counts(count_by_severity(records))}")
    print(f"Par utilisateur : {format_counts(count_by_user(records))}")
    print(f"Par événement : {format_counts(count_by_event(records))}")

    blacklisted = format_ips(ips["blacklisted_and_active"])
    suspects = format_ips(ips["suspects_not_blacklisted"])
    print("\n=== Adresses IP ===")
    print(f"Blacklistées et actives : {blacklisted}")
    print(f"Suspectes non blacklistées : {suspects}")

    print(f"\n=== Alertes ({len(alerts)}) ===")
    for alert in alerts:
        print(f"[{alert['rule']}] {alert['ip']} : {alert['message']}")


def main(arguments: list[str] | None = None) -> int:
    """Lance l'analyse complète et renvoie le code de sortie."""
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.threshold < 1:
        parser.error("le seuil doit être au moins égal à 1")
    logging.basicConfig(format="%(levelname)s : %(message)s")

    try:
        blacklist = load_blacklist(args.blacklist)
    except LogEngineError as error:
        print(f"Erreur : {error}")
        return 1

    records = list(process_files(args.files))
    ips = compare_with_blacklist(
        blacklist, active_ips(records), error_ips(records)
    )
    alerts = apply_security_rules(
        records,
        rule_brute_force,
        rule_blacklisted_ips,
        rule_privilege_escalation,
        threshold=args.threshold,
        blacklist=blacklist,
    )
    print_report(records, ips, alerts)

    if args.audit is not None:
        export_audit_report(args.audit, globals(), locals())
        print(f"\nAudit exporté dans {args.audit}")
    return 0
