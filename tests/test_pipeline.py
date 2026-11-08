"""Tests d'intégration de la chaîne complète de traitement."""

import tracemalloc

from log_engine.aggregation import count_by_severity, count_by_user
from log_engine.audit import export_audit_report
from log_engine.bruteforce import detect_brute_force
from log_engine.ip_analysis import (
    active_ips,
    compare_with_blacklist,
    error_ips,
    load_blacklist,
)
from log_engine.models import SEVERITY_LEVELS
from log_engine.pipeline import DEFAULT_FILES, process_files
from log_engine.router import route_line
from log_engine.rules import (
    apply_security_rules,
    rule_blacklisted_ips,
    rule_brute_force,
    rule_privilege_escalation,
)


def test_process_files_is_lazy():
    """La chaîne ne lit rien tant qu'on ne demande pas d'enregistrement."""
    records = process_files(["fichier_absent.log"])
    assert type(records) is filter


def test_process_files_gives_clean_records():
    """Tous les enregistrements sont normalisés et valides."""
    records = list(process_files(DEFAULT_FILES))
    assert len(records) == 49
    for record in records:
        assert record["severity"] in SEVERITY_LEVELS
        assert record["event"] == record["event"].upper()
        assert type(record["connection"]) is tuple
        if record["user"] is not None:
            assert record["user"] == record["user"].lower()


def test_missing_file_does_not_stop_the_pipeline(caplog):
    """Un fichier absent est ignoré, les autres sont traités."""
    paths = ["data/samples/absent.log", "data/samples/connections.csv"]
    assert len(list(process_files(paths))) == 15
    assert "absent.log" in caplog.text


def test_malformed_lines_never_crash(tmp_path):
    """Des lignes absurdes sont rejetées sans faire planter la chaîne."""
    path = tmp_path / "bizarre.jsonl"
    path.write_text(
        "[1, 2, 3, 4, 5, 6]\n"
        "null\n"
        '"texte"\n'
        "42\n"
        "{}\n"
        '{"timestamp": 5, "level": "INFO", "src_ip": "1.1.1.1", '
        '"src_port": 22, "protocol": "TCP", "event": "X"}\n',
        encoding="utf-8",
    )
    assert list(process_files([str(path)])) == []


def test_list_of_six_numbers_is_rejected():
    """Une liste JSON de 6 nombres ne fait plus planter le routeur."""
    assert route_line("x.jsonl", "[1, 2, 3, 4, 5, 6]") is None


def test_full_analysis_on_sample_files(tmp_path):
    """De la lecture des fichiers jusqu'aux alertes et à l'audit."""
    records = list(process_files(DEFAULT_FILES))
    blacklist = load_blacklist("data/samples/blacklist.txt")

    assert count_by_user(records)["admin"] == 9
    assert count_by_severity(records)["CRITICAL"] == 2
    ips = compare_with_blacklist(
        blacklist, active_ips(records), error_ips(records)
    )
    assert ips["blacklisted_and_active"] == {"198.51.100.77", "192.0.2.150"}
    assert detect_brute_force(records) == {"203.0.113.45"}

    alerts = apply_security_rules(
        records,
        rule_brute_force,
        rule_blacklisted_ips,
        rule_privilege_escalation,
        blacklist=blacklist,
    )
    assert len(alerts) == 4

    report = export_audit_report(
        str(tmp_path / "audit.json"), globals(), locals()
    )
    assert report["locals"]["alerts"]["value"] == "4 éléments"


def measure_peak(function):
    """Exécute la fonction et renvoie le pic de mémoire utilisé."""
    tracemalloc.start()
    function()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def test_pipeline_memory_stays_low(tmp_path):
    """Le flux utilise au moins 10 fois moins de mémoire qu'une liste."""
    path = tmp_path / "gros.log"
    with open(path, "w", encoding="utf-8") as file:
        for i in range(20_000):
            file.write(
                "2026-11-04T08:12:01Z | WARNING | 10.0.0.5:22/TCP | admin "
                f"| AUTH_FAILURE | tentative {i}\n"
            )
    paths = [str(path)]
    list(process_files(DEFAULT_FILES))

    stream_peak = measure_peak(lambda: count_by_severity(process_files(paths)))
    list_peak = measure_peak(lambda: list(process_files(paths)))

    assert stream_peak * 10 < list_peak
