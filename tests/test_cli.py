"""Tests de la ligne de commande."""

import json

import pytest

from log_engine.cli import format_counts, format_ips, main


def test_format_counts_sorted_by_count():
    """Les comptages sont affichés du plus grand au plus petit."""
    assert format_counts({"bob": 2, "admin": 9}) == "admin 9 | bob 2"


def test_format_ips():
    """Les IP sont triées, et un ensemble vide affiche 'aucune'."""
    assert format_ips({"2.2.2.2", "1.1.1.1"}) == "1.1.1.1, 2.2.2.2"
    assert format_ips(set()) == "aucune"


def test_default_analysis(capsys):
    """Sans argument, les fichiers d'exemple sont analysés."""
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "Événements analysés : 49" in output
    assert "=== Alertes (4) ===" in output
    assert "[brute_force] 203.0.113.45" in output


def test_threshold_option(capsys):
    """L'option --threshold change les attaques détectées."""
    main(["--threshold", "3"])
    output = capsys.readouterr().out
    assert "[brute_force] 198.51.100.23" in output


def test_single_file(capsys):
    """On peut analyser un seul fichier."""
    main(["data/samples/connections.csv"])
    output = capsys.readouterr().out
    assert "Événements analysés : 15" in output


def test_audit_option(tmp_path, capsys):
    """L'option --audit exporte les variables de main() en JSON."""
    path = tmp_path / "audit.json"
    main(["--audit", str(path)])
    with open(path, encoding="utf-8") as file:
        report = json.load(file)
    assert report["locals"]["records"]["value"] == "49 éléments"
    assert report["locals"]["alerts"]["value"] == "4 éléments"
    assert "DEFAULT_BLACKLIST" in report["globals"]


def test_missing_blacklist(capsys):
    """Une blacklist introuvable donne un message clair et le code 1."""
    assert main(["--blacklist", "absente.txt"]) == 1
    assert "Source introuvable" in capsys.readouterr().out


def test_invalid_threshold():
    """Un seuil de 0 est refusé par la ligne de commande."""
    with pytest.raises(SystemExit):
        main(["--threshold", "0"])
