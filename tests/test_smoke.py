"""Tests de base du programme."""

import subprocess
import sys

from log_engine.cli import main


def test_cli_without_arguments():
    """Sans argument, le programme affiche l'aide et renvoie 0."""
    assert main([]) == 0


def test_main_script_runs():
    """main.py s'exécute sans erreur."""
    result = subprocess.run(
        [sys.executable, "main.py", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "0.1.0" in result.stdout
