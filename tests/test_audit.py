"""Tests du module d'audit."""

import json

from log_engine.audit import (
    describe_value,
    export_audit_report,
    inspect_scope,
    is_secret,
)

AUDIT_THRESHOLD = 5


def test_is_secret():
    """Les noms contenant un mot sensible sont reconnus."""
    assert is_secret("db_password") is True
    assert is_secret("API_TOKEN") is True
    assert is_secret("ssh_key") is True
    assert is_secret("threshold") is False


def test_describe_simple_value():
    """Une valeur simple est décrite par son type et sa valeur."""
    assert describe_value("threshold", 5) == {"type": "int", "value": "5"}


def test_describe_secret_is_masked():
    """La valeur d'un secret n'apparaît jamais."""
    assert describe_value("password", "azerty") == {
        "type": "str",
        "value": "***",
    }


def test_describe_collection_by_size():
    """Une collection est résumée par sa taille."""
    assert describe_value("records", [1, 2, 3]) == {
        "type": "list",
        "value": "3 éléments",
    }


def test_describe_long_text_is_cut():
    """Un texte trop long est coupé."""
    description = describe_value("message", "a" * 200)
    assert description["value"].endswith("...")
    assert len(description["value"]) < 100


def test_inspect_scope_keeps_only_useful_variables():
    """Noms internes, modules et fonctions sont ignorés."""
    scope = {
        "__name__": "test",
        "_cache": 1,
        "json": json,
        "is_secret": is_secret,
        "threshold": 5,
    }
    assert inspect_scope(scope) == {"threshold": {"type": "int", "value": "5"}}


def test_export_with_globals_and_locals(tmp_path):
    """Le rapport est exporté en JSON à partir de globals() et locals()."""
    path = str(tmp_path / "audit_report.json")
    threshold = 3
    db_password = "SuperSecret!"
    ips = {"10.0.0.1", "10.0.0.2"}

    export_audit_report(path, globals(), locals())

    with open(path, encoding="utf-8") as file:
        content = file.read()
    report = json.loads(content)

    assert report["globals"]["AUDIT_THRESHOLD"] == {
        "type": "int",
        "value": "5",
    }
    assert report["locals"]["threshold"] == {"type": "int", "value": "3"}
    assert report["locals"]["db_password"]["value"] == "***"
    assert report["locals"]["ips"] == {"type": "set", "value": "2 éléments"}
    assert "SuperSecret!" not in content
    assert "describe_value" not in report["globals"]
