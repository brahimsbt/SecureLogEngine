"""Audit des variables en mémoire avec globals() et locals()."""

import json
import types

SECRET_WORDS = ("password", "token", "secret", "key")
MAX_LENGTH = 80


def is_secret(name: str):
    """Indique si le nom d'une variable ressemble à celui d'un secret."""
    lower_name = name.lower()
    for word in SECRET_WORDS:
        if word in lower_name:
            return True
    return False


def describe_value(name: str, value):
    """Renvoie le type d'une variable et une description courte."""
    if is_secret(name):
        text = "***"
    elif isinstance(value, (list, tuple, set, frozenset, dict)):
        text = f"{len(value)} éléments"
    else:
        text = repr(value)
        if len(text) > MAX_LENGTH:
            text = text[:MAX_LENGTH] + "..."
    return {"type": type(value).__name__, "value": text}


def inspect_scope(scope: dict):
    """Décrit les variables utiles d'un dictionnaire de portée."""
    report = {}
    for name, value in scope.items():
        if name.startswith("_"):
            continue
        if isinstance(value, types.ModuleType) or callable(value):
            continue
        report[name] = describe_value(name, value)
    return report


def export_audit_report(path: str, global_scope: dict, local_scope: dict):
    """Écrit en JSON l'audit des variables globales et locales."""
    report = {
        "globals": inspect_scope(global_scope),
        "locals": inspect_scope(local_scope),
    }
    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
    return report
