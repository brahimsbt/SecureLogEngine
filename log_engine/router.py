"""Routage des événements selon leur forme avec match-case."""

import json
import os

from log_engine.parsers import (
    parse_connection_fields,
    parse_event_dict,
    parse_text_line,
)


def decode_line(source: str, line: str):
    """Transforme une ligne en chaîne, dict ou tuple selon son fichier."""
    extension = os.path.splitext(source)[1]
    match extension:
        case ".jsonl":
            try:
                return json.loads(line)
            except ValueError:
                return line
        case ".csv":
            return tuple(line.split(","))
        case _:
            return line


def route_event(data):
    """Envoie la donnée au bon parseur selon sa forme (match-case)."""
    match data:
        case str():
            return parse_text_line(data)
        case {
            "timestamp": _,
            "level": _,
            "src_ip": _,
            "src_port": _,
            "protocol": _,
            "event": _,
        }:
            return parse_event_dict(data)
        case (_, _, _, _, _, _):
            return parse_connection_fields(data)
        case _:
            return None


def route_line(source: str, line: str):
    """Décode puis route une ligne lue dans un fichier."""
    return route_event(decode_line(source, line))
