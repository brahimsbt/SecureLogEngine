"""Conversion des lignes de logs en dictionnaires."""

import json
from datetime import datetime

from log_engine.models import (
    JSONL_REQUIRED_KEYS,
    SUPPORTED_PROTOCOLS,
    TEXT_SEPARATOR,
)


def parse_timestamp(text: str):
    """Convertit une date du type 2026-11-04T08:12:01Z en datetime."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")


def make_connection(ip: str, port, protocol: str):
    """Crée le tuple (ip, port, protocole) après avoir vérifié les valeurs."""
    port = int(port)
    if port < 0 or port > 65535:
        raise ValueError(f"Port invalide : {port}")
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Protocole inconnu : {protocol}")
    return (ip, port, protocol)


def parse_connection(text: str):
    """Découpe 203.0.113.45:41001/TCP en tuple (ip, port, protocole)."""
    address, protocol = text.split("/")
    ip, port = address.split(":")
    return make_connection(ip, port, protocol)


def parse_payload(text: str):
    """Renvoie un dictionnaire si le JSON est valide, sinon le texte brut."""
    if not text.startswith("{"):
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def parse_text_line(line: str):
    """Convertit une ligne de auth.log en dictionnaire, ou renvoie None."""
    fields = line.split(TEXT_SEPARATOR, 5)
    if len(fields) != 6:
        return None

    try:
        timestamp = parse_timestamp(fields[0])
        connection = parse_connection(fields[2])
    except ValueError:
        return None

    payload = parse_payload(fields[5])

    user = fields[3]
    if user == "-":
        user = None

    return {
        "timestamp": timestamp,
        "severity": fields[1],
        "connection": connection,
        "user": user,
        "event": fields[4],
        "payload": payload,
    }


def parse_json_line(line: str):
    """Convertit une ligne de app_events.jsonl en dictionnaire, ou None."""
    try:
        data = json.loads(line)
        timestamp = parse_timestamp(data["timestamp"])
        connection = make_connection(
            data["src_ip"], data["src_port"], data["protocol"]
        )
        severity = data["level"]
        event = data["event"]
    except (ValueError, KeyError, TypeError):
        return None

    payload = {}
    for key, value in data.items():
        if key not in JSONL_REQUIRED_KEYS and key != "user":
            payload[key] = value

    return {
        "timestamp": timestamp,
        "severity": severity,
        "connection": connection,
        "user": data.get("user"),
        "event": event,
        "payload": payload,
    }


def parse_csv_line(line: str):
    """Convertit une ligne de connections.csv en dictionnaire, ou None."""
    fields = line.split(",")
    if len(fields) != 6:
        return None

    try:
        timestamp = parse_timestamp(fields[0])
        connection = make_connection(fields[1], fields[2], fields[3])
        destination_port = int(fields[4])
    except ValueError:
        return None

    if fields[5] == "ACCEPTED":
        severity = "INFO"
        event = "CONNECTION_ACCEPTED"
    else:
        severity = "WARNING"
        event = "CONNECTION_REJECTED"

    return {
        "timestamp": timestamp,
        "severity": severity,
        "connection": connection,
        "user": None,
        "event": event,
        "payload": {"dst_port": destination_port},
    }
