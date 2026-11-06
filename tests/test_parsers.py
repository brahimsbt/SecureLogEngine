"""Tests de la conversion des lignes de logs en dictionnaires."""

from datetime import datetime

import pytest

from log_engine.ingestion.readers import read_lines
from log_engine.parsers import (
    make_connection,
    parse_connection,
    parse_csv_line,
    parse_json_line,
    parse_payload,
    parse_text_line,
    parse_timestamp,
)


def test_parse_timestamp():
    """La date texte devient un objet datetime."""
    assert parse_timestamp("2026-11-04T08:12:01Z") == datetime(
        2026, 11, 4, 8, 12, 1
    )


def test_parse_connection():
    """L'adresse devient un tuple (ip, port, protocole)."""
    assert parse_connection("203.0.113.45:41001/TCP") == (
        "203.0.113.45",
        41001,
        "TCP",
    )


def test_text_line_becomes_dict():
    """Une ligne de auth.log valide devient un dictionnaire complet."""
    line = (
        "2026-11-04T08:12:01Z | WARNING | 203.0.113.45:41001/TCP | admin "
        '| AUTH_FAILURE | {"reason": "bad_password", "attempt": 1}'
    )
    assert parse_text_line(line) == {
        "timestamp": datetime(2026, 11, 4, 8, 12, 1),
        "severity": "WARNING",
        "connection": ("203.0.113.45", 41001, "TCP"),
        "user": "admin",
        "event": "AUTH_FAILURE",
        "payload": {"reason": "bad_password", "attempt": 1},
    }


def test_text_line_without_user():
    """Un utilisateur '-' devient None."""
    line = (
        "2026-11-04T08:00:00Z | INFO | 127.0.0.1:22/TCP | - "
        "| SERVICE_START | {}"
    )
    assert parse_text_line(line)["user"] is None


def test_text_line_with_raw_payload():
    """Un payload qui n'est pas du JSON reste du texte."""
    line = (
        "2026-11-04T08:45:21Z | WARNING | 10.0.0.15:50300/TCP | alice "
        "| AUTH_FAILURE | Password expired"
    )
    assert parse_text_line(line)["payload"] == "Password expired"


def test_invalid_text_lines_give_none():
    """Les lignes vides, tronquées ou mal formées donnent None."""
    assert parse_text_line("") is None
    assert parse_text_line("kernel: eth0: link is up") is None
    assert parse_text_line("2026-11-04T08:40:00Z | ERROR | 10.0.0.12") is None
    assert (
        parse_text_line(
            "hier | INFO | 10.0.0.1:22/TCP | bob | AUTH_SUCCESS | {}"
        )
        is None
    )


def test_json_line_becomes_dict():
    """Une ligne JSON valide devient un dictionnaire complet."""
    line = (
        '{"timestamp": "2026-11-04T08:13:05Z", "level": "ERROR", '
        '"src_ip": "203.0.113.45", "src_port": 41020, "protocol": "TCP", '
        '"user": "admin", "event": "ACCESS_DENIED", "code": 403}'
    )
    assert parse_json_line(line) == {
        "timestamp": datetime(2026, 11, 4, 8, 13, 5),
        "severity": "ERROR",
        "connection": ("203.0.113.45", 41020, "TCP"),
        "user": "admin",
        "event": "ACCESS_DENIED",
        "payload": {"code": 403},
    }


def test_json_line_with_null_user():
    """Un utilisateur null en JSON devient None."""
    line = (
        '{"timestamp": "2026-11-04T08:09:02Z", "level": "WARNING", '
        '"src_ip": "198.51.100.77", "src_port": 60001, "protocol": "TCP", '
        '"user": null, "event": "HTTP_ERROR"}'
    )
    assert parse_json_line(line)["user"] is None


def test_invalid_json_lines_give_none():
    """Le JSON vide, cassé ou incomplet donne None."""
    assert parse_json_line("") is None
    assert parse_json_line('{"timestamp": "2026-11-04T08:50:00Z", ') is None
    assert parse_json_line('{"timestamp": "2026-11-04T08:52:12Z"}') is None


def test_csv_line_becomes_dict():
    """Une connexion refusée devient un événement WARNING."""
    line = "2026-11-04T08:08:41Z,198.51.100.77,60101,TCP,22,REJECTED"
    assert parse_csv_line(line) == {
        "timestamp": datetime(2026, 11, 4, 8, 8, 41),
        "severity": "WARNING",
        "connection": ("198.51.100.77", 60101, "TCP"),
        "user": None,
        "event": "CONNECTION_REJECTED",
        "payload": {"dst_port": 22},
    }


def test_csv_accepted_connection_is_info():
    """Une connexion acceptée devient un événement INFO."""
    line = "2026-11-04T08:01:00Z,10.0.0.15,50100,TCP,443,ACCEPTED"
    assert parse_csv_line(line)["severity"] == "INFO"


def test_invalid_csv_lines_give_none():
    """L'en-tête, une ligne vide ou un port non numérique donnent None."""
    assert (
        parse_csv_line("timestamp,src_ip,src_port,protocol,dst_port,action")
        is None
    )
    assert parse_csv_line("") is None
    assert (
        parse_csv_line(
            "2026-11-04T08:30:00Z,10.0.0.9,notaport,TCP,443,ACCEPTED"
        )
        is None
    )


def count_valid_lines(path, parser):
    """Compte les lignes d'un fichier que le parseur arrive à convertir."""
    count = 0
    for number, line in read_lines(path):
        if parser(line) is not None:
            count = count + 1
    return count


def test_sample_files_are_parsed():
    """Seules les lignes volontairement cassées des exemples sont rejetées."""
    assert count_valid_lines("data/samples/auth.log", parse_text_line) == 21
    assert (
        count_valid_lines("data/samples/app_events.jsonl", parse_json_line)
        == 11
    )
    assert (
        count_valid_lines("data/samples/connections.csv", parse_csv_line) == 15
    )


def test_make_connection_converts_port_to_int():
    """Le port est converti en entier dans le tuple."""
    assert make_connection("10.0.0.5", "22", "TCP") == ("10.0.0.5", 22, "TCP")


def test_make_connection_rejects_bad_values():
    """Un port hors limites ou un protocole inconnu lève ValueError."""
    with pytest.raises(ValueError):
        make_connection("10.0.0.5", "99999", "TCP")
    with pytest.raises(ValueError):
        make_connection("10.0.0.5", "-1", "TCP")
    with pytest.raises(ValueError):
        make_connection("10.0.0.5", "22", "XYZ")


def test_connection_is_a_tuple():
    """Les métadonnées de connexion sont un tuple, donc non modifiables."""
    connection = parse_connection("10.0.0.5:22/TCP")
    assert type(connection) is tuple
    with pytest.raises(TypeError):
        connection[1] = 80


def test_parse_payload():
    """JSON valide -> dictionnaire ; texte ou JSON cassé -> texte brut."""
    assert parse_payload('{"a": 1}') == {"a": 1}
    assert parse_payload("Password expired") == "Password expired"
    assert parse_payload("{cassé") == "{cassé"


def test_broken_json_payload_keeps_the_line():
    """Un payload JSON cassé ne fait plus perdre la ligne."""
    line = (
        "2026-11-04T08:12:01Z | WARNING | 10.0.0.5:22/TCP | bob "
        "| AUTH_FAILURE | {cassé"
    )
    record = parse_text_line(line)
    assert record["user"] == "bob"
    assert record["payload"] == "{cassé"


def test_bad_connection_makes_line_invalid():
    """Un port ou un protocole invalide rend la ligne invalide."""
    text_line = (
        "2026-11-04T08:12:01Z | WARNING | 10.0.0.5:99999/TCP | bob "
        "| AUTH_FAILURE | {}"
    )
    json_line = (
        '{"timestamp": "2026-11-04T08:13:05Z", "level": "ERROR", '
        '"src_ip": "10.0.0.5", "src_port": 22, "protocol": "XYZ", '
        '"event": "ACCESS_DENIED"}'
    )
    csv_line = "2026-11-04T08:08:41Z,10.0.0.5,70000,TCP,22,REJECTED"
    assert parse_text_line(text_line) is None
    assert parse_json_line(json_line) is None
    assert parse_csv_line(csv_line) is None
