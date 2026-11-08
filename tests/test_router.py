"""Tests du routage des événements avec match-case."""

from log_engine.ingestion.readers import read_sources
from log_engine.router import decode_line, route_event, route_line

TEXT_LINE = (
    "2026-11-04T08:12:01Z | WARNING | 203.0.113.45:41001/TCP | admin "
    '| AUTH_FAILURE | {"reason": "bad_password"}'
)
JSON_DATA = {
    "timestamp": "2026-11-04T08:13:05Z",
    "level": "ERROR",
    "src_ip": "203.0.113.45",
    "src_port": 41020,
    "protocol": "TCP",
    "user": "admin",
    "event": "ACCESS_DENIED",
    "code": 403,
}
CSV_TUPLE = (
    "2026-11-04T08:08:41Z",
    "198.51.100.77",
    "60101",
    "TCP",
    "22",
    "REJECTED",
)


def test_decode_line_by_extension():
    """La ligne devient un dict (.jsonl), un tuple (.csv) ou reste du texte."""
    assert decode_line("app_events.jsonl", '{"a": 1}') == {"a": 1}
    assert decode_line("connections.csv", "a,b,c") == ("a", "b", "c")
    assert decode_line("auth.log", "texte") == "texte"


def test_invalid_json_stays_raw_string():
    """Un JSON cassé reste une chaîne brute."""
    assert decode_line("app_events.jsonl", '{"cassé": ') == '{"cassé": '


def test_route_raw_string():
    """Une chaîne brute est envoyée au parseur texte."""
    record = route_event(TEXT_LINE)
    assert record["event"] == "AUTH_FAILURE"
    assert record["connection"] == ("203.0.113.45", 41001, "TCP")


def test_route_dictionary():
    """Un dictionnaire avec les bonnes clés est envoyé au parseur JSON."""
    record = route_event(JSON_DATA)
    assert record["severity"] == "ERROR"
    assert record["payload"] == {"code": 403}


def test_route_connection_tuple():
    """Un tuple de 6 champs est envoyé au parseur de connexions."""
    record = route_event(CSV_TUPLE)
    assert record["event"] == "CONNECTION_REJECTED"
    assert record["payload"] == {"dst_port": 22}


def test_unknown_shapes_give_none():
    """Une forme inconnue tombe dans case _ et donne None."""
    assert route_event({"level": "ERROR", "code": 500}) is None
    assert route_event(("trop", "court")) is None
    assert route_event(42) is None
    assert route_event(None) is None


def test_route_line_on_all_sample_files():
    """Les trois fichiers d'exemple sont routés vers le bon parseur."""
    paths = [
        "data/samples/auth.log",
        "data/samples/app_events.jsonl",
        "data/samples/connections.csv",
    ]
    counts = {"auth.log": 0, "app_events.jsonl": 0, "connections.csv": 0}
    for source, number, line in read_sources(paths):
        if route_line(source, line) is not None:
            counts[source] = counts[source] + 1
    assert counts == {
        "auth.log": 23,
        "app_events.jsonl": 11,
        "connections.csv": 15,
    }
