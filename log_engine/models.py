"""Constantes décrivant les formats de logs."""

SEVERITY_LEVELS = {
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
}

TEXT_SEPARATOR = " | "
TEXT_FIELDS = (
    "timestamp",
    "severity",
    "connection",
    "user",
    "event",
    "payload",
)

JSONL_REQUIRED_KEYS = frozenset(
    {"timestamp", "level", "src_ip", "src_port", "protocol", "event"}
)

CSV_COLUMNS = (
    "timestamp",
    "src_ip",
    "src_port",
    "protocol",
    "dst_port",
    "action",
)

SUPPORTED_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP"})

KNOWN_EVENTS = frozenset(
    {
        "SERVICE_START",
        "SERVICE_STOP",
        "SERVICE_FAILURE",
        "AUTH_SUCCESS",
        "AUTH_FAILURE",
        "ACCESS_DENIED",
        "PRIVILEGE_ESCALATION",
        "CONFIG_CHANGE",
        "HTTP_REQUEST",
        "HTTP_ERROR",
        "CONNECTION_ACCEPTED",
        "CONNECTION_REJECTED",
    }
)
