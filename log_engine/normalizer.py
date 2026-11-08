"""Normalisation des enregistrements avec map()."""


def normalize_record(record: dict):
    """Renvoie une copie de l'enregistrement avec des champs uniformisés."""
    normalized = dict(record)

    severity = str(record["severity"]).strip().upper()
    event = str(record["event"]).strip().upper()
    user = record["user"]
    if user is not None:
        user = str(user).strip().lower()

    normalized["severity"] = severity
    normalized["event"] = event
    normalized["user"] = user

    ip = record["connection"][0]
    shown_user = user
    if shown_user is None:
        shown_user = "-"
    normalized["summary"] = f"[{severity}] {ip} {shown_user} {event}"

    return normalized


def normalize_records(records):
    """Applique normalize_record à chaque enregistrement avec map()."""
    return map(normalize_record, records)
