"""Exceptions propres au moteur d'analyse de logs."""


class LogEngineError(Exception):
    """Erreur générale du moteur."""


class SourceNotFoundError(LogEngineError):
    """Le fichier de logs demandé n'existe pas."""
