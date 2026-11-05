"""Interface en ligne de commande."""

import argparse

from log_engine import __version__


def main(arguments: list[str] | None = None) -> int:
    """Lit les arguments de la ligne de commande et lance le programme."""
    parser = argparse.ArgumentParser(
        prog="secure-log-engine",
        description="Analyse de fichiers de logs de sécurité.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(arguments)
    parser.print_help()
    return 0
