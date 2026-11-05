"""Compare la mémoire utilisée par trois façons de lire un gros fichier."""

import os
import tempfile
import tracemalloc

from log_engine.ingestion.readers import read_lines

NB_LINES = 200_000


def create_test_file(path: str, nb_lines: int) -> None:
    """Crée un fichier de logs de test contenant nb_lines lignes."""
    with open(path, "w", encoding="utf-8") as file:
        for i in range(nb_lines):
            line = f"2026-11-04T08:12:01Z | WARNING | 10.0.0.5 | tentative {i}"
            file.write(line + "\n")


def read_with_generator(path: str) -> int:
    """Compte les lignes avec le générateur, sans rien garder en mémoire."""
    count = 0
    for _ in read_lines(path):
        count += 1
    return count


def read_with_list(path: str) -> int:
    """Transforme le générateur en liste : toutes les lignes en mémoire."""
    lines = list(read_lines(path))
    return len(lines)


def read_all_at_once(path: str) -> int:
    """Charge tout le fichier d'un coup avec readlines()."""
    with open(path, encoding="utf-8") as file:
        lines = file.readlines()
    return len(lines)


def measure_peak(read_function, path: str) -> int:
    """Exécute read_function(path) et renvoie le pic mémoire en octets."""
    tracemalloc.start()
    read_function(path)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def main() -> None:
    """Crée un fichier temporaire et affiche les trois mesures."""
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "demo.log")
        create_test_file(path, NB_LINES)
        size_mb = os.path.getsize(path) / 1024 / 1024
        print(f"Fichier de test : {NB_LINES} lignes, {size_mb:.1f} Mo\n")

        methods = [
            ("Générateur read_lines", read_with_generator),
            ("list(read_lines(...))", read_with_list),
            ("readlines()", read_all_at_once),
        ]
        for name, function in methods:
            peak_kb = measure_peak(function, path) / 1024
            print(f"{name:<25} pic mémoire : {peak_kb:>8.0f} Ko")


if __name__ == "__main__":
    main()
