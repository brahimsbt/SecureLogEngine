"""Tests du script de démonstration mémoire."""

from scripts.memory_demo import (
    create_test_file,
    measure_peak,
    read_all_at_once,
    read_with_generator,
)


def test_create_test_file(tmp_path):
    """Le fichier créé contient le bon nombre de lignes."""
    path = str(tmp_path / "demo.log")
    create_test_file(path, 50)
    with open(path, encoding="utf-8") as file:
        assert len(file.readlines()) == 50


def test_generator_uses_much_less_memory(tmp_path):
    """Le générateur utilise au moins 10 fois moins de mémoire."""
    path = str(tmp_path / "demo.log")
    create_test_file(path, 50_000)
    generator_peak = measure_peak(read_with_generator, path)
    full_load_peak = measure_peak(read_all_at_once, path)
    assert generator_peak * 10 < full_load_peak
