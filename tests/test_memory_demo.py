"""Tests du script de démonstration mémoire."""

from scripts.memory_demo import (
    create_test_file,
    main,
    measure_peak,
    read_all_at_once,
    read_with_generator,
    read_with_list,
    read_with_pipeline,
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


def test_test_file_lines_are_valid_logs(tmp_path):
    """Les lignes générées sont de vrais logs acceptés par la chaîne."""
    path = str(tmp_path / "demo.log")
    create_test_file(path, 100)
    assert read_with_pipeline(path) == 100


def test_list_reads_every_line(tmp_path):
    """La lecture en liste compte bien toutes les lignes."""
    path = str(tmp_path / "demo.log")
    create_test_file(path, 30)
    assert read_with_list(path) == 30


def test_main_prints_every_method(tmp_path, capsys):
    """La démonstration affiche une mesure pour chaque méthode."""
    main(nb_lines=1000)
    output = capsys.readouterr().out
    assert "Chaîne complète" in output
    assert output.count("pic mémoire") == 4
