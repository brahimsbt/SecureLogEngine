"""Tests de la lecture des fichiers de logs."""

import inspect

import pytest

from log_engine.exceptions import LogEngineError, SourceNotFoundError
from log_engine.ingestion.readers import read_lines, read_source, read_sources


def create_file(folder, name, content):
    """Crée un fichier dans le dossier de test et renvoie son chemin."""
    path = folder / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_read_lines_is_a_generator(tmp_path):
    """read_lines renvoie un générateur, pas une liste."""
    path = create_file(tmp_path, "test.log", "a\n")
    assert inspect.isgenerator(read_lines(path))


def test_lines_are_numbered_without_newline(tmp_path):
    """Chaque ligne est un tuple (numéro, texte sans saut de ligne)."""
    path = create_file(tmp_path, "test.log", "un\ndeux\n")
    assert list(read_lines(path)) == [(1, "un"), (2, "deux")]


def test_empty_lines_are_kept(tmp_path):
    """Les lignes vides sont gardées."""
    path = create_file(tmp_path, "test.log", "a\n\nb\n")
    assert list(read_lines(path)) == [(1, "a"), (2, ""), (3, "b")]


def test_empty_file(tmp_path):
    """Un fichier vide ne produit aucune ligne."""
    path = create_file(tmp_path, "test.log", "")
    assert list(read_lines(path)) == []


def test_bad_character_does_not_crash(tmp_path):
    """Un octet illisible est remplacé au lieu de faire planter la lecture."""
    path = tmp_path / "bad.log"
    path.write_bytes(b"ok\nmauvais \xff octet\n")
    assert list(read_lines(str(path))) == [(1, "ok"), (2, "mauvais � octet")]


def test_next_gives_one_line_at_a_time(tmp_path):
    """next() donne la ligne suivante."""
    path = create_file(tmp_path, "test.log", "a\nb\n")
    lines = read_lines(path)
    assert next(lines) == (1, "a")
    assert next(lines) == (2, "b")


def test_stop_iteration_at_the_end(tmp_path):
    """Quand il n'y a plus de ligne, next() lève StopIteration."""
    path = create_file(tmp_path, "test.log", "a\n")
    lines = read_lines(path)
    next(lines)
    with pytest.raises(StopIteration):
        next(lines)


def test_generator_can_be_used_only_once(tmp_path):
    """Un générateur ne se relit pas."""
    path = create_file(tmp_path, "test.log", "a\nb\n")
    lines = read_lines(path)
    assert len(list(lines)) == 2
    assert list(lines) == []


def test_missing_file_raises_error(tmp_path):
    """Un fichier absent lève SourceNotFoundError."""
    with pytest.raises(SourceNotFoundError):
        list(read_lines(str(tmp_path / "absent.log")))


def test_error_only_at_first_next(tmp_path):
    """L'erreur n'arrive qu'au premier next()."""
    lines = read_lines(str(tmp_path / "absent.log"))
    with pytest.raises(SourceNotFoundError):
        next(lines)


def test_error_can_be_caught_with_base_class(tmp_path):
    """SourceNotFoundError est aussi une LogEngineError."""
    with pytest.raises(LogEngineError):
        list(read_lines(str(tmp_path / "absent.log")))


@pytest.mark.parametrize(
    "name, expected",
    [
        ("auth.log", 26),
        ("app_events.jsonl", 14),
        ("connections.csv", 17),
        ("blacklist.txt", 4),
    ],
)
def test_each_sample_file(name, expected):
    """Chaque fichier d'exemple est lu en entier."""
    lines = list(read_lines("data/samples/" + name))
    assert len(lines) == expected


def test_read_source_adds_file_name(tmp_path):
    """Chaque ligne est accompagnée du nom de son fichier."""
    path = create_file(tmp_path, "test.log", "a\n")
    assert list(read_source(path)) == [("test.log", 1, "a")]


def test_read_sources_chains_files_in_order(tmp_path):
    """Les fichiers sont lus l'un après l'autre, dans l'ordre."""
    first = create_file(tmp_path, "un.log", "a\nb\n")
    second = create_file(tmp_path, "deux.log", "c\n")
    assert list(read_sources([first, second])) == [
        ("un.log", 1, "a"),
        ("un.log", 2, "b"),
        ("deux.log", 1, "c"),
    ]


def test_read_sources_on_sample_files():
    """Les trois fichiers d'exemple forment un seul flux."""
    paths = [
        "data/samples/auth.log",
        "data/samples/app_events.jsonl",
        "data/samples/connections.csv",
    ]
    lines = list(read_sources(paths))
    assert len(lines) == 26 + 14 + 17


def test_missing_file_is_skipped_with_warning(tmp_path, caplog):
    """Un fichier absent est signalé puis ignoré."""
    path = create_file(tmp_path, "test.log", "a\n")
    absent = str(tmp_path / "absent.log")
    assert list(read_sources([absent, path])) == [("test.log", 1, "a")]
    assert "Source ignorée" in caplog.text


def test_second_file_is_opened_only_when_needed(tmp_path, caplog):
    """Le fichier suivant n'est ouvert qu'une fois le premier terminé."""
    path = create_file(tmp_path, "test.log", "a\n")
    lines = read_sources([path, str(tmp_path / "absent.log")])
    assert next(lines) == ("test.log", 1, "a")
    assert caplog.text == ""
    list(lines)
    assert "absent.log" in caplog.text
