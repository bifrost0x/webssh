"""Tests for post-connect command normalization and terminal input."""

import pytest


def test_normalize_startup_commands_accepts_blank_input():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('')

    assert commands == ''
    assert error is None


def test_normalize_startup_commands_converts_all_line_endings_to_lf():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('echo first\r\necho second\recho third')

    assert commands == 'echo first\necho second\necho third'
    assert error is None


@pytest.mark.parametrize('value', [None, 42, ['echo test']])
def test_normalize_startup_commands_rejects_non_string_values(value):
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands(value)

    assert commands == ''
    assert error == 'Startup commands must be text'


def test_normalize_startup_commands_rejects_nul_bytes():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('echo safe\x00echo unsafe')

    assert commands == ''
    assert error == 'Startup commands must not contain NUL bytes'


def test_normalize_startup_commands_rejects_too_long_text():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('x' * 4097)

    assert commands == ''
    assert error == 'Startup commands must not exceed 4096 characters'


def test_to_terminal_input_converts_normalized_linefeeds_to_carriage_returns():
    from app.startup_commands import to_terminal_input

    assert to_terminal_input('echo first\necho second') == 'echo first\recho second'
