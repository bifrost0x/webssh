"""Explicit argument parameters never interpolate shell source or auto-run."""
import shlex

import pytest

from app import command_set_manager as manager


def payload():
    return {
        'name': 'Inspect path', 'parameters': [{'name': 'path'}],
        'steps': [{'type': 'argv', 'argv': ['printf', '%s', '{{path}}', '{{path}}']}],
    }


def test_parameterized_set_is_saved_and_never_resolves_for_startup():
    validated, error = manager._validate_payload(payload(), [], {})
    assert error is None
    assert validated['parameters'] == [{'name': 'path'}]
    command, error = manager._resolve_loaded_command_set(validated, {})
    assert command is None
    assert 'interactive' in error.lower()


def test_argument_step_storage_excludes_transient_input_fields():
    incoming = payload()
    incoming['steps'][0]['values'] = {'path': 'private input'}
    incoming['steps'][0]['argvText'] = 'editor draft'
    validated, error = manager._validate_payload(incoming, [], {})
    assert error is None
    assert validated['steps'] == payload()['steps']


@pytest.mark.parametrize('value', ['', "a'b; $(touch /tmp/injected) `id`", '雪 $HOME'])
def test_values_are_exact_posix_arguments_and_repeated_placeholders(value):
    from app.command_parameters import resolve_parameters

    text, error = resolve_parameters(payload(), {'path': value})
    assert error is None
    assert shlex.split(text) == ['printf', '%s', value, value]


@pytest.mark.parametrize('steps', [
    [{'type': 'inline', 'command': 'echo "{{path}}"'}],
    [{'type': 'argv', 'argv': ['{{path}}', 'hello']}],
    [{'type': 'argv', 'argv': ['echo', 'prefix{{path}}']}],
    [{'type': 'argv', 'argv': ['sh', '-c', '{{path}}']}],
    [{'type': 'argv', 'argv': ['echo', '{{unknown}}']}],
])
def test_parameterized_sets_reject_shell_source_and_non_argument_templates(steps):
    value = {**payload(), 'steps': steps}
    validated, error = manager._validate_payload(value, [], {})
    assert validated is None
    assert error


@pytest.mark.parametrize('values', [{}, {'path': 'x', 'extra': 'y'}, {'path': '\n'}, {'path': '\x1b'}, {'path': 'x' * 1025}])
def test_missing_unknown_control_or_unbounded_values_are_rejected(values):
    from app.command_parameters import resolve_parameters

    text, error = resolve_parameters(payload(), values)
    assert text is None
    assert error


def test_declarations_are_bounded_unique_and_explicit():
    for names in [['x', 'x'], ['bad-name'], ['x' * 33], [f'p{i}' for i in range(21)]]:
        validated, error = manager._validate_payload({
            **payload(), 'parameters': [{'name': name} for name in names],
        }, [], {})
        assert validated is None
        assert error


def test_legacy_shell_templates_remain_literal():
    literal = {'name': 'Legacy', 'steps': [{'type': 'inline', 'command': 'echo "{{path}}"'}]}
    validated, error = manager._validate_payload(literal, [], {})
    assert error is None
    assert manager._resolve_loaded_command_set(validated, {}) == ('echo "{{path}}"', None)


def test_saved_parameters_roundtrip_duplicate_preview_and_ownership(app):
    from app.models import User, db
    from app import post_connect_manager

    with app.app_context():
        users = [User(username=name, password_hash='unused') for name in ('parameter-owner', 'parameter-other')]
        db.session.add_all(users)
        db.session.commit()
        owner, other = [user.id for user in users]
        saved, error = manager.upsert_command_set(owner, payload())
        assert error is None
        copied, error = manager.duplicate_command_set(owner, saved['id'])
        assert error is None
        assert copied['parameters'] == saved['parameters']
        listed, error = manager.load_command_sets_with_resolution(owner)
        assert error is None
        assert all('interactive' in item['resolution_error'] for item in listed)
        assert manager.resolve_command_set_parameters(other, saved['id'], {'path': 'secret'}) == (None, 'Command set not found')
        resolved, error = manager.resolve_command_set_parameters(owner, saved['id'], {'path': 'private input'})
        assert error is None
        assert 'private input' in resolved
        assert 'private input' not in manager._command_sets_file(owner).read_text(encoding='utf-8')
        resolved, error = post_connect_manager.resolve_configuration(owner, {'startup_mode': 'command_set', 'command_set_id': saved['id']})
        assert resolved is None
        assert 'interactive' in error
