"""Tests for named post-connect command sets."""
import json
import shutil
import subprocess

import pytest


def create_user(app, username='command-set-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='not-used-in-this-test')
        db.session.add(user)
        db.session.commit()
        return user.id


def library_commands():
    return [
        {
            'id': 'cmd-echo',
            'name': 'Echo',
            'command': 'echo',
            'parameters': 'default',
            'description': 'Echo text',
            'os': ['all'],
            'category': 'custom',
        },
        {
            'id': 'cmd-pwd',
            'name': 'Working directory',
            'command': 'pwd',
            'parameters': '',
            'description': 'Print directory',
            'os': ['all'],
            'category': 'files',
        },
    ]


def test_load_command_sets_returns_empty_for_missing_file(app):
    from app import command_set_manager

    user_id = create_user(app)
    with app.app_context():
        command_sets, error = command_set_manager.load_command_sets(user_id)

    assert error is None
    assert command_sets == []


def test_load_command_sets_reports_corrupt_json_without_overwriting(app):
    from app import command_set_manager
    from app.models import User

    user_id = create_user(app)
    with app.app_context():
        user = User.query.get(user_id)
        path = user.get_data_dir() / 'command_sets.json'
        path.write_text('{broken', encoding='utf-8')

        command_sets, error = command_set_manager.load_command_sets(user_id)

        assert command_sets is None
        assert error == 'Command set storage is unreadable'
        assert path.read_text(encoding='utf-8') == '{broken'


def test_upsert_creates_updates_and_loads_command_set(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'description': 'Prepare the host',
            'steps': [{'type': 'library', 'command_id': 'cmd-pwd'}],
        })
        assert error is None
        assert created['id']
        assert created['created_at'] == created['updated_at']

        updated, error = command_set_manager.upsert_command_set(user_id, {
            'id': created['id'],
            'name': 'Bootstrap updated',
            'description': '',
            'steps': [{'type': 'inline', 'command': 'whoami'}],
        })

        assert error is None
        assert updated['id'] == created['id']
        assert updated['created_at'] == created['created_at']
        assert updated['name'] == 'Bootstrap updated'
        assert command_set_manager.load_command_sets(user_id)[0] == [updated]


def test_upsert_defaults_missing_sudo_to_false_and_accepts_boolean(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        legacy_compatible, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Existing behavior',
            'steps': [{'type': 'inline', 'command': 'whoami'}],
        })
        sudo_set, sudo_error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Privileged',
            'use_sudo': True,
            'steps': [{'type': 'inline', 'command': 'apt update'}],
        })

    assert error is None
    assert legacy_compatible['use_sudo'] is False
    assert sudo_error is None
    assert sudo_set['use_sudo'] is True


@pytest.mark.parametrize('invalid', [None, 1, 0, 'true', [], {}])
def test_upsert_rejects_non_boolean_sudo(app, monkeypatch, invalid):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        saved, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Invalid {type(invalid).__name__}',
            'use_sudo': invalid,
            'steps': [{'type': 'inline', 'command': 'whoami'}],
        })

    assert saved is None
    assert error == 'Command set sudo option must be a boolean'


def test_upsert_rejects_case_insensitive_duplicate_names(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        first, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'inline', 'command': 'pwd'}],
        })
        assert error is None
        duplicate, error = command_set_manager.upsert_command_set(user_id, {
            'name': ' bootstrap ',
            'steps': [{'type': 'inline', 'command': 'whoami'}],
        })

    assert duplicate is None
    assert error == 'A command set with this name already exists'


def test_upsert_rejects_invalid_name_steps_and_references(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    cases = [
        ({'name': '', 'steps': [{'type': 'inline', 'command': 'pwd'}]}, 'Command set name is required'),
        ({'name': 'x' * 129, 'steps': [{'type': 'inline', 'command': 'pwd'}]}, 'Command set name must be 128 characters or fewer'),
        ({'name': 'Empty', 'steps': []}, 'Command set must contain at least one step'),
        ({'name': 'Bad type', 'steps': [{'type': 'unknown'}]}, 'Command set step 1 has an invalid type'),
        ({'name': 'Blank inline', 'steps': [{'type': 'inline', 'command': ''}]}, 'Command set step 1 is empty'),
        ({'name': 'Missing ref', 'steps': [{'type': 'library', 'command_id': 'missing'}]}, "Command set step 1 references a missing command"),
    ]

    with app.app_context():
        for payload, expected_error in cases:
            command_set, error = command_set_manager.upsert_command_set(user_id, payload)
            assert command_set is None
            assert error == expected_error


def test_resolve_preserves_order_and_parameter_semantics(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [
                {'type': 'library', 'command_id': 'cmd-echo'},
                {'type': 'library', 'command_id': 'cmd-echo', 'parameters_override': ''},
                {'type': 'library', 'command_id': 'cmd-echo', 'parameters_override': 'custom'},
                {'type': 'inline', 'command': 'echo €\r\npwd'},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None

        resolved, error = command_set_manager.resolve_command_set(user_id, created['id'])

    assert error is None
    assert resolved == (
        'echo default && echo && echo custom && '
        'echo €\npwd && pwd'
    )


def test_resolve_chains_steps_without_rewriting_internal_inline_lines(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Mixed blocks',
            'steps': [
                {'type': 'inline', 'command': 'cd /srv\necho ready\n'},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == 'cd /srv\necho ready && pwd'


@pytest.mark.parametrize(
    ('use_sudo', 'expected'),
    [
        (False, 'echo ready && pwd'),
        (True, 'sudo echo ready && sudo pwd'),
    ],
)
def test_resolve_trims_trailing_whitespace_at_step_boundaries(
    app, monkeypatch, use_sudo, expected
):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Trailing whitespace {use_sudo}',
            'use_sudo': use_sudo,
            'steps': [
                {'type': 'inline', 'command': 'echo ready\n   '},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == expected


@pytest.mark.parametrize(
    ('use_sudo', 'expected'),
    [
        (False, 'echo ready &&\n# note\npwd'),
        (True, 'sudo echo ready &&\n# note\nsudo pwd'),
    ],
)
def test_resolve_preserves_trailing_comment_without_hiding_next_step(
    app, monkeypatch, use_sudo, expected
):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Trailing comment {use_sudo}',
            'use_sudo': use_sudo,
            'steps': [
                {'type': 'inline', 'command': 'echo ready\n# note'},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == expected


@pytest.mark.parametrize(
    ('command', 'use_sudo', 'expected'),
    [
        ('echo ready # note', False, 'echo ready && # note\npwd'),
        ('echo ready; # note', False, 'echo ready && # note\npwd'),
        ('echo ready # note', True, 'sudo echo ready && # note\nsudo pwd'),
        ('echo ready; # note', True, 'sudo echo ready && # note\nsudo pwd'),
    ],
)
def test_resolve_preserves_inline_comment_without_hiding_next_step(
    app, monkeypatch, command, use_sudo, expected
):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Inline comment {command} {use_sudo}',
            'use_sudo': use_sudo,
            'steps': [
                {'type': 'inline', 'command': command},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == expected


@pytest.mark.parametrize(
    'command',
    ["echo '#'", r'echo \#', 'echo value#suffix'],
)
def test_resolve_does_not_treat_literal_hash_as_shell_comment(
    app, monkeypatch, command
):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Literal hash {command}',
            'steps': [
                {'type': 'inline', 'command': command},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == f'{command} && pwd'


@pytest.mark.parametrize(
    ('use_sudo', 'expected'),
    [
        (False, 'echo first && : &&\n# note\npwd'),
        (True, 'sudo echo first && : &&\n# note\nsudo pwd'),
    ],
)
def test_resolve_treats_comment_only_step_as_successful_noop(
    app, monkeypatch, use_sudo, expected
):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': f'Comment only {use_sudo}',
            'use_sudo': use_sudo,
            'steps': [
                {'type': 'inline', 'command': 'echo first'},
                {'type': 'inline', 'command': '# note'},
                {'type': 'library', 'command_id': 'cmd-pwd'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == expected


def test_trailing_comment_boundary_preserves_errexit_semantics(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager,
        'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Preserve errexit',
            'steps': [
                {
                    'type': 'inline',
                    'command': 'set -e\nfalse\necho SHOULD_NOT_RUN\n# note',
                },
                {'type': 'inline', 'command': 'echo NEXT_SHOULD_NOT_RUN'},
            ],
        })
        assert error is None
        resolved, error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert error is None
    assert resolved == (
        'set -e\nfalse\necho SHOULD_NOT_RUN &&\n'
        '# note\necho NEXT_SHOULD_NOT_RUN'
    )

    shell = shutil.which('sh')
    if shell is None:
        pytest.skip('POSIX shell is not available')
    completed = subprocess.run(
        [shell, '-c', resolved],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert 'SHOULD_NOT_RUN' not in completed.stdout
    assert 'NEXT_SHOULD_NOT_RUN' not in completed.stdout


def test_resolve_sudo_prefixes_commands_without_changing_non_commands(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Privileged bootstrap',
            'use_sudo': True,
            'steps': [
                {'type': 'library', 'command_id': 'cmd-echo'},
                {
                    'type': 'inline',
                    'command': (
                        '  systemctl restart nginx\n\n# note\n'
                        'sudo reboot\tsafe\n'
                        'sudo; echo semicolon\n'
                        'sudo&&echo and\n'
                        'sudo||echo or\n'
                        'sudo>output'
                    ),
                },
            ],
        })
        assert error is None
        resolved, resolve_error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert resolve_error is None
    assert resolved == (
        'sudo echo default && '
        '  sudo systemctl restart nginx\n'
        '\n'
        '# note\n'
        'sudo reboot\tsafe\n'
        'sudo; echo semicolon\n'
        'sudo&&echo and\n'
        'sudo||echo or\n'
        'sudo>output'
    )


def test_resolve_revalidates_length_after_sudo_prefix(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Too long after prefix',
            'use_sudo': True,
            'steps': [{'type': 'inline', 'command': 'x' * 4092}],
        })
        assert error is None
        resolved, resolve_error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert resolved is None
    assert resolve_error == 'Startup commands must not exceed 4096 characters'


def test_resolve_revalidates_length_after_step_separators(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Too long after separators',
            'steps': [
                {'type': 'inline', 'command': 'x' * 2047},
                {'type': 'inline', 'command': 'y' * 2047},
            ],
        })
        assert error is None
        resolved, resolve_error = command_set_manager.resolve_command_set(
            user_id, created['id']
        )

    assert resolved is None
    assert resolve_error == 'Startup commands must not exceed 4096 characters'


def test_resolve_rejects_reference_removed_after_save(app, monkeypatch):
    from app import command_manager, command_set_manager

    commands = library_commands()
    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: commands)
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'library', 'command_id': 'cmd-pwd'}],
        })
        assert error is None
        commands.clear()

        resolved, error = command_set_manager.resolve_command_set(user_id, created['id'])

    assert resolved is None
    assert error == "Command set 'Bootstrap' step 1 references a missing command"


def test_upsert_rejects_nul_and_raw_or_normalized_limit_violations(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    cases = [
        ('Nul', 'echo safe\x00echo unsafe', 'Startup commands must not contain NUL bytes'),
        ('Raw too long', '\r\n' * 2049, 'Startup commands must not exceed 4096 characters'),
        ('Normalized too long', 'x' * 4097, 'Startup commands must not exceed 4096 characters'),
    ]

    with app.app_context():
        for name, command, expected_error in cases:
            command_set, error = command_set_manager.upsert_command_set(user_id, {
                'name': name,
                'steps': [{'type': 'inline', 'command': command}],
            })
            assert command_set is None
            assert error == expected_error


def test_duplicate_uses_new_id_and_unique_copy_name_but_keeps_references(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        original, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'use_sudo': True,
            'steps': [{'type': 'library', 'command_id': 'cmd-pwd'}],
        })
        assert error is None
        duplicate, error = command_set_manager.duplicate_command_set(user_id, original['id'])

    assert error is None
    assert duplicate['id'] != original['id']
    assert duplicate['name'] == 'Bootstrap Copy'
    assert duplicate['steps'] == original['steps']
    assert duplicate['use_sudo'] is True


def test_get_command_usage_and_delete_guard_report_names(app, monkeypatch):
    from app import command_manager, command_set_manager, profile_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'library', 'command_id': 'cmd-pwd'}],
        })
        assert error is None
        usages, error = command_set_manager.get_command_usage(user_id, 'cmd-pwd')
        assert error is None
        assert [item['name'] for item in usages] == ['Bootstrap']

        profile_manager.save_profiles(user_id, [{
            'id': 'profile-1',
            'name': 'Production',
            'command_set_id': created['id'],
        }])
        success, error, profiles = command_set_manager.delete_command_set(user_id, created['id'])

    assert success is False
    assert error == 'Command set is used by 1 profile'
    assert profiles == ['Production']


def test_delete_unreferenced_command_set(app, monkeypatch):
    from app import command_manager, command_set_manager

    monkeypatch.setattr(command_manager, 'get_all_commands', lambda user_id, os_filter=None: library_commands())
    user_id = create_user(app)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Disposable',
            'steps': [{'type': 'inline', 'command': 'pwd'}],
        })
        assert error is None
        success, error, profiles = command_set_manager.delete_command_set(user_id, created['id'])
        loaded, load_error = command_set_manager.load_command_sets(user_id)

    assert (success, error, profiles) == (True, None, [])
    assert load_error is None
    assert loaded == []
