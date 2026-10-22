"""Only reorder the known hosted Ubuntu mirrors, preserving all trust inputs."""

from pathlib import Path

import pytest


AZURE = 'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n'
ARCHIVE = 'https://archive.ubuntu.com/ubuntu/\tpriority:2\n'


def test_only_known_priorities_change_and_all_other_text_is_preserved():
    from scripts.ci_apt_mirrors import prefer_official_archive

    other = '# preserve this comment\nhttps://security.ubuntu.com/ubuntu/ priority:3\nhttps://custom.example/ubuntu/ priority:4\n'
    original = other + AZURE + ARCHIVE
    expected = other + AZURE.replace('priority:1', 'priority:9') + ARCHIVE.replace('priority:2', 'priority:1')
    assert prefer_official_archive(original) == expected
    assert prefer_official_archive(expected) == expected


def test_whitespace_line_endings_and_comments_are_preserved():
    from scripts.ci_apt_mirrors import prefer_official_archive

    original = ('  ' + AZURE.rstrip('\n') + '  # fallback\r\n'
                + '\t' + ARCHIVE.rstrip('\n') + ' # primary')
    assert prefer_official_archive(original) == original.replace('priority:1', 'priority:9').replace('priority:2', 'priority:1')


@pytest.mark.parametrize('original', [
    '', AZURE, ARCHIVE,
    AZURE + ARCHIVE.replace('https://', 'http://'),
    AZURE.replace('/ubuntu/', '/ubuntu') + ARCHIVE,
    AZURE.replace('priority:1', 'priority:11') + ARCHIVE,
    AZURE + ARCHIVE.replace('priority:2', 'priority:7'),
    AZURE + ARCHIVE.replace('priority:2', 'priority:2 unexpected'),
    AZURE + ARCHIVE + ARCHIVE,
    AZURE + AZURE + ARCHIVE,
    '# ' + AZURE + ARCHIVE,
    AZURE.replace('azure.archive.ubuntu.com', 'azure.archive.ubuntu.com.evil') + ARCHIVE,
])
def test_unknown_malformed_incomplete_or_duplicate_configuration_is_unchanged(original):
    from scripts.ci_apt_mirrors import prefer_official_archive

    assert prefer_official_archive(original) == original


def test_entrypoint_uses_only_fixed_path_and_rejects_arguments(monkeypatch):
    from scripts import ci_apt_mirrors as mirrors

    assert mirrors.MIRRORS_FILE == Path('/etc/apt/apt-mirrors.txt')
    monkeypatch.setattr(mirrors.sys, 'argv', ['ci_apt_mirrors.py', '/other'])
    assert mirrors.main() == 2


def test_missing_file_is_skipped_and_real_file_update_is_idempotent(tmp_path, monkeypatch):
    from scripts import ci_apt_mirrors as mirrors

    target = tmp_path / 'mirrors'
    monkeypatch.setattr(mirrors, 'MIRRORS_FILE', target)
    monkeypatch.setattr(mirrors.sys, 'argv', ['ci_apt_mirrors.py'])
    assert mirrors.main() == 0
    assert not target.exists()
    target.write_text(AZURE + ARCHIVE)
    assert mirrors.main() == 0
    expected = target.read_bytes()
    assert b'priority:9' in expected
    assert mirrors.main() == 0
    assert target.read_bytes() == expected


def test_symlink_is_refused_without_modifying_target(tmp_path, monkeypatch):
    from scripts import ci_apt_mirrors as mirrors

    target = tmp_path / 'real-mirrors'
    target.write_text(AZURE + ARCHIVE)
    link = tmp_path / 'mirrors'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('Symlink creation is not permitted on this platform')
    monkeypatch.setattr(mirrors, 'MIRRORS_FILE', link)
    monkeypatch.setattr(mirrors.sys, 'argv', ['ci_apt_mirrors.py'])
    assert mirrors.main() != 0
    assert target.read_text() == AZURE + ARCHIVE


def test_installer_limits_privileged_mirror_setup_to_hosted_actions_before_fast_path():
    source = (Path(__file__).resolve().parents[1] / 'scripts/install_ci_test_system_deps.sh').read_text()
    assert '"${GITHUB_ACTIONS:-}" == true' in source
    assert '"${RUNNER_ENVIRONMENT:-}" == github-hosted' in source
    assert 'sudo "$(command -v python)" "$script_dir/ci_apt_mirrors.py"' in source
    assert source.index('ci_apt_mirrors.py') < source.index('packages=(libldap2-dev libsasl2-dev)')
