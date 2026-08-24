import pytest

from app.smb_paths import SMBPath, SMBPathRejected, SMBShareName


@pytest.mark.parametrize(
    'value',
    [
        '..',
        '/a/../b',
        r'\\server\share',
        r'/a\b',
        '/file:stream',
        '/a/*',
        '/CON',
        '/nul.txt',
        '/a\x00b',
        '/trailing.',
        '/trailing ',
        '//double',
    ],
)
def test_smb_path_rejects_escape_and_windows_special_cases(value):
    with pytest.raises(SMBPathRejected):
        SMBPath.parse(value)


@pytest.mark.parametrize(
    'share',
    ['IPC$', 'ADMIN$', 'C$', 'a/b', r'a\b', 'a:b', 'bad.', 'bad ', '', '.', '..'],
)
def test_share_rejects_admin_and_non_component_values(share):
    with pytest.raises(SMBPathRejected):
        SMBShareName.parse(share)


def test_root_unicode_and_case_are_preserved():
    assert str(SMBPath.parse('/')) == '/'
    assert str(SMBPath.parse('/Berichte/Überblick.txt')) == '/Berichte/Überblick.txt'
    assert str(SMBPath.parse('/Case/File')) != str(SMBPath.parse('/case/file'))


def test_only_validated_ip_share_and_segments_build_unc():
    path = SMBPath.parse('/Berichte/2026.txt')
    share = SMBShareName.parse('Dokumente')

    assert path.to_unc('10.0.0.8', share) == (
        r'\\10.0.0.8\Dokumente\Berichte\2026.txt'
    )
    with pytest.raises(SMBPathRejected):
        path.to_unc('nas.example', share)


def test_child_accepts_exactly_one_safe_component():
    root = SMBPath.parse('/')
    assert str(root.child('Überblick.txt')) == '/Überblick.txt'
    for name in ('../escape', 'a/b', r'a\b', 'NUL'):
        with pytest.raises(SMBPathRejected):
            root.child(name)


def test_length_limits_are_enforced():
    with pytest.raises(SMBPathRejected):
        SMBShareName.parse('a' * 81)
    with pytest.raises(SMBPathRejected):
        SMBPath.parse('/' + ('a' * 256))
