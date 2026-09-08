import pytest

from app.smb_paths import (
    SMBPath,
    SMBPathRejected,
    SMBShareName,
    SMB_PATH_MAX_COMPONENTS,
)


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


def test_dollar_is_allowed_in_paths_but_not_share_names():
    path = SMBPath.parse('/reports/budget$.xlsx')

    assert str(path) == '/reports/budget$.xlsx'
    assert str(path.parent().child('next$.xlsx')) == '/reports/next$.xlsx'
    with pytest.raises(SMBPathRejected):
        SMBShareName.parse('Finance$')


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


def test_component_depth_limit_applies_to_parse_and_child():
    maximum = '/' + '/'.join('a' for _ in range(SMB_PATH_MAX_COMPONENTS))
    path = SMBPath.parse(maximum)

    assert len(path.segments) == SMB_PATH_MAX_COMPONENTS
    with pytest.raises(SMBPathRejected, match='too many components'):
        SMBPath.parse(maximum + '/b')
    with pytest.raises(SMBPathRejected, match='too many components'):
        path.child('b')
    with pytest.raises(SMBPathRejected, match='too many components'):
        SMBPath(tuple('a' for _ in range(SMB_PATH_MAX_COMPONENTS + 1)))
