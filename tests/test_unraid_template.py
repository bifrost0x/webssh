"""The Unraid template and CA profile stay valid and match the homelab Compose."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from xml.etree import ElementTree

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'unraid' / 'webssh.xml'
PROFILE = ROOT / 'ca_profile.xml'
RAW_MAIN = 'https://raw.githubusercontent.com/bifrost0x/webssh/main/'
IMAGE = 'ghcr.io/bifrost0x/webssh:latest'
# Unraid creates missing template paths as nobody:users; the image must run as
# exactly that identity to write them (dynamix.docker.manager xmlToCommand).
UNRAID_USER = '--user 99:100'
CONFIG_ATTRIBUTES = {
    'Name', 'Target', 'Default', 'Mode', 'Description', 'Type', 'Display', 'Required', 'Mask',
}
REQUIRED_TAGS = (
    'Name', 'Repository', 'Overview', 'Category', 'Icon', 'Project', 'Support',
    'TemplateURL', 'WebUI',
)
COMPOSE_FILE = ROOT / 'docker-compose.yml'
INTERPOLATION = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)')


def template():
    return ElementTree.parse(TEMPLATE).getroot()


def configs(kind):
    return [entry for entry in template().findall('Config') if entry.get('Type') == kind]


def raw_url_path(url):
    assert url.startswith(RAW_MAIN), url
    return ROOT / url.removeprefix(RAW_MAIN)


@pytest.fixture(scope='module')
def homelab_service():
    docker = shutil.which('docker')
    if docker is None:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            pytest.fail('CI must compare the template with the resolved Compose file')
        pytest.skip('Docker Compose CLI is unavailable')
    # Compare against the file's own defaults, never values from the shell.
    interpolated = set(INTERPOLATION.findall(COMPOSE_FILE.read_text(encoding='utf-8')))
    environment = {key: value for key, value in os.environ.items() if key not in interpolated}
    result = subprocess.run(
        [docker, 'compose', '-f', 'docker-compose.yml', 'config', '--format', 'json'],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)['services']['webssh']


def test_template_is_a_version_two_container_with_required_metadata():
    root = template()

    assert root.tag == 'Container' and root.get('version') == '2'
    for tag in REQUIRED_TAGS:
        element = root.find(tag)
        assert element is not None and (element.text or '').strip(), tag
    assert root.findtext('Network') == 'bridge'
    assert root.findtext('Privileged') == 'false'


def test_template_url_points_at_this_exact_file_on_main():
    assert raw_url_path(template().findtext('TemplateURL')) == TEMPLATE


@pytest.mark.parametrize('tag, signature', [('Icon', b'\x89PNG\r\n\x1a\n'),
                                            ('Screenshot', b'\x89PNG\r\n\x1a\n')])
def test_media_urls_resolve_to_tracked_png_files(tag, signature):
    # Unraid caches the icon as <name>-icon.png, so an SVG would not render.
    path = raw_url_path(template().findtext(tag))
    assert path.read_bytes()[:8] == signature


def test_template_references_the_published_image(homelab_service):
    assert template().findtext('Repository') == IMAGE == homelab_service['image']


def test_every_config_entry_is_complete_and_consistent():
    entries = template().findall('Config')
    assert entries
    names = [entry.get('Name') for entry in entries]
    targets = [entry.get('Target') for entry in entries]
    assert len(names) == len(set(names)) and len(targets) == len(set(targets))
    for entry in entries:
        assert set(entry.attrib) == CONFIG_ATTRIBUTES, entry.attrib
        assert entry.get('Type') in {'Port', 'Path', 'Variable'}
        assert entry.get('Display') in {'always', 'advanced'}
        assert entry.get('Required') in {'true', 'false'}
        assert entry.get('Mask') in {'true', 'false'}
        assert entry.get('Description').strip()
        assert (entry.text or '') == entry.get('Default'), entry.get('Name')


def test_ports_and_webui_match_compose(homelab_service):
    published = {int(port['target']): port['published'] for port in homelab_service['ports']}
    ports = configs('Port')

    assert {int(entry.get('Target')) for entry in ports} == set(published)
    for entry in ports:
        assert entry.get('Mode') == 'tcp'
        assert entry.get('Default') == str(published[int(entry.get('Target'))])
    assert template().findtext('WebUI') == 'http://[IP]:[PORT:5000]/'


def test_container_paths_match_compose_volumes(homelab_service):
    compose_targets = {volume['target'] for volume in homelab_service['volumes']}
    paths = configs('Path')

    assert {entry.get('Target') for entry in paths} == compose_targets
    for entry in paths:
        assert entry.get('Mode') == 'rw'
        assert entry.get('Default').startswith('/mnt/user/appdata/webssh/')
    assert len({entry.get('Default') for entry in paths}) == len(paths)


def test_variables_match_the_homelab_compose_environment(homelab_service):
    variables = {entry.get('Target'): entry.get('Default') for entry in configs('Variable')}
    expected = homelab_service['environment']

    assert variables == {key: value or '' for key, value in expected.items()}


def test_template_runs_as_the_unraid_appdata_owner_without_secrets():
    root = template()
    variables = {entry.get('Target'): entry for entry in configs('Variable')}

    # Only the user switch; never root, privileges, capabilities or devices.
    assert root.findtext('ExtraParams') == UNRAID_USER
    assert (root.findtext('PostArgs') or '') == ''
    assert 'SECRET_KEY' not in variables
    for name, entry in variables.items():
        if any(marker in name for marker in ('SECRET', 'PASSWORD', 'TOKEN')):
            assert entry.get('Mask') == 'true' and entry.get('Default') == '', name


def test_overview_states_the_security_boundary_and_first_admin():
    overview = ' '.join(template().findtext('Overview').split())

    assert 'SSH gateway' in overview
    assert 'Do not publish it to the internet' in overview
    assert 'first account created in the browser becomes the administrator' in overview
    assert 'docs/wiki/Production-Deployment.md' in overview


def test_ca_profile_is_complete():
    root = ElementTree.parse(PROFILE).getroot()

    assert root.tag == 'CommunityApplications'
    assert (root.findtext('Profile') or '').strip()
    assert root.findtext('WebPage') == 'https://getwebssh.com'
    assert raw_url_path(root.findtext('Icon')).read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'
    assert 'https://github.com/bifrost0x/webssh/issues' in root.findtext('Profile')


def test_install_guide_documents_the_template_and_its_identity():
    guide = (ROOT / 'docs' / 'wiki' / 'Install-on-Unraid.md').read_text(encoding='utf-8')

    assert template().findtext('TemplateURL') in guide
    assert UNRAID_USER in guide
    assert 'chown -R 99:100' in guide
    assert 'assets/webssh-icon.png' in guide
