import pytest
from app import host_catalog, host_platform
from tests.host_identity_corpus import CASES


@pytest.mark.parametrize('name, output, expected', CASES, ids=[c[0] for c in CASES])
def test_corpus_maps_to_the_expected_identity(name, output, expected):
    result = host_platform.parse_identity(output)
    assert {key: result[key] for key in expected} == expected
    assert result['platform'] != 'server'


def test_corpus_covers_every_detectable_platform():
    seen = {host_platform.parse_identity(out)['platform'] for _, out, _ in CASES}
    detectable = host_catalog.PLATFORMS - host_catalog.BANNER_ONLY_PLATFORMS - {'server', 'docker'}
    assert detectable <= seen


def test_corpus_is_broad_and_uniquely_named():
    names = [name for name, _, _ in CASES]
    assert len(names) >= 40 and len(set(names)) == len(names)


@pytest.mark.parametrize('name, output, expected', CASES, ids=[c[0] for c in CASES])
def test_corpus_results_hold_only_catalog_values(name, output, expected):
    result = host_platform.parse_identity(output)
    assert set(result) == {'state', 'platform', 'family', 'os_id', 'os_version', 'virt', 'graphical',
                           'guests', 'services', 'container_access'}
    assert result['state'] in {'detected', 'unavailable'}
    assert result['platform'] is None or result['platform'] in host_catalog.PLATFORMS
    assert result['family'] is None or result['family'] in set(host_catalog.FAMILIES.values())
    assert result['virt'] is None or result['virt'] in host_catalog.VIRT_KINDS
    assert result['container_access'] is None or result['container_access'] in host_catalog.CONTAINER_ACCESS
    assert result['services'] == sorted(set(result['services']))
    assert set(result['services']) <= host_catalog.SERVICES and len(result['services']) <= host_catalog.MAX_SERVICES
