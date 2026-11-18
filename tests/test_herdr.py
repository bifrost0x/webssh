"""Herdr snapshots are untrusted input and are reduced to a bounded agent list."""

import json
from pathlib import Path

import pytest

from app import herdr

FIXTURE = Path(__file__).parent / 'fixtures' / 'herdr_snapshot.json'


def encode(agents, panes=None, **snapshot):
    return json.dumps({'id': 'cli:api:snapshot', 'result': {
        'type': 'session_snapshot',
        'snapshot': {'agents': agents, 'panes': panes or [], **snapshot},
    }}).encode('utf-8')


def agent(pane_id='w1:p1', **fields):
    return {'pane_id': pane_id, 'agent': 'codex', 'agent_status': 'idle',
            'cwd': '/srv/app', **fields}


def test_recorded_snapshot_yields_the_expected_agents():
    assert herdr.parse_snapshot(FIXTURE.read_bytes()) == {
        'agents': [
            {'id': 'w1:p1', 'kind': 'claude', 'label': 'build',
             'cwd': '/home/deploy', 'status': 'working'},
            {'id': 'w1:p2', 'kind': 'codex', 'label': 'reviewer',
             'cwd': '/home/deploy', 'status': 'blocked'},
            {'id': 'w1:p4', 'kind': 'pi', 'label': '',
             'cwd': '/home/deploy', 'status': 'idle'},
        ],
        'truncated': False,
    }


def test_recorded_snapshot_contains_no_local_identifiers():
    text = FIXTURE.read_text(encoding='utf-8')
    assert json.loads(text)['result']['snapshot']['version'] == '0.9.5'
    for marker in ('Users', 'C:\\\\', '/root', '172.'):
        assert marker not in text


def test_output_exposes_only_the_documented_fields():
    result = herdr.parse_snapshot(encode(
        [agent(title='secret title', terminal_title='secret terminal',
               tokens={'branch': 'secret'}, state_labels={'idle': 'secret'},
               agent_session={'value': 'secret'}, foreground_cwd='/secret',
               terminal_id='term_secret', unknown_field='secret')],
        panes=[{'pane_id': 'w1:p1', 'label': 'api', 'title': 'secret', 'tokens': {'a': 'secret'}}],
        layouts=[{'secret': True}], workspaces=[{'label': 'secret'}], future='secret',
    ))
    assert result == {'agents': [{
        'id': 'w1:p1', 'kind': 'codex', 'label': 'api', 'cwd': '/srv/app', 'status': 'idle',
    }], 'truncated': False}
    assert 'secret' not in json.dumps(result)


def test_kind_prefers_the_display_name_and_label_prefers_the_agent_name():
    result = herdr.parse_snapshot(encode(
        [agent(display_agent='Codex CLI', name='reviewer'), agent('w1:p2')],
        panes=[{'pane_id': 'w1:p1', 'label': 'ignored'}, {'pane_id': 'w1:p2', 'label': 'logs'}],
    ))
    assert [(item['kind'], item['label']) for item in result['agents']] == [
        ('Codex CLI', 'reviewer'), ('codex', 'logs'),
    ]


@pytest.mark.parametrize('status,expected', [
    ('idle', 'idle'), ('working', 'working'), ('blocked', 'blocked'), ('done', 'done'),
    ('unknown', 'unknown'), ('finished', 'unknown'), ('IDLE', 'unknown'), ('', 'unknown'),
    (None, 'unknown'), (1, 'unknown'), (['idle'], 'unknown'), ({'idle': True}, 'unknown'),
])
def test_unrecognized_status_becomes_unknown(status, expected):
    result = herdr.parse_snapshot(encode([agent(agent_status=status)]))
    assert result['agents'][0]['status'] == expected


@pytest.mark.parametrize('value', [None, 1, 1.5, True, ['x'], {'x': 'y'}])
def test_wrongly_typed_text_fields_become_empty(value):
    result = herdr.parse_snapshot(encode(
        [agent(agent=value, display_agent=value, name=value, cwd=value)],
        panes=[{'pane_id': 'w1:p1', 'label': value}],
    ))
    assert result['agents'] == [{'id': 'w1:p1', 'kind': '', 'label': '', 'cwd': '', 'status': 'idle'}]


def test_missing_fields_become_empty():
    result = herdr.parse_snapshot(encode([{'pane_id': 'w1:p1'}]))
    assert result['agents'] == [{'id': 'w1:p1', 'kind': '', 'label': '', 'cwd': '', 'status': 'unknown'}]


@pytest.mark.parametrize('pane_id', [
    None, 1, '', 'w1 p1', 'w1/p1', 'w1:p1\n', '<b>', 'a' * 65, ['w1:p1'], 'w1:p\u00e9',
])
def test_agents_with_an_invalid_id_are_dropped(pane_id):
    result = herdr.parse_snapshot(encode([agent(pane_id), agent('w1:p2')]))
    assert [item['id'] for item in result['agents']] == ['w1:p2']
    assert result['truncated'] is False


def test_non_object_agents_and_duplicate_ids_are_dropped():
    result = herdr.parse_snapshot(encode(
        ['w1:p1', None, 3, [], agent('w1:p1', name='first'), agent('w1:p1', name='second')]))
    assert [item['label'] for item in result['agents']] == ['first']


def test_agent_list_is_capped_and_marked_truncated():
    exact = herdr.parse_snapshot(encode([agent(f'w1:p{index}') for index in range(64)]))
    assert len(exact['agents']) == 64 and exact['truncated'] is False
    over = herdr.parse_snapshot(encode([agent(f'w1:p{index}') for index in range(65)]))
    assert [item['id'] for item in over['agents']] == [f'w1:p{index}' for index in range(64)]
    assert over['truncated'] is True


def test_invalid_entries_do_not_count_towards_the_cap():
    entries = [None] * 100 + [agent(f'w1:p{index}') for index in range(64)]
    result = herdr.parse_snapshot(encode(entries))
    assert len(result['agents']) == 64 and result['truncated'] is False


def test_pane_lookup_reads_a_bounded_number_of_panes():
    panes = [{'pane_id': f'w1:p{index}', 'label': f'pane {index}'} for index in range(300)]
    result = herdr.parse_snapshot(encode([agent('w1:p255'), agent('w1:p256')], panes=panes))
    assert [item['label'] for item in result['agents']] == ['pane 255', '']


@pytest.mark.parametrize('panes', [None, 'panes', 3, {'pane_id': 'w1:p1'}, [None, 3, 'x', []]])
def test_unusable_pane_list_only_loses_labels(panes):
    payload = json.dumps({'result': {'type': 'session_snapshot',
                                     'snapshot': {'agents': [agent()], 'panes': panes}}}).encode()
    assert herdr.parse_snapshot(payload)['agents'][0]['label'] == ''


@pytest.mark.parametrize('raw,expected', [
    ('build\x00\x07\x1b[31m', 'build[31m'),
    ('a\x7fb\x80c\x9fd', 'abcd'),
    ('line\nbreak\ttab\rreturn', 'linebreaktabreturn'),
    ('safe\u202egnp.exe', 'safegnp.exe'),
    ('\u2066a\u2067b\u2068c\u2069\u200e\u200f\u061c', 'abc'),
    ('zero\u200bwidth\ufeff', 'zerowidth'),
    ('line\u2028para\u2029end', 'lineparaend'),
    ('private\ue000use', 'privateuse'),
    ('   padded   ', 'padded'),
    ('<img src=x onerror=alert(1)>', '<img src=x onerror=alert(1)>'),
    ('Grüße 東京 🚀', 'Grüße 東京 🚀'),
])
def test_control_and_bidi_characters_are_removed(raw, expected):
    result = herdr.parse_snapshot(encode(
        [agent(agent=raw, name=raw, cwd=raw)]))
    assert result['agents'][0]['kind'] == expected
    assert result['agents'][0]['label'] == expected
    assert result['agents'][0]['cwd'] == expected


def test_lone_surrogates_are_removed():
    payload = (b'{"result":{"type":"session_snapshot","snapshot":{"agents":['
               b'{"pane_id":"w1:p1","agent":"a\\ud800b","name":"\\udfffx","cwd":"/\\ud83d"}]}}}')
    result = herdr.parse_snapshot(payload)
    assert result['agents'][0]['kind'] == 'ab'
    assert result['agents'][0]['label'] == 'x'
    assert result['agents'][0]['cwd'] == '/'
    json.dumps(result).encode('utf-8')


def test_long_values_are_cut_to_their_limits():
    result = herdr.parse_snapshot(encode(
        [agent(agent='k' * 500, name='n' * 500, cwd='/' + 'c' * 2000)],
    ))
    assert result['agents'][0]['kind'] == 'k' * 120
    assert result['agents'][0]['label'] == 'n' * 120
    assert result['agents'][0]['cwd'] == '/' + 'c' * 511
    result = herdr.parse_snapshot(encode(
        [agent('w1:p1', name=None)], panes=[{'pane_id': 'w1:p1', 'label': 'p' * 500}]))
    assert result['agents'][0]['label'] == 'p' * 120


def test_limit_applies_after_removed_characters():
    result = herdr.parse_snapshot(encode([agent(name='\u202e' * 200 + 'visible')]))
    assert result['agents'][0]['label'] == 'visible'


@pytest.mark.parametrize('payload', [
    b'', b'not json', b'{', b'[]', b'null', b'"text"', b'1',
    b'{"id":"cli:api:snapshot"}',
    b'{"result":null}', b'{"result":[]}',
    b'{"result":{"type":"session_snapshot"}}',
    b'{"result":{"type":"session_snapshot","snapshot":[]}}',
    b'{"result":{"type":"session_snapshot","snapshot":{}}}',
    b'{"result":{"type":"session_snapshot","snapshot":{"agents":{}}}}',
    b'{"result":{"type":"agent_list","snapshot":{"agents":[]}}}',
    b'{"result":{"snapshot":{"agents":[]}}}',
    b'{"result":{"agents":[]}}',
    b'{"error":{"code":"server_not_running","message":"no server"}}',
    b'\xff\xfe{"result":{}}',
    b'{"result":{"type":"session_snapshot","snapshot":{"agents":[{"pane_id":"\xff"}]}}}',
])
def test_unusable_input_raises_value_error(payload):
    with pytest.raises(ValueError):
        herdr.parse_snapshot(payload)


@pytest.mark.parametrize('payload', [None, 'text', 3, ['x']])
def test_non_bytes_input_raises_value_error(payload):
    with pytest.raises(ValueError):
        herdr.parse_snapshot(payload)


def test_deeply_nested_input_raises_value_error():
    with pytest.raises(ValueError):
        herdr.parse_snapshot(b'[' * 200000)


def test_input_over_the_size_limit_is_rejected_without_parsing(monkeypatch):
    valid = encode([agent()])
    padded = valid + b' ' * (herdr.MAX_SNAPSHOT_BYTES - len(valid))
    assert len(padded) == herdr.MAX_SNAPSHOT_BYTES
    assert len(herdr.parse_snapshot(padded)['agents']) == 1
    monkeypatch.setattr(herdr.json, 'loads', lambda *args, **kwargs: pytest.fail('parsed'))
    with pytest.raises(ValueError):
        herdr.parse_snapshot(padded + b' ')


def test_empty_agent_list_is_valid():
    assert herdr.parse_snapshot(encode([])) == {'agents': [], 'truncated': False}
