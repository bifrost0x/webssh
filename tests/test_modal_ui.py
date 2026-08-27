import re
from pathlib import Path


INDEX = Path('templates/index.html')
STYLE = Path('static/css/style.css')
APP_JS = Path('static/js/app.js')


def test_all_primary_dialogs_use_centered_modal_size_classes():
    source = INDEX.read_text(encoding='utf-8')

    expected_sizes = {
        'connectionModal': 'modal-wide',
        'profileManagementModal': 'modal-large',
        'keyManagementModal': 'modal-wide',
        'jumpHostManagementModal': 'modal-wide',
    }

    for modal_id, size_class in expected_sizes.items():
        opening_tag = re.search(
            rf'<div class="(?P<classes>[^"]*\bmodal\b[^"]*)" id="{modal_id}"',
            source,
        )
        assert opening_tag, f'{modal_id} is missing'
        classes = opening_tag.group('classes').split()
        assert size_class in classes
        assert 'panel-left' not in classes
        assert 'panel-right' not in classes


def test_modal_css_has_no_edge_panel_layout_and_centers_all_sizes():
    source = STYLE.read_text(encoding='utf-8')

    assert '.panel-left' not in source
    assert '.panel-right' not in source
    assert 'align-items: center;' in source
    assert 'justify-content: center;' in source
    assert '.modal-wide .modal-content' in source


def test_modal_manager_has_one_code_path_and_restores_trigger_focus():
    source = APP_JS.read_text(encoding='utf-8')
    manager = source[source.index('window.ModalManager = {'):source.index(
        'window.clearConnectionProfileState',
    )]

    assert 'window.PanelManager' not in source
    assert 'previouslyFocused' in manager
    assert 'previouslyFocused.focus()' in manager


def test_modal_bodies_scroll_without_hiding_the_header():
    source = STYLE.read_text(encoding='utf-8')

    content_rule = re.search(r'\.modal-content\s*\{(?P<body>.*?)\n\}', source, re.DOTALL)
    body_rule = re.search(r'\.modal-body\s*\{(?P<body>.*?)\n\}', source, re.DOTALL)

    assert content_rule
    assert 'display: flex;' in content_rule.group('body')
    assert 'flex-direction: column;' in content_rule.group('body')
    assert 'overflow: hidden;' in content_rule.group('body')
    assert body_rule
    assert 'overflow-y: auto;' in body_rule.group('body')
