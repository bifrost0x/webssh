import re
from pathlib import Path


def test_all_locales_have_matching_translation_keys():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    locale_starts = list(re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', source, re.MULTILINE))
    keys_by_locale = {}

    for index, match in enumerate(locale_starts):
        end = locale_starts[index + 1].start() if index + 1 < len(locale_starts) else source.index('\n};', match.end())
        block = source[match.end():end]
        keys_by_locale[match.group(1)] = set(re.findall(r"^        '([^']+)':", block, re.MULTILINE))

    assert set(keys_by_locale) == {'en', 'vi', 'de', 'fr', 'es', 'zh'}
    assert keys_by_locale['vi'] == keys_by_locale['en']
    assert all(
        'connection.tailscaleSSH' in keys
        for keys in keys_by_locale.values()
    )
    assert all(
        {
            'connection.commandSet',
            'connection.commandSetHint',
            'commandSets.manage',
            'commandSets.create',
            'commandSets.saveToLibrary',
            'commandSets.useSudo',
            'commandSets.useSudoHint',
            'commandSets.sudoBadge',
        } <= keys
        for keys in keys_by_locale.values()
    )


def test_english_command_set_copy_explains_execution_boundaries():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    en_start = source.index('    en: {')
    en_end = source.index('\n    vi: {', en_start)
    english_block = source[en_start:en_end]
    match = re.search(
        r"'connection\.commandSetHint': '([^']+)'",
        english_block,
    )

    assert match is not None
    hint = match.group(1).lower()
    assert 'remote host' in hint
    assert 'not in webssh' in hint
    assert 'tmux' in hint
    assert 'not run again' in hint


def test_all_popup_translation_references_exist_in_every_locale():
    i18n_source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    sources = [
        Path('templates/index.html').read_text(encoding='utf-8'),
        Path('templates/admin.html').read_text(encoding='utf-8'),
        Path('static/js/sftp-file-manager.js').read_text(encoding='utf-8'),
    ]
    referenced_keys = set()
    for source in sources:
        referenced_keys.update(
            re.findall(
                r'data-i18n(?:-placeholder|-title|-label|-aria-label)?="([^"]+)"',
                source,
            )
        )

    locale_starts = list(
        re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', i18n_source, re.MULTILINE)
    )
    missing_by_locale = {}
    for index, match in enumerate(locale_starts):
        end = (
            locale_starts[index + 1].start()
            if index + 1 < len(locale_starts)
            else i18n_source.index('\n};', match.end())
        )
        locale_keys = set(
            re.findall(
                r"^        '([^']+)':",
                i18n_source[match.end():end],
                re.MULTILINE,
            )
        )
        missing = sorted(referenced_keys - locale_keys)
        if missing:
            missing_by_locale[match.group(1)] = missing

    assert missing_by_locale == {}


def test_popup_inputs_use_explicit_placeholder_translation_attribute():
    source = Path('templates/index.html').read_text(encoding='utf-8')
    popup_source = source[source.index('<div class="modal'):source.index(
        '<script src=',
    )]
    translated_fields = re.findall(
        r'<(?:input|textarea)\b[^>]*\bdata-i18n="[^"]+"[^>]*>',
        popup_source,
    )

    assert translated_fields == []


def test_dynamic_popup_select_placeholders_refresh_with_language():
    profile_source = Path('static/js/profile-manager.js').read_text(encoding='utf-8')
    jump_host_source = Path('static/js/jump-host-manager.js').read_text(encoding='utf-8')

    assert re.search(
        r"this\.t\(\s*'connection\.selectProfile'",
        profile_source,
    )
    assert re.search(
        r"this\.t\(\s*'connection\.selectSSHKey'",
        profile_source,
    )
    assert "window.addEventListener('languageChanged'" in jump_host_source
    assert 'window.JumpHostManager.renderSelect();' in jump_host_source
