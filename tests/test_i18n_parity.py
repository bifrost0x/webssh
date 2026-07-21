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
