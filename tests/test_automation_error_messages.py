"""Every error code the automation backend returns has an actionable message."""
from pathlib import Path
import re


from tests.i18n_sources import LOCALES, locale_block

ROOT = Path(__file__).resolve().parents[1]
# Raised only by password management, whose own interface explains them.
CREDENTIAL_INTERFACE_ONLY = {'credential_in_use', 'replacement_confirmation_required'}


def backend_codes():
    """The codes the automation service and its saved passwords answer with."""
    codes = set()
    for path in sorted((ROOT / 'internal/automation').glob('*.go')):
        if path.name.endswith('_test.go'):
            continue
        source = path.read_text(encoding='utf-8')
        codes |= set(re.findall(r'\b(?:Fail\(|NotDispatched\{Code: )"([a-z_]+)"', source))
    codes |= set(re.findall(r'Code = "([a-z_]+)"', (ROOT / 'internal/fault/codes_automation.go').read_text(encoding='utf-8')))
    data = (ROOT / 'internal/fault/codes_data.go').read_text(encoding='utf-8')
    passwords = data[data.index('// Codes of the saved passwords'):]
    codes |= set(re.findall(r'Code = "([a-z_]+)"', passwords[:passwords.index('\n)\n')]))
    return codes


def mapped_codes():
    source = (ROOT / 'static/js/automation.js').read_text(encoding='utf-8')
    block = re.search(r"const errors = new Set\(\[(.*?)\]\);", source, re.S).group(1)
    return set(re.findall(r"'([a-z_]+)'", block))


def translations():
    """Each message key with its text in every locale, in locale order."""
    found = {}
    for locale in LOCALES:
        for key, text in re.findall(r'^        "automation\.(error\.[a-z_]+)": "([^"]+)",?$', locale_block(locale), re.M):
            found.setdefault(key, []).append(text)
    return found


def test_every_backend_code_is_explained_in_the_automation_interface():
    assert backend_codes() - mapped_codes() == CREDENTIAL_INTERFACE_ONLY


def test_every_mapped_code_has_a_message_in_every_language():
    available = translations()
    incomplete = sorted(code for code in mapped_codes() if len(available.get(f'error.{code}', [])) != len(LOCALES))
    assert incomplete == []


def test_host_key_message_names_the_hosts():
    assert all('{hosts}' in text for text in translations()['error.host_key_required'])
