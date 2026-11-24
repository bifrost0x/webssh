"""Read the per-language dictionaries in static/js/i18n/ as one table source."""

from pathlib import Path

LOCALES = ('en', 'vi', 'de', 'fr', 'es', 'zh')
LOCALE_DIR = Path(__file__).resolve().parent.parent / 'static' / 'js' / 'i18n'


def locale_block(locale: str) -> str:
    """The ``    <locale>: {`` block of one dictionary file, key lines unchanged."""
    source = (LOCALE_DIR / f'{locale}.js').read_text(encoding='utf-8').replace('\r\n', '\n')
    start = source.index(f'\n    {locale}: {{\n') + 1
    end = source.index('\n    }\n});', start)
    return source[start:end]


def translation_source() -> str:
    """All dictionaries as one ``const translations = {...};`` literal.

    Each block starts with ``    <locale>: {`` and keeps the 8-space key lines,
    so tests can slice locales and match keys with line-anchored patterns.
    """
    blocks = ',\n'.join(locale_block(locale) + '\n    }' for locale in LOCALES)
    return f'const translations = {{\n{blocks}\n}};\n'
