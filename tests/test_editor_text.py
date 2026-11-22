"""Line endings and encodings survive an editor round trip."""

import time

import pytest

from app.editor_text import (
    EditorEncodingError,
    _merge_line_endings,
    detect_newline,
    encode_editor_text,
)


@pytest.mark.parametrize('raw,expected', [
    (b'', 'lf'),
    (b'one line', 'lf'),
    (b'a\nb\n', 'lf'),
    (b'a\r\nb\r\n', 'crlf'),
    (b'a\r\nb', 'crlf'),
    (b'a\nb\r\n', 'mixed'),
    (b'#!/bin/sh\necho a\r\necho b\n', 'mixed'),
])
def test_detect_newline(raw, expected):
    assert detect_newline(raw) == expected


def roundtrip(original, edited):
    return encode_editor_text(
        edited, encoding='utf-8', newline='mixed', original=original,
    )


def test_unchanged_mixed_file_is_byte_identical():
    original = b'a\r\nb\nc\r\nd'
    assert roundtrip(original, 'a\nb\nc\nd') == original


def test_appended_line_takes_the_ending_of_the_line_before():
    original = b'#!/bin/sh\necho a\r\necho b\necho c\n'
    assert roundtrip(original, '#!/bin/sh\necho a\necho b\necho c\necho d\n') == (
        b'#!/bin/sh\necho a\r\necho b\necho c\necho d\n'
    )


def test_changed_line_keeps_its_own_ending():
    original = b'one\r\ntwo\nthree\r\n'
    assert roundtrip(original, 'one\nTWO\nthree\n') == b'one\r\nTWO\nthree\r\n'
    assert roundtrip(original, 'ONE\ntwo\nthree\n') == b'ONE\r\ntwo\nthree\r\n'


def test_lines_shifted_by_an_insert_keep_their_endings():
    original = b'a\nb\r\nc\nd\r\ne\n'
    edited = 'new\na\nb\nX\nY\nc\nd\ne\nend\n'
    assert roundtrip(original, edited) == b'new\na\nb\r\nX\r\nY\r\nc\nd\r\ne\nend\n'


def test_deleted_lines_do_not_affect_remaining_endings():
    original = b'a\r\nb\nc\r\nd\n'
    assert roundtrip(original, 'a\nd\n') == b'a\r\nd\n'


def test_missing_final_newline_is_preserved_or_added_as_edited():
    original = b'a\r\nb\nc'
    assert roundtrip(original, 'a\nb\nc') == original
    assert roundtrip(original, 'a\nb\nc\n') == b'a\r\nb\nc\n'


def test_large_rewrite_falls_back_to_positional_endings(monkeypatch):
    import app.editor_text as editor_text
    monkeypatch.setattr(editor_text, '_MAX_DIFF_COMPARISONS', 1)
    assert _merge_line_endings('x\ny\nz\n', 'a\r\nb\nc\r\n') == 'x\r\ny\nz\r\n'


@pytest.mark.parametrize('old_lines,new_lines', [
    (2000, 1000),
    (1000, 2000),
    (1400, 1400),
    (10000, 199),
])
def test_repetitive_lines_do_not_make_the_merge_expensive(old_lines, new_lines):
    original = ('a\r\n' + 'x\n' * (old_lines - 1)).encode()
    edited = ''.join(('x' if index % 2 else 'y') + '\n' for index in range(new_lines))
    started = time.process_time()
    saved = roundtrip(original, edited)
    assert time.process_time() - started < 2
    assert saved.replace(b'\r\n', b'\n') == edited.encode()


def test_insert_between_repeated_blank_lines_keeps_the_endings_around_it():
    lines = []
    for index in range(150):
        lines.append((f'key{index} = {index}', '\r\n' if index % 3 == 0 else '\n'))
        lines.append(('', '\n'))
    original = ''.join(body + ending for body, ending in lines).encode()
    bodies = [body for body, _ending in lines]
    bodies.insert(150, 'inserted = 1')
    saved = roundtrip(original, '\n'.join(bodies) + '\n')
    expected = lines[:150] + [('inserted = 1', '\n')] + lines[150:]
    assert saved == ''.join(body + ending for body, ending in expected).encode()


def test_uniform_styles_are_converted_as_a_whole():
    assert encode_editor_text('a\nb\n', encoding='utf-8', newline='crlf') == b'a\r\nb\r\n'
    assert encode_editor_text('a\r\nb\n', encoding='utf-8', newline='lf') == b'a\nb\n'


def test_mixed_requires_the_original_bytes():
    with pytest.raises(ValueError):
        encode_editor_text('a\n', encoding='utf-8', newline='mixed')


def test_latin1_is_never_silently_rewritten_as_utf8():
    assert encode_editor_text('Grüße\n', encoding='latin-1', newline='lf') == b'Gr\xfc\xdfe\n'
    with pytest.raises(EditorEncodingError) as raised:
        encode_editor_text('Preis 5 €\n', encoding='latin-1', newline='lf')
    assert raised.value.character == '€'
    assert raised.value.code == 'EDIT_ENCODING_UNSUPPORTED'


def test_unknown_encoding_keeps_the_utf8_default():
    assert encode_editor_text('€', encoding='cp1252', newline='lf') == '€'.encode('utf-8')
