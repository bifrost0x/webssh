"""Convert remote file bytes to editor text and back without silent rewrites.

The browser textarea only knows LF line breaks. Files that consistently use
CRLF are converted back as a whole. Files that mix LF and CRLF keep the line
ending of every unchanged line; new or changed lines take the ending of the
line they replace or follow.
"""

from difflib import SequenceMatcher

EDITOR_ENCODINGS = ('utf-8', 'latin-1')

# Above this many line comparisons the changed region is mapped by position
# instead of being diffed. SequenceMatcher degrades far beyond quadratic time
# on many repeated lines, so this bound and autojunk keep a save of a crafted
# file well below a second.
_MAX_DIFF_COMPARISONS = 100_000


class EditorEncodingError(ValueError):
    """The edited text contains a character the file encoding cannot store."""

    code = 'EDIT_ENCODING_UNSUPPORTED'

    def __init__(self, character, encoding):
        self.character = character
        self.encoding = encoding
        super().__init__(
            f'The character {character!r} cannot be saved in this '
            f'{encoding} file. Remove or replace it before saving.'
        )


def detect_newline(raw):
    """Return 'lf', 'crlf' or 'mixed' for the line breaks in ``raw``."""
    crlf = raw.count(b'\r\n')
    if not crlf:
        return 'lf'
    if crlf == raw.count(b'\n'):
        return 'crlf'
    return 'mixed'


def _split_lines(text):
    """Split into (body, ending) pairs; the last pair has no ending."""
    parts = text.split('\n')
    lines = []
    for part in parts[:-1]:
        if part.endswith('\r'):
            lines.append((part[:-1], '\r\n'))
        else:
            lines.append((part, '\n'))
    lines.append((parts[-1], ''))
    return lines


def _merge_line_endings(text, original_text):
    old = _split_lines(original_text)
    old_bodies = [body for body, _ending in old]
    old_endings = [ending for _body, ending in old]
    new_bodies = text.split('\n')
    terminated = len(new_bodies) - 1
    crlf = old_endings.count('\r\n')
    default = '\r\n' if crlf > old_endings.count('\n') else '\n'

    endings = [None] * len(new_bodies)

    def ending_near(index):
        """Ending of the old line at ``index`` or the closest one before it."""
        for candidate in range(min(index, len(old_endings) - 1), -1, -1):
            if old_endings[candidate]:
                return old_endings[candidate]
        return default

    prefix = 0
    limit = min(len(old_bodies), len(new_bodies))
    while prefix < limit and old_bodies[prefix] == new_bodies[prefix]:
        endings[prefix] = old_endings[prefix] or default
        prefix += 1
    suffix = 0
    while (
        suffix < limit - prefix
        and old_bodies[-1 - suffix] == new_bodies[-1 - suffix]
    ):
        endings[-1 - suffix] = old_endings[-1 - suffix] or default
        suffix += 1

    old_middle = range(prefix, len(old_bodies) - suffix)
    new_middle = range(prefix, len(new_bodies) - suffix)
    if len(old_middle) * len(new_middle) <= _MAX_DIFF_COMPARISONS:
        matcher = SequenceMatcher(
            None,
            old_bodies[old_middle.start:old_middle.stop],
            new_bodies[new_middle.start:new_middle.stop],
            autojunk=True,
        )
        opcodes = matcher.get_opcodes()
    else:
        opcodes = [(
            'replace', 0, len(old_middle), 0, len(new_middle),
        )]
    for tag, i1, i2, j1, j2 in opcodes:
        i1 += prefix
        i2 += prefix
        j1 += prefix
        j2 += prefix
        for offset, new_index in enumerate(range(j1, j2)):
            if tag == 'insert' or i1 == i2:
                endings[new_index] = ending_near(i1 - 1)
            else:
                old_index = min(i1 + offset, i2 - 1)
                endings[new_index] = old_endings[old_index] or ending_near(old_index)

    return ''.join(
        body + (endings[index] if index < terminated else '')
        for index, body in enumerate(new_bodies)
    )


def encode_editor_text(content, *, encoding, newline, original=None):
    """Encode browser text for the file it was opened from.

    ``original`` holds the revision-checked bytes of the file and is required
    for files with mixed line endings.
    """
    if encoding not in EDITOR_ENCODINGS:
        encoding = 'utf-8'
    text = content.replace('\r\n', '\n')
    if newline == 'crlf':
        text = text.replace('\n', '\r\n')
    elif newline == 'mixed':
        if original is None:
            raise ValueError('original bytes are required for mixed line endings')
        text = _merge_line_endings(text, original.decode(encoding))
    try:
        return text.encode(encoding)
    except UnicodeEncodeError as error:
        raise EditorEncodingError(
            error.object[error.start], encoding,
        ) from error
