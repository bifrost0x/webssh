(function () {
    'use strict';

    // A contiguous changed region avoids quadratic line-matching costs. Each
    // side renders at most 200 lines / 32 KiB, including single-line files.
    function excerpt(text, start, end, sign) {
        const limit = Math.min(end, start + 32768);
        let cursor = start;
        let output = '';
        let lines = 0;
        while (cursor < limit && lines < 200) {
            const newline = text.indexOf('\n', cursor);
            const stop = newline < 0 ? limit : Math.min(newline + 1, limit);
            output += sign + text.slice(cursor, stop);
            if (stop === end && text[stop - 1] !== '\n') output += '\n\\ No newline at end of file\n';
            cursor = stop;
            lines++;
        }
        // A size-limited single line must not merge its old/new excerpts into
        // one row. The explicit limited warning requires full-version review.
        if (output && !output.endsWith('\n')) output += '\n';
        return { text: output, limited: cursor < end };
    }

    function compare(original, edited) {
        if (original === edited) return { changed: false, limited: false, text: '', originalLine: 1 };
        let start = 0;
        const shortest = Math.min(original.length, edited.length);
        while (start < shortest && original[start] === edited[start]) start++;
        // Include the whole first changed line, even for an EOF newline change.
        start = start === 0 ? 0 : original.lastIndexOf('\n', start - 1) + 1;
        let oldEnd = original.length;
        let newEnd = edited.length;
        let commonLineOldEnd = oldEnd;
        let commonLineNewEnd = newEnd;
        while (oldEnd > start && newEnd > start && original[oldEnd - 1] === edited[newEnd - 1]) {
            oldEnd--;
            newEnd--;
            if (original[oldEnd] === '\n') {
                commonLineOldEnd = oldEnd + 1;
                commonLineNewEnd = newEnd + 1;
            }
        }
        // Only omit complete common suffix lines.
        const removed = excerpt(original, start, commonLineOldEnd, '-');
        const added = excerpt(edited, start, commonLineNewEnd, '+');
        let originalLine = 1;
        for (let index = 0; index < start; index++) if (original[index] === '\n') originalLine++;
        return {
            changed: true,
            limited: removed.limited || added.limited,
            originalLine,
            text: removed.text + added.text,
        };
    }

    function render(element, result) {
        const doc = element.ownerDocument;
        const fragment = doc.createDocumentFragment();
        const heading = doc.createElement('span');
        heading.className = 'editor-diff-line editor-diff-location';
        heading.textContent = `@@ ${result.originalLine} @@\n`;
        fragment.appendChild(heading);
        let oldLine = result.originalLine;
        let newLine = result.originalLine;
        // compare() already caps each side at 200 lines / 32 KiB. Text nodes
        // keep remote file contents literal, including HTML and script markup.
        const lines = result.text.split('\n');
        if (lines[lines.length - 1] === '') lines.pop();
        for (const line of lines) {
            const row = doc.createElement('span');
            const removed = line.startsWith('-');
            const added = line.startsWith('+');
            row.className = `editor-diff-line editor-diff-${removed ? 'removed' : added ? 'added' : 'note'}`;
            row.dataset.oldLine = removed ? String(oldLine++) : '';
            row.dataset.newLine = added ? String(newLine++) : '';
            row.textContent = `${line}\n`;
            fragment.appendChild(row);
        }
        element.replaceChildren(fragment);
    }

    window.FileEditDiff = Object.freeze({ compare, render });
})();
