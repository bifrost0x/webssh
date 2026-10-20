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

    window.FileEditDiff = Object.freeze({ compare });
})();
