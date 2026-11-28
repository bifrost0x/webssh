// Splits the planned spec files of the Go suite into shards of about the
// same duration. The unit is the spec file: its tests share fixtures and
// helpers, and a serial spec has to stay with the stored settings it
// changes. Durations come from go-suite-timing.json (refreshed by
// scripts/refresh-go-suite-timing.js); a spec without a measurement gets
// the median of the measured ones, so a new spec does not land on a
// shard that is already the longest.
const path = require('node:path');

const SPEC_DIR = path.join('tests', 'e2e');

function specName(file) {
    return path.relative(SPEC_DIR, file).replaceAll('\\', '/');
}

function median(values) {
    if (!values.length) return 30;
    const sorted = [...values].sort((left, right) => left - right);
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

// Returns the estimated seconds of every file. Exported for tests/js.
function weigh(files, timing) {
    const specs = timing?.specs || {};
    for (const [name, seconds] of Object.entries(specs)) {
        if (!Number.isFinite(seconds) || seconds < 0) throw new Error(`go-suite-timing.json: invalid duration for ${name}`);
    }
    const fallback = median(Object.values(specs));
    return new Map(files.map(file => {
        const name = specName(file);
        return [file, Object.hasOwn(specs, name) ? specs[name] : fallback];
    }));
}

// Longest processing time first: the heaviest spec goes to the shard with
// the least load. Ties break by name, so the same input always gives the
// same shards. Fewer files than shards gives fewer shards, never an empty
// one.
function assign(files, count, timing) {
    if (!Number.isSafeInteger(count) || count < 1) throw new Error('--shards needs a positive number');
    if (!files.length) throw new Error('no spec files to run');
    const weights = weigh(files, timing);
    const shards = Array.from({length: Math.min(count, files.length)}, () => ({files: [], seconds: 0}));
    const ordered = [...files].sort((left, right) => weights.get(right) - weights.get(left) || left.localeCompare(right, 'en'));
    for (const file of ordered) {
        let target = shards[0];
        for (const shard of shards) if (shard.seconds < target.seconds) target = shard;
        target.files.push(file);
        target.seconds += weights.get(file);
    }
    // Playwright runs files in the given order; keep the plan's order.
    for (const shard of shards) shard.files.sort((left, right) => files.indexOf(left) - files.indexOf(right));
    return shards;
}

// Splits the files of one shard into the Playwright invocations it runs.
// With one worker everything runs at once. With more, the serial specs
// follow on one worker, because they change stored settings of a seed
// account the others read.
function phases(files, serial, workers) {
    const serialFiles = files.filter(file => serial.includes(file));
    const parallelFiles = files.filter(file => !serial.includes(file));
    if (workers === 1 || !serialFiles.length) return [{name: 'all', files, workers}];
    if (!parallelFiles.length) return [{name: 'all', files, workers: 1}];
    return [{name: 'parallel', files: parallelFiles, workers}, {name: 'serial', files: serialFiles, workers: 1}];
}

module.exports = {assign, phases, specName, weigh};
