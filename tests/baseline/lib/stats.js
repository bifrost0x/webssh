'use strict';

// Nearest-rank percentiles over raw samples. Raw samples are always kept in
// the result file, so other statistics can be derived later.

function percentile(values, fraction) {
    if (!values.length) return null;
    const sorted = [...values].sort((a, b) => a - b);
    const rank = Math.max(1, Math.ceil(fraction * sorted.length));
    return sorted[rank - 1];
}

function median(values) {
    if (!values.length) return null;
    const sorted = [...values].sort((a, b) => a - b);
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function summarize(values) {
    return {
        n: values.length,
        median: median(values),
        p95: percentile(values, 0.95),
        min: values.length ? Math.min(...values) : null,
        max: values.length ? Math.max(...values) : null,
    };
}

module.exports = { percentile, median, summarize };
