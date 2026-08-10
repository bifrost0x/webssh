const assert = require('node:assert/strict');
const test = require('node:test');

const charts = require('../../static/js/session-diagnostics-charts.js');

function fakeCanvas() {
    const calls = [];
    const context = {
        setTransform(...args) { calls.push(['setTransform', ...args]); },
        clearRect(...args) { calls.push(['clearRect', ...args]); },
        beginPath() { calls.push(['beginPath']); },
        moveTo(...args) { calls.push(['moveTo', ...args]); },
        lineTo(...args) { calls.push(['lineTo', ...args]); },
        stroke() { calls.push(['stroke']); },
        set strokeStyle(value) { calls.push(['strokeStyle', value]); },
        set lineWidth(value) { calls.push(['lineWidth', value]); },
    };
    return {
        width: 0,
        height: 0,
        clientWidth: 200,
        clientHeight: 80,
        style: {},
        getContext() { return context; },
        get calls() { return calls; },
    };
}

const history = [
    { cpuPercent: 20, memoryPercent: 60, normalizedLoadPercent: 13, receivedBps: 20, transmittedBps: 10 },
    { cpuPercent: null, memoryPercent: 61, normalizedLoadPercent: 25, receivedBps: null, transmittedBps: 40 },
    { cpuPercent: 40, memoryPercent: 62, normalizedLoadPercent: 50, receivedBps: 100, transmittedBps: 30 },
];

test('builds pressure series with null gaps preserved', () => {
    assert.deepEqual(charts.buildPressureSeries(history), [
        { key: 'cpu', label: 'CPU', values: [20, null, 40], max: 100 },
        { key: 'memory', label: 'Memory', values: [60, 61, 62], max: 100 },
        { key: 'load', label: 'Load', values: [13, 25, 50], max: 100 },
    ]);
    assert.equal(charts.buildPressureSeries([]).length, 3);
    assert.deepEqual(charts.buildPressureSeries([{ cpuPercent: 1 }])[0].values, [1]);
});

test('builds separately scaled network series without dropping timestamps', () => {
    const series = charts.buildNetworkSeries(history);
    assert.deepEqual(series.map(item => item.values), [[20, null, 100], [10, 40, 30]]);
    assert.equal(series[0].max, 100);
    assert.equal(series[1].max, 100);
    assert.equal(charts.buildNetworkSeries([])[0].max > 0, true);
});

test('draws canvas at device pixel ratio and splits paths at null values', () => {
    const canvas = fakeCanvas();
    charts.drawLineChart(canvas, [{ key: 'cpu', label: 'CPU', values: [20, null, 40], max: 100 }], {
        devicePixelRatio: 2,
        getComputedStyle: () => ({ getPropertyValue: () => '#123456' }),
    });
    assert.equal(canvas.width, 400);
    assert.equal(canvas.height, 160);
    assert.equal(canvas.calls.filter(call => call[0] === 'clearRect').length, 1);
    // Three grid moves plus two separate data-path starts prove the null gap did
    // not become a connecting data line.
    assert.equal(canvas.calls.filter(call => call[0] === 'moveTo').length, 5);
    assert.equal(canvas.calls.filter(call => call[0] === 'lineTo').length, 3);
    assert.equal(canvas.calls.filter(call => call[0] === 'stroke').length >= 2, true);
});

test('does not draw data paths with fewer than two finite values and supports sparklines', () => {
    const canvas = fakeCanvas();
    charts.drawLineChart(canvas, [{ key: 'cpu', label: 'CPU', values: [null, 25], max: 100 }]);
    assert.equal(canvas.calls.filter(call => call[0] === 'moveTo').length, 3);
    assert.equal(canvas.calls.filter(call => call[0] === 'stroke').length, 1);
    const sparkline = fakeCanvas();
    charts.drawSparkline(sparkline, [1, null, 3]);
    assert.equal(sparkline.calls.filter(call => call[0] === 'moveTo').length, 2);
});
