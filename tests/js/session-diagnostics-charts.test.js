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
        { key: 'disk', label: 'Root disk', values: [null, null, null], max: 100 },
    ]);
    assert.equal(charts.buildPressureSeries([]).length, 4);
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
    assert.deepEqual(canvas.style, {});
    assert.equal(canvas.calls.filter(call => call[0] === 'clearRect').length, 1);
    // Three grid moves plus two separate data-path starts prove the null gap did
    // not become a connecting data line.
    assert.equal(canvas.calls.filter(call => call[0] === 'moveTo').length, 5);
    assert.equal(canvas.calls.filter(call => call[0] === 'lineTo').length, 3);
    assert.equal(canvas.calls.filter(call => call[0] === 'stroke').length >= 2, true);
});

test('does not promote a hidden canvas backing size into its layout size', () => {
    const canvas = fakeCanvas();
    const series = [{ key: 'cpu', label: 'CPU', values: [20, 40], max: 100 }];
    const options = { devicePixelRatio: 2 };
    charts.drawLineChart(canvas, series, options);
    const visibleCallCount = canvas.calls.length;

    canvas.clientWidth = 0;
    canvas.clientHeight = 0;
    charts.drawLineChart(canvas, series, options);

    assert.equal(canvas.width, 400);
    assert.equal(canvas.height, 160);
    assert.equal(canvas.calls.length, visibleCallCount);
    assert.deepEqual(canvas.style, {});
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


test('load above 100 percent retains its peak on a shared scale', () => {
    const series = charts.buildPressureSeries([
        { cpuPercent: 40, memoryPercent: 60, normalizedLoadPercent: 150 },
        { cpuPercent: 50, memoryPercent: 65, normalizedLoadPercent: 325 },
    ]);
    assert.deepEqual(series[2].values, [150, 325]);
    assert.ok(series.every(item => item.max === 325));
});

test('network rates above 100 bytes per second are not clipped as percentages', () => {
    const canvas = fakeCanvas();
    charts.drawLineChart(canvas, [{ key: 'received', label: 'Received', values: [150, 200], max: 200 }]);
    assert.ok(canvas.calls.some(call => call[0] === 'lineTo' && call[2] === 0));
});


test('history uses elapsed sample time and breaks lines across polling gaps', () => {
    const canvas = fakeCanvas();
    charts.drawLineChart(canvas, [{ key: 'cpu', label: 'CPU', values: [10, 20, 30], max: 100 }], {
        grid: false, sampleTimes: [1000, 5000, 25000],
    });
    const lines = canvas.calls.filter(call => call[0] === 'lineTo');
    assert.equal(lines.length, 1);
    assert.ok(Math.abs(lines[0][1] - 200 / 6) < 0.001);
    assert.equal(canvas.calls.filter(call => call[0] === 'moveTo').length, 2);
});


test('renders root disk history with gaps on the shared load scale', () => {
    const series = charts.buildPressureSeries([
        { diskPercent: 20, normalizedLoadPercent: 200 },
        { diskPercent: null, normalizedLoadPercent: 200 },
        { diskPercent: 60, normalizedLoadPercent: 200 },
        { diskPercent: 80, normalizedLoadPercent: 200 },
    ]);
    const disk = series.find(item => item.key === 'disk');
    assert.ok(disk, 'root disk must remain visible in resource history');
    assert.deepEqual(disk.values, [20, null, 60, 80]);
    assert.equal(disk.max, 200);
    const canvas = fakeCanvas();
    charts.drawLineChart(canvas, [disk], { grid: false });
    assert.deepEqual(canvas.calls.filter(call => call[0] === 'moveTo'), [
        ['moveTo', 0, 72], ['moveTo', 400 / 3, 56],
    ]);
    assert.deepEqual(canvas.calls.filter(call => call[0] === 'lineTo'), [['lineTo', 200, 48]]);
});

test('invalid values cannot create zero points in diagnostic charts', () => {
    const invalid = ['  ', [], [5], {}];
    for (const value of invalid) {
        const series = charts.buildPressureSeries([{cpuPercent:value, memoryPercent:value}]);
        assert.deepEqual(series[0].values, [null]);
        assert.deepEqual(series[1].values, [null]);
    }
});
