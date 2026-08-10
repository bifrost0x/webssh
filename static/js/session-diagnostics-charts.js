(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionDiagnosticsCharts = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    function finite(value) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') {
            return null;
        }
        const number = Number(value);
        return Number.isFinite(number) ? number : null;
    }

    function boundedPercent(value) {
        const number = finite(value);
        return number === null ? null : Math.max(0, Math.min(100, number));
    }

    function buildPressureSeries(history) {
        const samples = Array.isArray(history) ? history : [];
        return [
            {
                key: 'cpu',
                label: 'CPU',
                values: samples.map(sample => boundedPercent(sample?.cpuPercent)),
                max: 100,
            },
            {
                key: 'memory',
                label: 'Memory',
                values: samples.map(sample => boundedPercent(sample?.memoryPercent)),
                max: 100,
            },
            {
                key: 'load',
                label: 'Load',
                values: samples.map(sample => boundedPercent(sample?.normalizedLoadPercent)),
                max: 100,
            },
        ];
    }

    function buildNetworkSeries(history) {
        const samples = Array.isArray(history) ? history : [];
        const received = samples.map(sample => {
            const value = finite(sample?.receivedBps);
            return value === null || value < 0 ? null : value;
        });
        const transmitted = samples.map(sample => {
            const value = finite(sample?.transmittedBps);
            return value === null || value < 0 ? null : value;
        });
        const maximum = Math.max(1, ...received, ...transmitted.filter(value => value !== null));
        return [
            { key: 'received', label: 'Received', values: received, max: maximum },
            { key: 'transmitted', label: 'Transmitted', values: transmitted, max: maximum },
        ];
    }

    function cssValue(canvas, name, fallback, options) {
        const getStyle = options?.getComputedStyle
            || root.getComputedStyle?.bind(root);
        const value = getStyle?.(canvas)?.getPropertyValue?.(name)?.trim();
        return value || fallback;
    }

    function canvasMetrics(canvas, options) {
        const ratio = Number(options?.devicePixelRatio ?? root.devicePixelRatio) || 1;
        const width = Math.max(1, Number(canvas.clientWidth) || Number(canvas.width) || 1);
        const height = Math.max(1, Number(canvas.clientHeight) || Number(canvas.height) || 1);
        canvas.width = Math.round(width * ratio);
        canvas.height = Math.round(height * ratio);
        if (canvas.style) {
            canvas.style.width = `${width}px`;
            canvas.style.height = `${height}px`;
        }
        return { width, height, ratio };
    }

    function latestValue(values) {
        for (let index = values.length - 1; index >= 0; index -= 1) {
            if (finite(values[index]) !== null) return finite(values[index]);
        }
        return null;
    }

    function updateAriaLabel(canvas, series, formatter) {
        if (!canvas?.setAttribute) return;
        const label = series.map(item => {
            const value = latestValue(item.values || []);
            return value === null ? null : `${item.label} ${formatter(value, item)}`;
        }).filter(Boolean).join(', ');
        if (label) canvas.setAttribute('aria-label', label);
    }

    function drawGrid(context, width, height, color) {
        context.strokeStyle = color;
        context.lineWidth = 1;
        context.beginPath();
        for (let index = 1; index <= 3; index += 1) {
            const y = (height / 4) * index;
            context.moveTo(0, y);
            context.lineTo(width, y);
        }
        context.stroke();
    }

    function drawSeries(context, item, width, height, options) {
        const values = Array.isArray(item.values) ? item.values : [];
        const validCount = values.reduce((count, value) => count + (finite(value) === null ? 0 : 1), 0);
        if (validCount < 2) return;
        const max = Number(item.max) > 0 ? Number(item.max) : 100;
        const step = values.length > 1 ? width / (values.length - 1) : width;
        let drawing = false;
        context.strokeStyle = cssValue(
            options?.canvas,
            `--session-chart-${item.key}`,
            cssValue(options?.canvas, '--session-chart-line', '#60a5fa', options),
            options,
        );
        context.lineWidth = 1.5;
        context.beginPath();
        values.forEach((value, index) => {
            const number = finite(value);
            if (number === null) {
                drawing = false;
                return;
            }
            const bounded = item.max === 100 ? Math.max(0, Math.min(100, number)) : Math.max(0, number);
            const x = index * step;
            const y = height - ((bounded / max) * height);
            if (!drawing) {
                context.moveTo(x, y);
                drawing = true;
            } else {
                context.lineTo(x, y);
            }
        });
        context.stroke();
    }

    function drawLineChart(canvas, series, options = {}) {
        if (!canvas?.getContext) return;
        const context = canvas.getContext('2d');
        if (!context) return;
        const { width, height, ratio } = canvasMetrics(canvas, options);
        context.setTransform(ratio, 0, 0, ratio, 0, 0);
        context.clearRect(0, 0, width, height);
        if (options.grid !== false) {
            drawGrid(context, width, height, cssValue(canvas, '--session-chart-grid', '#334155', options));
        }
        const chartSeries = Array.isArray(series) ? series : [];
        chartSeries.forEach(item => drawSeries(context, item, width, height, { ...options, canvas }));
        updateAriaLabel(canvas, chartSeries, options.formatValue || ((value, item) => (
            item.max === 100 ? `${Math.round(value)}%` : String(Math.round(value))
        )));
    }

    function drawSparkline(canvas, values, options = {}) {
        const samples = Array.isArray(values) ? values : [];
        const maximum = Math.max(1, ...samples.map(value => finite(value) ?? 0));
        drawLineChart(canvas, [{
            key: options.key || 'sparkline',
            label: options.label || 'Trend',
            values: samples,
            max: options.max || maximum,
        }], { ...options, grid: options.grid ?? false });
    }

    return {
        buildPressureSeries,
        buildNetworkSeries,
        drawLineChart,
        drawSparkline,
    };
}));
