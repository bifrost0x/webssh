const path = require('node:path');
const { test, expect } = require('playwright/test');


test('renders hostile inventory only as DOM text with unique service action names', async ({ page }) => {
    await page.setContent('<!doctype html><html><body></body></html>');
    await page.addScriptTag({
        path: path.resolve(__dirname, '../../static/js/session-diagnostics.js'),
    });

    const hostileUnit = '<img src=x onerror=alert(1)>.service';
    const rendered = await page.evaluate(({ hostileUnit }) => {
        const ids = [
            'contextDiagnosticsTab', 'contextDiagnosticsPanel',
            'sessionDiagnosticsOverlay',
            'sessionDiagnosticsBackdrop', 'sessionDiagnosticsClose',
            'sessionDiagnosticsRefresh', 'sessionDiagnosticsLastUpdated',
            'sessionDiagnosticsHost', 'sessionDiagnosticsOs',
            'sessionDiagnosticsState', 'sessionDiagnosticsPermissions',
            'sessionDiagnosticsPermissionList', 'sessionDiagnosticsPressureSection',
            'sessionDiagnosticsPressureChart', 'sessionDiagnosticsNetworkSection',
            'sessionDiagnosticsNetworkChart', 'sessionDiagnosticsNetworkReceived',
            'sessionDiagnosticsNetworkTransmitted', 'sessionDiagnosticsSwapMetric',
            'sessionDiagnosticsSwapValue', 'sessionDiagnosticsSwapDetail',
            'sessionDiagnosticsSwapBar', 'sessionDiagnosticsUptimeMetric',
            'sessionDiagnosticsUptimeValue', 'sessionDiagnosticsProcessMetric',
            'sessionDiagnosticsProcessValue', 'sessionDiagnosticsProcessDetail',
            'sessionDiagnosticsProcessesSection', 'sessionDiagnosticsCpuProcessesPanel',
            'sessionDiagnosticsMemoryProcessesPanel', 'sessionDiagnosticsCpuProcesses',
            'sessionDiagnosticsMemoryProcesses', 'sessionDiagnosticsSystemdSection',
            'sessionDiagnosticsSystemdState', 'sessionDiagnosticsSystemdCounts',
            'sessionDiagnosticsSystemdTruncation', 'sessionDiagnosticsSystemdDistribution',
            'sessionDiagnosticsSystemdSearch', 'sessionDiagnosticsSystemdServices',
            'sessionDiagnosticsDockerSection', 'sessionDiagnosticsDockerVersion',
            'sessionDiagnosticsDockerCounts', 'sessionDiagnosticsDockerTruncation',
            'sessionDiagnosticsDockerDistribution', 'sessionDiagnosticsDockerSearch',
            'sessionDiagnosticsDockerContainers', 'sessionDiagnosticsClipboardFeedback',
        ];
        ['Cpu', 'Memory', 'Disk', 'Load'].forEach(title => {
            ['Metric', 'Value', 'Detail', 'Severity', 'Bar', 'Sparkline'].forEach(suffix => {
                ids.push(`sessionDiagnostics${title}${suffix}`);
            });
        });
        const tags = {
            contextDiagnosticsTab: 'button', sessionDiagnosticsClose: 'button',
            sessionDiagnosticsRefresh: 'button', sessionDiagnosticsBackdrop: 'button',
            sessionDiagnosticsSystemdSearch: 'input', sessionDiagnosticsDockerSearch: 'input',
            sessionDiagnosticsPermissionList: 'ul',
            sessionDiagnosticsCpuProcesses: 'tbody', sessionDiagnosticsMemoryProcesses: 'tbody',
            sessionDiagnosticsSystemdServices: 'tbody', sessionDiagnosticsDockerContainers: 'tbody',
            sessionDiagnosticsPressureChart: 'canvas', sessionDiagnosticsNetworkChart: 'canvas',
            sessionDiagnosticsCpuSparkline: 'canvas', sessionDiagnosticsMemorySparkline: 'canvas',
            sessionDiagnosticsDiskSparkline: 'canvas', sessionDiagnosticsLoadSparkline: 'canvas',
        };
        ids.forEach(id => {
            const element = document.createElement(tags[id] || 'div');
            element.id = id;
            document.body.appendChild(element);
        });
        document.getElementById('sessionDiagnosticsOverlay').className = 'hidden';
        const drawer = document.createElement('section');
        drawer.className = 'session-diagnostics-drawer';
        document.body.appendChild(drawer);
        ['sessionDiagnosticsSystemdDistribution', 'sessionDiagnosticsDockerDistribution']
            .forEach((id, index) => {
                const distribution = document.getElementById(id);
                const count = index === 0 ? 3 : 2;
                for (let child = 0; child < count; child += 1) {
                    distribution.appendChild(document.createElement('span'));
                }
            });

        window.workspaceLayoutController = {
            getState: () => ({ activeContext: 'diagnostics' }),
            setContextAvailability() {},
        };
        const controller = window.SessionDiagnosticsModule.createController({
            document,
            window,
            inventoryModule: { copySystemdCommand: async () => null },
        });
        const state = {
            status: 'ready', sessionId: 'session-a', cpuPercent: 1,
            networkRates: {}, metricHistory: [],
            stats: {
                cpu: [1, 0, 0, 99],
                memory: { total_kib: 100, available_kib: 99, used_kib: 1 },
                disk: { total_kib: 100, available_kib: 99, used_kib: 1, percent: 1 },
                load: { one: 0, five: 0, fifteen: 0, cpu_count: 1 },
                network: { received_bytes: 0, transmitted_bytes: 0 },
            },
        };
        const inventory = {
            status: 'ready', sessionId: 'session-a', permissionDenied: [],
            inventory: {
                systemd: {
                    state: 'running', total: 1, active: 1, failed: 0,
                    returned: 1, truncated: false,
                    services: [{
                        unit: hostileUnit, load: '<b>loaded</b>', active: 'active',
                        sub: '<svg/onload=alert(1)>',
                        description: '<script>alert(1)</script>',
                    }],
                },
                docker: {
                    version: '27.5.1', total: 1, running: 1,
                    returned: 1, truncated: false,
                    containers: [{
                        name: '<img src=x onerror=alert(2)>',
                        status: '<svg onload=alert(3)>Up</svg>',
                    }],
                },
            },
        };
        controller.render(state, { connected: true }, inventory);
        const systemd = document.getElementById('sessionDiagnosticsSystemdServices');
        const docker = document.getElementById('sessionDiagnosticsDockerContainers');
        const buttons = Array.from(systemd.querySelectorAll('button'));
        const eventAttributes = Array.from(systemd.querySelectorAll('*'))
            .concat(Array.from(docker.querySelectorAll('*')))
            .flatMap(element => Array.from(element.attributes))
            .filter(attribute => attribute.name.startsWith('on'));
        const result = {
            systemdText: systemd.textContent,
            dockerText: docker.textContent,
            systemdHtml: systemd.innerHTML,
            dockerHtml: docker.innerHTML,
            dangerousElements: systemd.querySelectorAll('img,script,svg').length
                + docker.querySelectorAll('img,script,svg').length,
            eventAttributes: eventAttributes.map(attribute => attribute.name),
            actions: buttons.map(button => button.dataset.action),
            unitTag: systemd.querySelector('tr > :first-child')?.tagName,
            unitScope: systemd.querySelector('tr > :first-child')?.scope,
            diagnosticsVisible: !document.getElementById('sessionDiagnosticsOverlay')
                .classList.contains('hidden'),
        };
        controller.destroy();
        return result;
    }, { hostileUnit });

    expect(rendered.systemdText).toMatch(/<script>alert\(1\)<\/script>/);
    expect(rendered.dockerText).toMatch(/<svg onload=alert\(3\)>Up<\/svg>/);
    expect(rendered.systemdHtml.includes('<script>')).toBe(false);
    expect(rendered.dockerHtml.includes('<svg onload=')).toBe(false);
    expect(rendered.dangerousElements).toBe(0);
    expect(rendered.eventAttributes).toEqual([]);
    expect(rendered.actions).toEqual(['start', 'stop', 'restart']);
    expect(rendered.unitTag).toBe('TH');
    expect(rendered.unitScope).toBe('row');
    expect(rendered.diagnosticsVisible).toBe(true);
    await expect(page.getByRole('button', {
        name: `Restart for ${hostileUnit}`,
        exact: true,
    })).toHaveCount(1);
});
