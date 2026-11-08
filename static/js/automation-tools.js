/* Pure helpers for automation: comparing run results across hosts.
 * No DOM; exported for tests. */
(function (root) {
    'use strict';

    /**
     * Group the hosts of a run by identical result per step: same status, exit
     * code, standard output and error output (trailing whitespace ignored).
     * Largest group first. Truncated output never counts as proof of sameness.
     */
    function compareRun(run) {
        const targets = Array.isArray(run?.targets) ? run.targets : [];
        const stepCount = Math.max(0, ...targets.map(target => (target.steps || []).length));
        const steps = [];
        for (let index = 0; index < stepCount; index += 1) {
            const groups = new Map();
            let name = '';
            targets.forEach(target => {
                const step = (target.steps || [])[index];
                if (!step) return;
                name = name || step.name || '';
                const captured = typeof step.stdout === 'string';
                const output = captured ? step.stdout.trimEnd() : null;
                const errors = typeof step.stderr === 'string' ? step.stderr.trimEnd() : null;
                const exit = Number.isInteger(step.exit_code) ? step.exit_code : null;
                const key = JSON.stringify([step.status, exit, output, errors]);
                if (!groups.has(key)) groups.set(key, {status: step.status, exitCode: exit, output, errors, truncated: false, hosts: []});
                const group = groups.get(key);
                group.hosts.push(target.name || target.host || '');
                group.truncated = group.truncated || step.output_truncated === true;
            });
            const list = [...groups.values()].sort((a, b) => b.hosts.length - a.hosts.length);
            steps.push({index, name, groups: list, uniform: list.length === 1 && !list[0].truncated});
        }
        return {hostCount: targets.length, steps};
    }

    const api = Object.freeze({compareRun});
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.AutomationTools = api;
})(typeof window !== 'undefined' ? window : globalThis);
