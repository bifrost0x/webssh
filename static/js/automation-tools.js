/* Pure helpers for automation: comparing run results across hosts and
 * deciding when to poll.
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

    const POLL = Object.freeze({tick: 3000, activeRuns: 3000, idleRuns: 30000, state: 15000, unavailableState: 60000, startedRunGrace: 30000});

    /**
     * Decide which refreshes are due on one polling tick. Runs are polled fast
     * only while a run is queued or running and someone can see it; otherwise
     * slowly while the overview or the run history is open, and not at all
     * elsewhere. Workflows and targets refresh only while automation is open.
     */
    function pollPlan({now, lastRuns = 0, lastState = 0, automationVisible = false, overviewVisible = false,
        runsTabOpen = false, runActive = false, runExpected = false}) {
        let runsInterval = null;
        // A run just started may not be listed yet; follow it as if active.
        if ((runActive || runExpected) && (automationVisible || overviewVisible)) runsInterval = POLL.activeRuns;
        else if (overviewVisible || (automationVisible && runsTabOpen)) runsInterval = POLL.idleRuns;
        // Timers drift by a few milliseconds; do not let that skip a whole tick.
        const due = (last, interval) => now - last + POLL.tick / 4 >= interval;
        return {
            runs: runsInterval !== null && due(lastRuns, runsInterval),
            state: automationVisible && due(lastState, POLL.state),
        };
    }

    const isRunActive = run => ['queued', 'running'].includes(run?.status);

    const api = Object.freeze({compareRun, pollPlan, isRunActive, POLL});
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.AutomationTools = api;
})(typeof window !== 'undefined' ? window : globalThis);
