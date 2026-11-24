const {test, mock} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {pollPlan, isRunActive, POLL} = require('../../static/js/automation-tools.js');

// Mirrors the polling loop in automation.js: one interval tick that asks the
// plan what is due and records what it would have loaded.
function simulate({seconds, view, runsTabOpen = false, runActive = () => false}) {
    mock.timers.enable({apis: ['setInterval', 'Date'], now: 1_000_000});
    const calls = {runs: [], state: []};
    let lastRuns = Date.now();
    let lastState = Date.now();
    const start = Date.now();
    const timer = setInterval(() => {
        const now = Date.now();
        const currentView = typeof view === 'function' ? view(now - start) : view;
        const plan = pollPlan({now, lastRuns, lastState, runsTabOpen,
            automationVisible: currentView === 'automation', overviewVisible: currentView === 'overview',
            runActive: runActive(now - start)});
        if (plan.runs) { lastRuns = now; calls.runs.push((now - start) / 1000); }
        if (plan.state) { lastState = now; calls.state.push((now - start) / 1000); }
    }, POLL.tick);
    try {
        for (let second = 0; second < seconds; second += 1) mock.timers.tick(1000);
    } finally {
        clearInterval(timer);
        mock.timers.reset();
    }
    return calls;
}

test('nothing is polled while another workspace is shown', () => {
    assert.deepEqual(simulate({seconds: 120, view: 'workspaces', runActive: () => true}), {runs: [], state: []});
    assert.deepEqual(simulate({seconds: 120, view: 'files'}), {runs: [], state: []});
});

test('the overview polls runs every 30 seconds while nothing is running and never polls state', () => {
    const calls = simulate({seconds: 95, view: 'overview'});
    assert.deepEqual(calls.runs, [30, 60, 90]);
    assert.deepEqual(calls.state, []);
});

test('an active run is followed every 3 seconds in the overview and slows down when it ends', () => {
    const calls = simulate({seconds: 75, view: 'overview', runActive: elapsed => elapsed <= 12_000});
    assert.deepEqual(calls.runs.slice(0, 4), [3, 6, 9, 12]);
    // Once the run is no longer active the next refresh is 30 seconds after the last one.
    assert.deepEqual(calls.runs.slice(4), [42, 72]);
});

test('automation polls state every 15 seconds and runs only when a run is active or the history is open', () => {
    const editing = simulate({seconds: 46, view: 'automation'});
    assert.deepEqual(editing, {runs: [], state: [15, 30, 45]});
    const history = simulate({seconds: 61, view: 'automation', runsTabOpen: true});
    assert.deepEqual(history.runs, [30, 60]);
    const active = simulate({seconds: 10, view: 'automation', runActive: () => true});
    assert.deepEqual(active.runs, [3, 6, 9]);
});

test('leaving automation stops state polling', () => {
    const calls = simulate({seconds: 90, view: elapsed => elapsed < 20_000 ? 'automation' : 'workspaces'});
    assert.deepEqual(calls.state, [15]);
});

test('timer drift does not skip a tick', () => {
    assert.equal(pollPlan({now: 2_990, lastRuns: 0, overviewVisible: true, runActive: true}).runs, true);
    assert.equal(pollPlan({now: 29_400, lastRuns: 0, overviewVisible: true}).runs, true);
    assert.equal(pollPlan({now: 27_000, lastRuns: 0, overviewVisible: true}).runs, false);
});

test('queued and running runs count as active', () => {
    assert.deepEqual(['queued', 'running', 'succeeded', 'failed', 'unknown', 'cancelled', undefined].map(status => isRunActive({status})),
        [true, true, false, false, false, false, false]);
    assert.equal(isRunActive(null), false);
});

test('the automation controller drives its interval through the shared plan', () => {
    const source = fs.readFileSync('static/js/automation.js', 'utf8');
    assert.match(source, /schedule\.pollPlan\(/);
    assert.match(source, /setInterval\(poll, schedule\.POLL\.tick\)/);
    assert.match(source, /'primary-workspace-change'/);
    assert.doesNotMatch(source, /lastStateRefresh >= 15000/);
});

test('a just started run is followed quickly before it appears in the history', () => {
    // The start response can arrive before the run is listed; the history tab
    // alone would only refresh every 30 seconds.
    const waiting = {now: 3_000, lastRuns: 0, automationVisible: true, runsTabOpen: true};
    assert.equal(pollPlan(waiting).runs, false);
    assert.equal(pollPlan({...waiting, runExpected: true}).runs, true);
    assert.equal(pollPlan({...waiting, runExpected: true, automationVisible: false}).runs, false);
    assert.ok(POLL.startedRunGrace >= POLL.activeRuns * 5);
});
