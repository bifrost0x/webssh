const exclusiveResourceTests = new Set([
    'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over polling',
    'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over websocket',
]);

function validateResourceInventory(discovered) {
    const identities = new Set(discovered.map(item => item.identity));
    for (const identity of exclusiveResourceTests) {
        if (!identities.has(identity)) throw new Error(`Missing exclusive resource test: ${identity}`);
    }
    for (const item of discovered) {
        if (item.identity.includes('tests/e2e/terminal-load.spec.js::') && !exclusiveResourceTests.has(item.identity)) {
            throw new Error(`Unknown exclusive resource test: ${item.identity}`);
        }
    }
}

function isExclusiveTest(test) {
    return exclusiveResourceTests.has(test.identity);
}

function selectPhase(assigned, phase) {
    if (!['all', 'exclusive', 'shared'].includes(phase)) throw new Error(`Unknown E2E phase: ${phase}`);
    const selected = assigned.filter(test => phase === 'all' || isExclusiveTest(test) === (phase === 'exclusive'));
    if (selected.length === 0) throw new Error(`E2E phase ${phase} has no assigned tests.`);
    return selected;
}

module.exports = { validateResourceInventory, isExclusiveTest, selectPhase };
