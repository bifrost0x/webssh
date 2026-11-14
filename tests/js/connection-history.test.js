const test = require('node:test');
const assert = require('node:assert/strict');

const { createConnectionHistory } = require(
    '../../static/js/connection-history.js'
);

function createStorage(initial = {}) {
    const values = new Map(Object.entries(initial));
    return {
        get length() {
            return values.size;
        },
        key(index) {
            return [...values.keys()][index] ?? null;
        },
        getItem(key) {
            return values.has(key) ? values.get(key) : null;
        },
        setItem(key, value) {
            values.set(key, String(value));
        },
        removeItem(key) {
            values.delete(key);
        },
        snapshot() {
            return Object.fromEntries(values);
        },
    };
}

test('isolates recent connections by authenticated user scope', () => {
    const storage = createStorage();
    const alice = createConnectionHistory({
        storage,
        scope: 'user-1',
        now: () => 1_000,
    });
    const bob = createConnectionHistory({
        storage,
        scope: 'user-2',
        now: () => 1_000,
    });

    alice.addConnection('alpha.internal', 22, 'alice');

    assert.deepEqual(alice.getHistory(), [{
        host: 'alpha.internal',
        port: 22,
        username: 'alice',
        timestamp: 1_000,
    }]);
    assert.deepEqual(bob.getHistory(), []);
    assert.deepEqual(Object.keys(storage.snapshot()).sort(), [
        'recentConnections:user-1',
    ]);
});

test('removes expired histories from inactive account scopes', () => {
    const day = 24 * 60 * 60 * 1_000;
    const now = 40 * day;
    const storage = createStorage({
        'recentConnections:inactive-scope': JSON.stringify([{
            host: 'expired.internal',
            port: 22,
            username: 'old-user',
            timestamp: now - (31 * day),
        }]),
        unrelated: 'keep-me',
    });

    createConnectionHistory({
        storage,
        scope: 'current-scope',
        now: () => now,
    });

    assert.deepEqual(storage.snapshot(), { unrelated: 'keep-me' });
});

test('fails closed without a user scope and removes legacy shared history', () => {
    const storage = createStorage({
        recentConnections: JSON.stringify([{
            host: 'legacy.internal',
            port: 22,
            username: 'shared',
        }]),
    });
    const history = createConnectionHistory({
        storage,
        scope: '',
        now: () => 2_000,
    });

    history.addConnection('ignored.internal', 22, 'nobody');

    assert.deepEqual(history.getHistory(), []);
    assert.deepEqual(storage.snapshot(), {});
});

test('deduplicates endpoints and drops expired or malformed entries', () => {
    const now = 40 * 24 * 60 * 60 * 1_000;
    const storage = createStorage({
        'recentConnections:user-7': JSON.stringify([
            {
                host: 'expired.internal',
                port: 22,
                username: 'old',
                timestamp: 1,
            },
            {
                host: '',
                port: 22,
                username: 'invalid',
                timestamp: now,
            },
            {
                host: 'valid.internal',
                port: 2202,
                username: 'operator',
                timestamp: now - 1_000,
            },
        ]),
    });
    const history = createConnectionHistory({
        storage,
        scope: 'user-7',
        now: () => now,
    });

    history.addConnection('valid.internal', '2202', 'operator');

    assert.deepEqual(history.getHistory(), [{
        host: 'valid.internal',
        port: 2202,
        username: 'operator',
        timestamp: now,
    }]);
});

test('keeps at most ten entries and excludes the exact 30-day boundary', () => {
    const day = 24 * 60 * 60 * 1_000;
    const now = 40 * day;
    const entries = Array.from({ length: 11 }, (_, index) => ({
        host: `host-${index}.internal`,
        port: 22,
        username: 'operator',
        timestamp: now - (index + 1),
    }));
    entries.unshift({
        host: 'boundary.internal',
        port: 22,
        username: 'operator',
        timestamp: now - (30 * day),
    });
    entries.unshift({
        host: 'inside.internal',
        port: 22,
        username: 'operator',
        timestamp: now - (30 * day) + 1,
    });
    const storage = createStorage({
        'recentConnections:user-8': JSON.stringify(entries),
    });
    const history = createConnectionHistory({
        storage,
        scope: 'user-8',
        now: () => now,
    });

    const retained = history.getHistory();

    assert.equal(retained.length, 10);
    assert.equal(retained[0].host, 'inside.internal');
    assert.equal(retained.some(entry => entry.host === 'boundary.internal'), false);
});

test('history retains route identity and never persists connection secrets', () => {
    const storage = createStorage();
    const history = createConnectionHistory({storage, scope:'user-route', now:()=>1_000});
    history.addConnection('target.internal',22,'user',{socks_proxy_id:'proxy-a',via_socks:true,
        password:'target-secret',credential_id:'private-credential',credential_target_token:'private-token',
        socks_proxy:{password:'proxy-secret',username:'proxy-user',host:'private-proxy'}});
    assert.deepEqual(history.getHistory(),[{host:'target.internal',port:22,username:'user',timestamp:1_000,socks_proxy_id:'proxy-a'}]);
    const persisted=storage.getItem(history.storageKey);
    for (const secret of ['target-secret','proxy-secret','private-credential','private-token','proxy-user','private-proxy']) assert.equal(persisted.includes(secret),false);
});

test('history deduplicates by endpoint and route without replacing direct or other proxies', () => {
    const history=createConnectionHistory({storage:createStorage(),scope:'user-route',now:()=>1_000});
    history.addConnection('target.internal',22,'user');
    history.addConnection('target.internal',22,'user',{socks_proxy_id:'proxy-a'});
    history.addConnection('target.internal',22,'user',{socks_proxy_id:'proxy-b'});
    history.addConnection('target.internal',22,'user',{jump_host_id:'jump-a'});
    history.addConnection('target.internal',22,'user',{socks_proxy_id:'proxy-a'});
    assert.equal(history.getHistory().length,4);
    assert.equal(history.getHistory()[0].socks_proxy_id,'proxy-a');
    assert.equal(history.getHistory().filter(entry=>!entry.socks_proxy_id&&!entry.jump_host_id).length,1);
});

test('invalid or unknown routed histories are discarded instead of normalized into direct routes', () => {
    const entries=[
        {socks_proxy_id:42}, {socks_proxy_id:{}}, {socks_proxy_id:'x'.repeat(65)},
        {socks_proxy_id:'bad/reference'}, {via_socks:true}, {via_socks:true,socks_proxy_id:''},
        {socks_proxy_id:'proxy',jump_host_id:'jump'}, {via_jump:true},
    ].map(route=>({host:'target.internal',port:22,username:'user',timestamp:1_000,...route}));
    const storage=createStorage({'recentConnections:user-route':JSON.stringify(entries)});
    const history=createConnectionHistory({storage,scope:'user-route',now:()=>1_001});
    assert.deepEqual(history.getHistory(),[]);
    history.addConnection('target.internal',22,'user',{via_socks:true});
    assert.deepEqual(history.getHistory(),[]);
});

test('inactive account cleanup preserves SOCKS route references', () => {
    const entry={host:'target.internal',port:22,username:'user',timestamp:1_000,socks_proxy_id:'proxy-a'};
    const storage=createStorage({'recentConnections:other':JSON.stringify([entry])});
    createConnectionHistory({storage,scope:'active',now:()=>1_001});
    assert.deepEqual(JSON.parse(storage.getItem('recentConnections:other')),[entry]);
});
