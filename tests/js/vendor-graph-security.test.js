const assert = require('node:assert/strict');
const test = require('node:test');
const graph = require('../../site/vendor/vis-network-9.1.6/vis-network.min.js');

test('DataSet updateOnly cannot merge through an inherited prototype', () => {
    const data = new graph.DataSet([{id: 1, label: 'First'}]);
    try {
        assert.throws(() => data.updateOnly(JSON.parse('{"id":1,"__proto__":{"websshAuditMarker":"owned"}}')), /Invalid object key/);
        assert.equal(Object.hasOwn(Object.prototype, 'websshAuditMarker'), false);
    } finally {
        delete Object.prototype.websshAuditMarker;
    }
    data.updateOnly({id: 1, label: 'Updated', font: {size: 18}});
    assert.equal(data.get(1).label, 'Updated');
    assert.equal(data.get(1).font.size, 18);
});

for (const [name, parse] of Object.entries({
    parseDOT: graph.networkDOTParser.parseDOT,
    parseDOTNetwork: graph.parseDOTNetwork,
})) {
    for (const attribute of ['__proto__.websshAuditMarker', 'constructor.prototype.websshAuditMarker']) {
        test(`${name} rejects prototype traversal in DOT attributes: ${attribute}`, () => {
            try {
                assert.throws(() => parse(`digraph { a ["${attribute}"="owned"]; }`), /Invalid DOT attribute/);
                assert.equal(Object.hasOwn(Object.prototype, 'websshAuditMarker'), false);
            } finally {
                delete Object.prototype.websshAuditMarker;
            }
        });
    }
}

test('DOT graph conversion preserves ordinary nodes, edges and dotted attributes', () => {
    const result = graph.parseDOTNetwork('digraph { a [label="First", "font.size"=16]; b [label="Second"]; a -> b [label="route"]; }');
    assert.equal(result.nodes[0].label, 'First');
    assert.equal(result.nodes[0].font.size, 16);
    assert.equal(result.nodes[1].label, 'Second');
    assert.equal(result.edges[0].from, 'a');
    assert.equal(result.edges[0].to, 'b');
    assert.equal(result.edges[0].label, 'route');
});
