const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const test = require('node:test');

const eslintRequire = createRequire(require.resolve('eslint'));
const configArrayRequire = createRequire(eslintRequire.resolve('@eslint/config-array'));

for (const [consumer, load] of [['eslint', eslintRequire], ['config-array', configArrayRequire]]) {
    const { Minimatch } = load('minimatch');

    test(`${consumer} limits globstar-parent pattern amplification`, () => {
        for (const prefix of ['root', '{root,other}']) {
            const pattern = `${prefix}/${'**/../a/b/'.repeat(8)}*.js`;
            const matcher = new Minimatch(pattern, {
                optimizationLevel: 2,
                braceExpandMax: 16,
            });
            assert.ok(matcher.set.length <= 16, `${prefix}: expanded to ${matcher.set.length} patterns`);
        }
    });

    test(`${consumer} preserves lint file matching`, () => {
        const matcher = new Minimatch('static/js/**/*.{js,cjs}', { dot: true });
        assert.equal(matcher.match('static/js/app.js'), true);
        assert.equal(matcher.match('static/js/nested/.hidden.cjs'), true);
        assert.equal(matcher.match('static/js/app.css'), false);
        assert.equal(matcher.match('templates/app.js'), false);
        assert.equal(matcher.match('static/js/nested', true), true);
        const ignored = new Minimatch('!static/js/**', { dot: true, flipNegate: true });
        assert.equal(ignored.match('static/js/app.js'), true);
        assert.equal(ignored.match('templates/app.js'), false);
        const windows = new Minimatch('static/js/**/*.js', { dot: true, platform: 'win32' });
        assert.equal(windows.match('static\\js\\nested\\app.js'), true);
        assert.equal(windows.match('static\\js\\nested\\app.css'), false);
    });
}
