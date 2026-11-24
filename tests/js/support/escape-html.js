'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Evaluates the escaper app.js installs as window.escapeHtml, so script tests
// run against the production implementation instead of a stand-in.
function loadEscapeHtml() {
    const source = fs.readFileSync(path.join(__dirname, '../../../static/js/app.js'), 'utf8')
        .replace(/\r\n/g, '\n');
    const match = /\n {4}window\.escapeHtml = function[\s\S]*?\n {4}\};\n/.exec(source);
    if (!match) throw new Error('window.escapeHtml was not found in app.js');
    const context = { window: {} };
    vm.runInNewContext(match[0], context);
    return context.window.escapeHtml;
}

module.exports = { loadEscapeHtml };
