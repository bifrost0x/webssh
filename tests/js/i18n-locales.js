// Shared loaders for the i18n runtime and its per-language dictionaries.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '../..');
const LOCALES = ['en', 'vi', 'de', 'fr', 'es', 'zh'];
const runtimeSource = fs.readFileSync(path.join(root, 'static/js/i18n.js'), 'utf8');

function localePath(locale) {
    return path.join(root, 'static/js/i18n', `${locale}.js`);
}

function localeSource(locale) {
    return fs.readFileSync(localePath(locale), 'utf8');
}

// Runs the runtime and the given dictionaries inside one vm context, the way a
// page loads i18n.js followed by its locale scripts.
function runI18n(context, locales = LOCALES) {
    const sandbox = vm.isContext(context) ? context : vm.createContext(context);
    vm.runInContext(runtimeSource, sandbox);
    for (const locale of locales) vm.runInContext(localeSource(locale), sandbox);
    return sandbox;
}

// Every locale's entries in file order, duplicates included.
function localeEntries(locale) {
    const espree = require('espree');
    const ast = espree.parse(localeSource(locale), {ecmaVersion: 'latest'});
    const call = ast.body.find(node => node.type === 'ExpressionStatement'
        && node.expression.type === 'CallExpression'
        && node.expression.callee.property?.name === 'registerLocales');
    if (!call) throw new Error(`${locale}.js does not call registerLocales`);
    const [bundle] = call.expression.arguments;
    const table = bundle.properties.find(property => (property.key.name || property.key.value) === locale);
    if (!table || bundle.properties.length !== 1) throw new Error(`${locale}.js must register exactly ${locale}`);
    return table.value.properties.map(property => [property.key.value, property.value.value]);
}

function localeTable() {
    return Object.fromEntries(LOCALES.map(locale => [locale, Object.fromEntries(localeEntries(locale))]));
}

module.exports = {LOCALES, localeEntries, localePath, localeSource, localeTable, runI18n, runtimeSource};
