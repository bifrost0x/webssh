const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const espree = require('espree');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/i18n.js'), 'utf8');
const ast = espree.parse(source, {ecmaVersion: 'latest'});
const declaration = ast.body.find(node => node.type === 'VariableDeclaration'
    && node.declarations.some(item => item.id.name === 'translations'));
const table = declaration.declarations.find(item => item.id.name === 'translations').init;
const locales = Object.fromEntries(table.properties.map(locale => [
    locale.key.name || locale.key.value,
    locale.value.properties.map(property => [property.key.value, property.value.value]),
]));
const placeholders = value => (value.match(/\{\{?\w+\}?\}|%[sd]/g) || []).sort();

// Feature bundles register dictionaries before DOMContentLoaded. Include them
// in the same contract checks as the core table, without hiding missing locale
// keys behind the runtime's English fallback.
const bundleRoot = path.join(__dirname, '../../static/js');
const registered = Object.fromEntries(Object.entries(locales).map(([language, entries]) => [language, Object.fromEntries(entries)]));
const featureBundles = fs.readdirSync(bundleRoot).filter(file => file.endsWith('-i18n.js'))
    .filter(file => fs.readFileSync(path.join(bundleRoot, file), 'utf8').includes('.addTranslations('));
for (const file of featureBundles) {
    const dictionaries = {};
    const window = {i18n: {addTranslations(language, values) {
        assert.ok(Object.hasOwn(registered, language), `${file}: unsupported language ${language}`);
        dictionaries[language] = {...dictionaries[language], ...values};
        Object.assign(registered[language], values);
    }}};
    vm.runInNewContext(fs.readFileSync(path.join(bundleRoot, file), 'utf8'), {window});
    test(`${file} supplies complete nonempty translations and matching placeholders in every language`, () => {
        assert.deepEqual(Object.keys(dictionaries).sort(), Object.keys(locales).sort());
        const english = dictionaries.en;
        for (const [language, values] of Object.entries(dictionaries)) {
            assert.deepEqual(Object.keys(values).sort(), Object.keys(english).sort(), language);
            for (const [key, value] of Object.entries(values)) {
                assert.equal(typeof value, 'string', `${language}: ${key}`);
                assert.ok(value.trim(), `${language}: ${key}`);
                assert.deepEqual(placeholders(value), placeholders(english[key]), `${language}: ${key}`);
            }
        }
    });
}


test('translation table includes every supported language', () => {
    assert.deepEqual(Object.keys(locales).sort(), ['de', 'en', 'es', 'fr', 'vi', 'zh']);
});

test('all HTML templates reference existing translation keys', () => {
    const english = registered.en;
    const templateRoot = path.join(__dirname, '../../templates');
    const templates = fs.readdirSync(templateRoot, {recursive: true}).filter(file => file.endsWith('.html'));
    assert.ok(templates.length > 0, 'No templates found');
    for (const template of templates) {
        const markup = fs.readFileSync(path.join(templateRoot, template), 'utf8');
        const references = markup.matchAll(/data-i18n(?:-[a-z-]+)?="([\w.]+)"/g);
        for (const [, key] of references) {
            assert.ok(Object.hasOwn(english, key), `${template}: unknown ${key}`);
        }
    }
});

for (const [locale, entries] of Object.entries(locales)) {
    test(`${locale} has unique keys and nonempty string translations`, () => {
        const seen = new Set();
        for (const [key, value] of entries) {
            assert.ok(!seen.has(key), `${locale}: duplicate ${key}`);
            seen.add(key);
            assert.equal(typeof value, 'string', `${locale}: ${key} must be text`);
            assert.ok(value.trim(), `${locale}: empty ${key}`);
        }
    });
    test(`${locale} matches English keys and interpolation placeholders`, () => {
        const values = Object.fromEntries(entries);
        const english = Object.fromEntries(locales.en);
        assert.deepEqual(Object.keys(values).sort(), Object.keys(english).sort());
        for (const [key, value] of entries) {
            assert.deepEqual(placeholders(value), placeholders(english[key]), `${locale}: ${key}`);
        }
    });
}

test('chmod help explains separate modes, optional recursion and preview in every locale', () => {
    const required = {
        en: [/files/i, /folders/i, /optional/i, /preview/i, /apply/i],
        de: [/Dateien/, /Ordner/, /optional/i, /Vorschau/, /anwenden/i],
        vi: [/tệp/, /thư mục/, /tùy chọn/, /xem trước/, /áp dụng/],
        fr: [/fichiers/, /dossiers/, /facultative/, /aperçu/, /appliqu/],
        es: [/archivos/, /carpetas/, /opcional/, /vista previa/, /aplic/],
        zh: [/文件/, /文件夹/, /可选/, /预览/, /应用/],
    };
    for (const [locale, patterns] of Object.entries(required)) {
        const help = Object.fromEntries(locales[locale])['fm.chmodHelpUsage'];
        assert.doesNotMatch(help, /20/, `${locale}: obsolete selection cap`);
        for (const pattern of patterns) assert.match(help, pattern, `${locale}: missing ${pattern}`);
    }
    const manager = fs.readFileSync(path.join(__dirname, '../../static/js/sftp-file-manager.js'), 'utf8');
    const fallback = /data-i18n="fm.chmodHelpUsage">([^<]+)</.exec(manager)[1];
    assert.match(fallback, /optional/i);
    assert.match(fallback, /preview/i);
    assert.match(fallback, /apply/i);
    assert.doesNotMatch(fallback, /20|Select one /);
});
