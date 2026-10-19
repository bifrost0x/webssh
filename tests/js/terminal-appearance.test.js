const test = require('node:test');
const assert = require('node:assert/strict');
const appearance = require('../../static/js/terminal-appearance');

const base = {background: '#182028', foreground: '#eeeeee', cursor: '#ffffff', red: '#cc0000'};
test('custom terminal colors survive a different app theme without changing ANSI colors', () => {
    const settings = {background: '#112233', foreground: '#abcdef', cursor_color: '#fedcba'};
    const result = appearance.resolve(settings, base, 'monospace', 14);
    assert.equal(result.surface, '#112233');
    assert.equal(result.options.theme.foreground, '#abcdef');
    assert.equal(result.options.theme.cursor, '#fedcba');
    assert.equal(result.options.theme.red, base.red);
    assert.equal(base.foreground, '#eeeeee');
    assert.equal(appearance.resolve(settings, {...base, background: '#ffffff'}, 'monospace', 14).surface, '#112233');
});
test('opacity affects only the background surface, not terminal text', () => {
    const result = appearance.resolve({background_opacity: 25}, base, 'monospace', 14);
    assert.equal(result.opacity, .25);
    assert.equal(result.options.theme.background, '#00000000');
    assert.equal(result.options.theme.foreground, base.foreground);
    assert.equal(result.options.allowTransparency, true);
});
test('custom typography survives responsive sizing and reset follows theme defaults', () => {
    const result = appearance.resolve({font_family: 'JetBrains Mono', font_size: 19, line_height: 1.4, letter_spacing: .5, font_weight: 'bold', cursor_style: 'bar', cursor_blink: false}, base, 'Consolas', 12);
    assert.equal(result.options.fontSize, 19);
    assert.equal(result.options.fontFamily, '"JetBrains Mono", monospace');
    assert.equal(result.options.lineHeight, 1.4);
    assert.equal(result.options.letterSpacing, .5);
    assert.equal(result.options.fontWeight, 'bold');
    assert.equal(result.options.cursorStyle, 'bar');
    assert.equal(result.options.cursorBlink, false);
    const reset = appearance.resolve({}, base, 'Consolas', 12);
    assert.equal(reset.options.fontSize, 12);
    assert.equal(reset.options.fontFamily, 'Consolas');
    assert.equal(reset.surface, base.background);
    assert.equal(reset.opacity, 1);
});
test('invalid browser-side values cannot inject CSS or unbounded terminal geometry', () => {
    const result = appearance.resolve({font_family: 'x";url(https://example.com)', background: 'url(x)', font_size: 999, line_height: Infinity, letter_spacing: NaN, background_opacity: -5}, base, 'monospace', 14);
    assert.equal(result.options.fontFamily, 'monospace');
    assert.equal(result.surface, base.background);
    assert.equal(result.options.fontSize, 14);
    assert.equal(result.options.lineHeight, 1);
    assert.equal(result.options.letterSpacing, 0);
    assert.equal(result.opacity, 1);
});

test('theme refresh applies saved typography and colors to existing terminal instances', () => {
    global.window = {addEventListener() {}, TerminalAppearance: appearance};
    require('../../static/js/terminal-manager');
    const manager = window.TerminalManager;
    manager.buildTheme = () => base;
    manager.getMonoFont = () => 'monospace';
    manager.getResponsiveFontSize = () => 12;
    appearance.setPreferences({font_size: 20, font_family: 'Consolas', cursor_style: 'underline', foreground: '#aabbcc'});
    const terminal = {options: {}, rows: 24, refresh() {}};
    manager.terminals = {one: terminal};
    manager.sessionTerminals = {session: ['one']};
    manager.applyThemeToTerminal('session');
    assert.equal(terminal.options.fontSize, 20);
    assert.equal(terminal.options.theme.foreground, '#aabbcc');
    assert.equal(terminal.options.cursorStyle, 'underline');
    appearance.setPreferences({});
    manager.applyThemeToTerminal('session');
    assert.equal(terminal.options.fontSize, 12);
    assert.equal(terminal.options.theme.foreground, base.foreground);
});

test('bundled fonts load both weights once and become usable only after loading', async () => {
    const family = 'WebSSH Hack';
    const calls = [];
    let finish;
    const pending = new Promise(resolve => { finish = resolve; });
    const fonts = {load(spec, sample) { calls.push({spec, sample}); return pending; }};
    assert.equal(appearance.resolve({font_family: family}, base, 'monospace', 14).options.fontFamily, 'monospace');
    const first = appearance.loadFont(family, fonts);
    const second = appearance.loadFont(family, fonts);
    assert.equal(first, second);
    assert.equal(calls.length, 2);
    assert.match(calls[0].spec, /^400 /);
    assert.match(calls[1].spec, /^700 /);
    finish([{}]);
    assert.equal(await first, true);
    assert.equal(appearance.resolve({font_family: family}, base, 'monospace', 14).options.fontFamily, '"WebSSH Hack", monospace');
    await appearance.loadFont(family, fonts);
    assert.equal(calls.length, 2);
});

test('failed bundled font loads remain on fallback and can be retried', async () => {
    const family = 'WebSSH Fira Mono';
    assert.equal(await appearance.loadFont(family, {load: () => Promise.reject(new Error('offline'))}), false);
    assert.equal(appearance.resolve({font_family: family}, base, 'Consolas', 14).options.fontFamily, 'Consolas');
    assert.equal(await appearance.loadFont(family, {load: () => Promise.resolve([])}), false);
    assert.equal(await appearance.loadFont(family, {load: () => Promise.resolve([{}])}), true);
});

test('custom font names never trigger font discovery or URL fetching', async () => {
    const fonts = {load() { throw new Error('Must not query local fonts'); }};
    for (const family of ['Consolas', 'theme', 'https://example.com/font.woff2', '";url(x)', '__proto__']) {
        assert.equal(await appearance.loadFont(family, fonts), true);
    }
    assert.equal(await appearance.loadFont('WebSSH Source Code Pro', null), false);
});

test('preview contains Nerd Font icons from both Unicode private-use planes', () => {
    assert.match(appearance.samples.shell, /\uf07b/);
    assert.match(appearance.samples.characters, /\u{f0004}/u);
});

test('slow font loading times out without blocking, then recovers when bytes arrive', async () => {
    const vm = require('node:vm');
    const fs = require('node:fs');
    let timeout;
    const context = {module: {exports: {}}, setTimeout(callback) { timeout = callback; }, clearTimeout() {}};
    vm.runInNewContext(fs.readFileSync(require.resolve('../../static/js/terminal-appearance'), 'utf8'), context);
    const api = context.module.exports;
    let complete;
    const bytes = new Promise(resolve => { complete = resolve; });
    const family = 'WebSSH Source Code Pro';
    const request = api.loadFont(family, {load: () => bytes});
    timeout();
    assert.equal(await request, false);
    assert.equal(api.resolve({font_family: family}, base, 'monospace', 14).options.fontFamily, 'monospace');
    complete([{}]);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(api.resolve({font_family: family}, base, 'monospace', 14).options.fontFamily, '"WebSSH Source Code Pro", monospace');
});

test('shared PUA icons also protect theme and unpatched local fonts without replacing text', async () => {
    const fs = require('node:fs');
    const css = fs.readFileSync('static/vendor/terminal-fonts/fonts.css', 'utf8');
    assert.match(css, /unicode-range: U\+E000-F8FF, U\+F0000-FFFFD, U\+100000-10FFFD/);
    const calls = [];
    await appearance.loadFont('WebSSH Nerd Symbols', {load(spec) { calls.push(spec); return Promise.resolve([{}]); }});
    assert.equal(calls.length, 1);
    for (const family of ['Fira Mono', 'WebSSH Fira Mono', 'theme']) {
        const result = appearance.resolve({font_family: family}, base, 'Consolas, monospace', 14);
        assert.equal(result.options.fontFamily, `${family === 'theme' ? 'Consolas' : `"${family}"`}, "WebSSH Nerd Symbols", monospace`);
    }
});

test('live font changes wait for xterm cell measurement before resizing the server PTY', () => {
    const manager = window.TerminalManager;
    const saved = Object.fromEntries(['updateAppearanceSurface', 'applyThemeToTerminal', 'fitAndSyncVisibleTerminals', 'sessionTerminals'].map(key => [key, manager[key]]));
    const frames = [];
    const events = [];
    global.requestAnimationFrame = callback => frames.push(callback);
    manager.sessionTerminals = {live: ['live']};
    manager.updateAppearanceSurface = () => {};
    manager.applyThemeToTerminal = () => {
        events.push('font changed');
        requestAnimationFrame(() => events.push('cells measured'));
    };
    global.SessionManager = {getSession: id => ({connected: id === 'live'})};
    manager.fitAndSyncVisibleTerminals = ({isConnected}) => {
        assert.equal(isConnected('live'), true);
        assert.equal(isConnected('closed'), false);
        events.push('server resized');
    };
    try {
        manager.applyThemeToAll();
        frames.shift()();
        assert.deepEqual(events, ['font changed']);
        while (frames.length) frames.shift()();
        assert.deepEqual(events, ['font changed', 'cells measured', 'server resized']);
    } finally {
        Object.assign(manager, saved);
        delete global.requestAnimationFrame;
        delete global.SessionManager;
    }
});
