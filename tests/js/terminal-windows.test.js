const test = require('node:test');
const assert = require('node:assert/strict');

const windows = require('../../static/js/terminal-windows.js');

const DESKTOP = {width: 1200, height: 800};

function overlaps(a, b) {
    return a.x < b.x + b.width && b.x < a.x + a.width
        && a.y < b.y + b.height && b.y < a.y + a.height;
}

function inside(rect, bounds) {
    return rect.x >= 0 && rect.y >= 0
        && rect.x + rect.width <= bounds.width
        && rect.y + rect.height <= bounds.height;
}

test('clamping keeps a minimum size and the title bar reachable', () => {
    const tiny = windows.clampRect({x: 10, y: 10, width: 40, height: 20}, DESKTOP);
    assert.equal(tiny.width, windows.MIN_WIDTH);
    assert.equal(tiny.height, windows.MIN_HEIGHT);

    const lost = windows.clampRect({x: 5000, y: 5000, width: 400, height: 300}, DESKTOP);
    assert.equal(lost.x, DESKTOP.width - 96);
    assert.equal(lost.y, DESKTOP.height - windows.TITLE_HEIGHT);

    const left = windows.clampRect({x: -5000, y: -40, width: 400, height: 300}, DESKTOP);
    assert.equal(left.x, 96 - 400);
    assert.equal(left.y, 0);

    const huge = windows.clampRect({x: 0, y: 0, width: 9000, height: 9000}, DESKTOP);
    assert.deepEqual(huge, {x: 0, y: 0, width: DESKTOP.width, height: DESKTOP.height});
});

test('a desktop smaller than the minimum window still fits the window', () => {
    const small = {width: 280, height: 150};
    const rect = windows.clampRect({x: 0, y: 0, width: 50, height: 50}, small);
    assert.equal(rect.width, 280);
    assert.equal(rect.height, 150);
});

test('resizing moves only the dragged edges and honours the minimum size', () => {
    const start = {x: 100, y: 100, width: 500, height: 400};
    assert.deepEqual(
        windows.resizeRect(start, 'se', 60, 40, DESKTOP),
        {x: 100, y: 100, width: 560, height: 440},
    );
    assert.deepEqual(
        windows.resizeRect(start, 'nw', 30, 20, DESKTOP),
        {x: 130, y: 120, width: 470, height: 380},
    );
    const collapsed = windows.resizeRect(start, 'w', 900, 0, DESKTOP);
    assert.equal(collapsed.width, windows.MIN_WIDTH);
    assert.equal(collapsed.x + collapsed.width, start.x + start.width);
    const shortened = windows.resizeRect(start, 'n', 0, 900, DESKTOP);
    assert.equal(shortened.height, windows.MIN_HEIGHT);
    assert.equal(shortened.y + shortened.height, start.y + start.height);
});

test('resizing stops at the desktop border', () => {
    const start = {x: 100, y: 100, width: 500, height: 400};
    const grown = windows.resizeRect(start, 'nw', -900, -900, DESKTOP);
    assert.equal(grown.x, 0);
    assert.equal(grown.y, 0);
    const wide = windows.resizeRect(start, 'se', 2000, 2000, DESKTOP);
    assert.equal(wide.x + wide.width, DESKTOP.width);
    assert.equal(wide.y + wide.height, DESKTOP.height);
});

test('a window already past an edge can keep resizing out there', () => {
    const start = {x: -120, y: 50, width: 500, height: 300};
    const rect = windows.resizeRect(start, 'w', -30, 0, DESKTOP);
    assert.equal(rect.x, -120);
    assert.equal(rect.width, 500);
});

test('snap zones follow the edges and corners of the desktop', () => {
    assert.equal(windows.snapZone({x: 2, y: 400}, DESKTOP), 'left');
    assert.equal(windows.snapZone({x: 1198, y: 400}, DESKTOP), 'right');
    assert.equal(windows.snapZone({x: 600, y: 3}, DESKTOP), 'maximize');
    assert.equal(windows.snapZone({x: 3, y: 3}, DESKTOP), 'top-left');
    assert.equal(windows.snapZone({x: 1199, y: 2}, DESKTOP), 'top-right');
    assert.equal(windows.snapZone({x: 1, y: 799}, DESKTOP), 'bottom-left');
    assert.equal(windows.snapZone({x: 1199, y: 799}, DESKTOP), 'bottom-right');
    assert.equal(windows.snapZone({x: 600, y: 400}, DESKTOP), null);
    assert.equal(windows.snapZone({x: 600, y: 799}, DESKTOP), null);
});

test('snapped halves and quarters fill the desktop without overlapping', () => {
    const left = windows.snapRect('left', DESKTOP);
    const right = windows.snapRect('right', DESKTOP);
    assert.ok(inside(left, DESKTOP) && inside(right, DESKTOP));
    assert.equal(overlaps(left, right), false);
    assert.equal(left.height, right.height);
    assert.equal(Math.abs(left.width - right.width) <= 1, true);

    const quarters = ['top-left', 'top-right', 'bottom-left', 'bottom-right']
        .map(zone => windows.snapRect(zone, DESKTOP));
    quarters.forEach((rect, index) => {
        assert.ok(inside(rect, DESKTOP));
        quarters.slice(index + 1).forEach(other => assert.equal(overlaps(rect, other), false));
    });
    assert.deepEqual(
        windows.snapRect('maximize', DESKTOP),
        {x: 0, y: 0, width: DESKTOP.width, height: DESKTOP.height},
    );
    assert.equal(windows.snapRect('nowhere', DESKTOP), null);
});

test('tiling covers every window without overlaps for any count', () => {
    for (let count = 1; count <= 12; count += 1) {
        const rects = windows.tileLayout(count, DESKTOP);
        assert.equal(rects.length, count);
        rects.forEach((rect, index) => {
            assert.ok(inside(rect, DESKTOP), `count ${count}: ${JSON.stringify(rect)}`);
            rects.slice(index + 1).forEach(other => {
                assert.equal(overlaps(rect, other), false, `count ${count}`);
            });
        });
    }
    assert.deepEqual(windows.tileLayout(0, DESKTOP), []);
});

test('tiling prefers side by side on wide screens and stacks on tall ones', () => {
    const [first, second] = windows.tileLayout(2, {width: 1600, height: 700});
    assert.equal(first.y, second.y);
    assert.ok(second.x > first.x);

    const [top, bottom] = windows.tileLayout(2, {width: 700, height: 1400});
    assert.equal(top.x, bottom.x);
    assert.ok(bottom.y > top.y);

    const grid = windows.tileLayout(4, {width: 1600, height: 900});
    assert.equal(new Set(grid.map(rect => rect.y)).size, 2);
});

test('cascading places new windows on fresh positions inside the desktop', () => {
    const placed = [];
    for (let index = 0; index < 20; index += 1) {
        const rect = windows.cascadeRect(placed, DESKTOP);
        assert.ok(inside(rect, DESKTOP), JSON.stringify(rect));
        placed.push(rect);
    }
    const lastTen = placed.slice(-10).map(rect => `${rect.x}:${rect.y}`);
    assert.equal(new Set(lastTen).size, lastTen.length);

    const layout = windows.cascadeLayout(5, DESKTOP);
    assert.equal(new Set(layout.map(rect => `${rect.x}:${rect.y}`)).size, 5);
    layout.forEach(rect => assert.ok(inside(rect, DESKTOP)));
});

test('fractions round-trip and scale with the desktop', () => {
    const rect = {x: 120, y: 80, width: 600, height: 400};
    const fraction = windows.toFraction(rect, DESKTOP);
    assert.deepEqual(windows.fromFraction(fraction, DESKTOP), rect);
    const doubled = windows.fromFraction(fraction, {width: 2400, height: 1600});
    assert.deepEqual(doubled, {x: 240, y: 160, width: 1200, height: 800});
});

test('stored fractions are validated before use', () => {
    assert.deepEqual(
        windows.validFraction({x: 0.1, y: 0.2, width: 0.5, height: 0.4}),
        {x: 0.1, y: 0.2, width: 0.5, height: 0.4},
    );
    for (const bad of [
        null,
        'x',
        {x: 0, y: 0, width: 0, height: 0.5},
        {x: 0, y: 0, width: 2, height: 0.5},
        {x: 0, y: 0, width: 0.5, height: -1},
        {x: 'a', y: 0, width: 0.5, height: 0.5},
        {x: 0, y: 1.5, width: 0.5, height: 0.5},
        {x: -3, y: 0, width: 0.5, height: 0.5},
    ]) {
        assert.equal(windows.validFraction(bad), null, JSON.stringify(bad));
    }
});

test('default windows are comfortable but never exceed the desktop', () => {
    const size = windows.defaultSize(DESKTOP);
    assert.ok(size.width >= windows.MIN_WIDTH && size.width <= DESKTOP.width);
    assert.ok(size.height >= windows.MIN_HEIGHT && size.height <= DESKTOP.height);
    const capped = windows.defaultSize({width: 4000, height: 3000});
    assert.equal(capped.width, 980);
    assert.equal(capped.height, 640);
    const cramped = windows.defaultSize({width: 300, height: 160});
    assert.deepEqual(cramped, {width: 300, height: 160});
});
