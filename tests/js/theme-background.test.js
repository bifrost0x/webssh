const test = require('node:test');
const assert = require('node:assert/strict');
const {inspect} = require('../../static/js/theme-background.js');
function png(width = 1920, height = 1080, animated = false) {
    const bytes = Buffer.alloc(animated ? 57 : 45);
    bytes.writeUInt32BE(0x89504e47); bytes.writeUInt32BE(0x0d0a1a0a, 4);
    bytes.writeUInt32BE(13, 8); bytes.write('IHDR', 12);
    bytes.writeUInt32BE(width, 16); bytes.writeUInt32BE(height, 20);
    if (animated) bytes.write('acTL', 37);
    bytes.write('IEND', bytes.length - 8);
    return bytes;
}
test('wallpapers enforce dimensions before image decoding', () => {
    assert.equal(inspect(png()), 'image/png');
    for (const size of [[1, 1], [1080, 1920], [100000, 100000]]) {
        assert.throws(() => inspect(png(...size)), /dimensions/);
    }
});
test('wallpapers reject animation, SVG, truncated chunks and arbitrary files', () => {
    assert.throws(() => inspect(png(1920, 1080, true)), /format/);
    for (const bytes of [Buffer.from('<svg onload="alert(1)"/>'), Buffer.from('GIF89a'), png().subarray(0, 34)]) {
        assert.throws(() => inspect(bytes), /format/);
    }
    const oversizedChunk = png(); oversizedChunk.writeUInt32BE(0xffffffff, 33);
    assert.throws(() => inspect(oversizedChunk), /format/);
});
test('JPEG dimensions are read without trusting filename or MIME type', () => {
    const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 4, 56, 7, 128, 0, 0xff, 0xd9]);
    assert.equal(inspect(jpeg), 'image/jpeg');
    jpeg[7] = 0xff;
    assert.throws(() => inspect(jpeg), /dimensions/);
});
