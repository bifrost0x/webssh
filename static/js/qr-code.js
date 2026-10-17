/* Dependency-free QR Code Model 2 encoder (byte mode) for share links. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHQRCode = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    // Error correction levels: format bits and table row.
    const LEVELS = {
        L: { bits: 1, row: 0 },
        M: { bits: 0, row: 1 },
        Q: { bits: 3, row: 2 },
        H: { bits: 2, row: 3 },
    };

    // ISO/IEC 18004 table 9, indexed by [level row][version]; index 0 unused.
    const ECC_CODEWORDS_PER_BLOCK = [
        [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
        [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
        [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
        [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    ];
    const NUM_ERROR_CORRECTION_BLOCKS = [
        [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
        [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
        [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
        [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
    ];

    const PENALTY_N1 = 3;
    const PENALTY_N2 = 3;
    const PENALTY_N3 = 40;
    const PENALTY_N4 = 10;

    function bit(value, index) {
        return ((value >>> index) & 1) !== 0;
    }

    function rawDataModules(version) {
        let result = (16 * version + 128) * version + 64;
        if (version >= 2) {
            const alignments = Math.floor(version / 7) + 2;
            result -= (25 * alignments - 10) * alignments - 55;
            if (version >= 7) result -= 36;
        }
        return result;
    }

    function dataCodewords(version, level) {
        const row = LEVELS[level].row;
        return Math.floor(rawDataModules(version) / 8)
            - ECC_CODEWORDS_PER_BLOCK[row][version] * NUM_ERROR_CORRECTION_BLOCKS[row][version];
    }

    function alignmentPositions(version, size) {
        if (version === 1) return [];
        const count = Math.floor(version / 7) + 2;
        const step = Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
        const positions = [6];
        for (let position = size - 7; positions.length < count; position -= step) {
            positions.splice(1, 0, position);
        }
        return positions;
    }

    // Reed-Solomon over GF(2^8) with the QR primitive polynomial 0x11D.
    function gfMultiply(x, y) {
        let z = 0;
        for (let i = 7; i >= 0; i -= 1) {
            z = (z << 1) ^ ((z >>> 7) * 0x11d);
            z ^= ((y >>> i) & 1) * x;
        }
        return z & 0xff;
    }

    function rsDivisor(degree) {
        const result = new Array(degree).fill(0);
        result[degree - 1] = 1;
        let rootValue = 1;
        for (let i = 0; i < degree; i += 1) {
            for (let j = 0; j < result.length; j += 1) {
                result[j] = gfMultiply(result[j], rootValue);
                if (j + 1 < result.length) result[j] ^= result[j + 1];
            }
            rootValue = gfMultiply(rootValue, 0x02);
        }
        return result;
    }

    function rsRemainder(data, divisor) {
        const result = divisor.map(() => 0);
        for (const value of data) {
            const factor = value ^ result.shift();
            result.push(0);
            divisor.forEach((coefficient, index) => {
                result[index] ^= gfMultiply(coefficient, factor);
            });
        }
        return result;
    }

    function utf8Bytes(text) {
        if (typeof TextEncoder === 'function') {
            return Array.from(new TextEncoder().encode(text));
        }
        return Array.from(unescape(encodeURIComponent(text)), char => char.charCodeAt(0));
    }

    function encodeData(bytes, version, level) {
        const bits = [];
        const append = (value, length) => {
            for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
        };
        append(0x4, 4);
        append(bytes.length, version <= 9 ? 8 : 16);
        bytes.forEach(value => append(value, 8));
        const capacity = dataCodewords(version, level) * 8;
        append(0, Math.min(4, capacity - bits.length));
        append(0, (8 - (bits.length % 8)) % 8);
        const codewords = [];
        for (let i = 0; i < bits.length; i += 8) {
            codewords.push(bits.slice(i, i + 8).reduce((value, item) => (value << 1) | item, 0));
        }
        for (let pad = 0xec; codewords.length < capacity / 8; pad ^= 0xec ^ 0x11) {
            codewords.push(pad);
        }
        return codewords;
    }

    function interleaveWithEcc(data, version, level) {
        const row = LEVELS[level].row;
        const blockCount = NUM_ERROR_CORRECTION_BLOCKS[row][version];
        const eccLength = ECC_CODEWORDS_PER_BLOCK[row][version];
        const rawCodewords = Math.floor(rawDataModules(version) / 8);
        const shortBlocks = blockCount - (rawCodewords % blockCount);
        const shortLength = Math.floor(rawCodewords / blockCount);
        const divisor = rsDivisor(eccLength);
        const blocks = [];
        for (let i = 0, offset = 0; i < blockCount; i += 1) {
            const block = data.slice(offset, offset + shortLength - eccLength + (i < shortBlocks ? 0 : 1));
            offset += block.length;
            const ecc = rsRemainder(block, divisor);
            if (i < shortBlocks) block.push(0);
            blocks.push(block.concat(ecc));
        }
        const result = [];
        for (let i = 0; i < blocks[0].length; i += 1) {
            blocks.forEach((block, index) => {
                if (i !== shortLength - eccLength || index >= shortBlocks) result.push(block[i]);
            });
        }
        return result;
    }

    class Matrix {
        constructor(version) {
            this.version = version;
            this.size = version * 4 + 17;
            this.modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
            this.reserved = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
        }

        set(x, y, dark) {
            this.modules[y][x] = dark;
            this.reserved[y][x] = true;
        }

        drawFunctionPatterns() {
            const size = this.size;
            for (let i = 0; i < size; i += 1) {
                this.set(6, i, i % 2 === 0);
                this.set(i, 6, i % 2 === 0);
            }
            this.drawFinder(3, 3);
            this.drawFinder(size - 4, 3);
            this.drawFinder(3, size - 4);
            const positions = alignmentPositions(this.version, size);
            const last = positions.length - 1;
            positions.forEach((y, i) => {
                positions.forEach((x, j) => {
                    const corner = (i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0);
                    if (!corner) this.drawAlignment(x, y);
                });
            });
            this.drawFormat('M', 0);
            this.drawVersion();
        }

        drawFinder(cx, cy) {
            for (let dy = -4; dy <= 4; dy += 1) {
                for (let dx = -4; dx <= 4; dx += 1) {
                    const distance = Math.max(Math.abs(dx), Math.abs(dy));
                    const x = cx + dx;
                    const y = cy + dy;
                    if (x >= 0 && x < this.size && y >= 0 && y < this.size) {
                        this.set(x, y, distance !== 2 && distance !== 4);
                    }
                }
            }
        }

        drawAlignment(cx, cy) {
            for (let dy = -2; dy <= 2; dy += 1) {
                for (let dx = -2; dx <= 2; dx += 1) {
                    this.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
                }
            }
        }

        drawFormat(level, mask) {
            const data = (LEVELS[level].bits << 3) | mask;
            let remainder = data;
            for (let i = 0; i < 10; i += 1) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
            const bits = ((data << 10) | remainder) ^ 0x5412;
            const size = this.size;
            for (let i = 0; i <= 5; i += 1) this.set(8, i, bit(bits, i));
            this.set(8, 7, bit(bits, 6));
            this.set(8, 8, bit(bits, 7));
            this.set(7, 8, bit(bits, 8));
            for (let i = 9; i < 15; i += 1) this.set(14 - i, 8, bit(bits, i));
            for (let i = 0; i < 8; i += 1) this.set(size - 1 - i, 8, bit(bits, i));
            for (let i = 8; i < 15; i += 1) this.set(8, size - 15 + i, bit(bits, i));
            this.set(8, size - 8, true);
        }

        drawVersion() {
            if (this.version < 7) return;
            let remainder = this.version;
            for (let i = 0; i < 12; i += 1) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
            const bits = (this.version << 12) | remainder;
            for (let i = 0; i < 18; i += 1) {
                const dark = bit(bits, i);
                const a = this.size - 11 + (i % 3);
                const b = Math.floor(i / 3);
                this.set(a, b, dark);
                this.set(b, a, dark);
            }
        }

        drawCodewords(codewords) {
            const size = this.size;
            let index = 0;
            for (let right = size - 1; right >= 1; right -= 2) {
                if (right === 6) right = 5;
                for (let vertical = 0; vertical < size; vertical += 1) {
                    for (let j = 0; j < 2; j += 1) {
                        const x = right - j;
                        const upward = ((right + 1) & 2) === 0;
                        const y = upward ? size - 1 - vertical : vertical;
                        if (!this.reserved[y][x] && index < codewords.length * 8) {
                            this.modules[y][x] = bit(codewords[index >>> 3], 7 - (index & 7));
                            index += 1;
                        }
                    }
                }
            }
        }

        applyMask(mask) {
            for (let y = 0; y < this.size; y += 1) {
                for (let x = 0; x < this.size; x += 1) {
                    if (this.reserved[y][x]) continue;
                    let invert;
                    switch (mask) {
                    case 0: invert = (x + y) % 2 === 0; break;
                    case 1: invert = y % 2 === 0; break;
                    case 2: invert = x % 3 === 0; break;
                    case 3: invert = (x + y) % 3 === 0; break;
                    case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
                    case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
                    case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
                    default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
                    }
                    if (invert) this.modules[y][x] = !this.modules[y][x];
                }
            }
        }

        penalty() {
            const size = this.size;
            let result = 0;
            const addHistory = (length, history) => {
                if (history[0] === 0) length += size;
                history.pop();
                history.unshift(length);
            };
            const countPatterns = history => {
                const n = history[1];
                const core = n > 0 && history[2] === n && history[3] === n * 3
                    && history[4] === n && history[5] === n;
                return (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0)
                    + (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0);
            };
            const terminate = (color, length, history) => {
                if (color) {
                    addHistory(length, history);
                    length = 0;
                }
                addHistory(length + size, history);
                return countPatterns(history);
            };
            const scan = read => {
                for (let a = 0; a < size; a += 1) {
                    let color = false;
                    let run = 0;
                    const history = [0, 0, 0, 0, 0, 0, 0];
                    for (let b = 0; b < size; b += 1) {
                        if (read(a, b) === color) {
                            run += 1;
                            if (run === 5) result += PENALTY_N1;
                            else if (run > 5) result += 1;
                        } else {
                            addHistory(run, history);
                            if (!color) result += countPatterns(history) * PENALTY_N3;
                            color = read(a, b);
                            run = 1;
                        }
                    }
                    result += terminate(color, run, history) * PENALTY_N3;
                }
            };
            scan((y, x) => this.modules[y][x]);
            scan((x, y) => this.modules[y][x]);
            let dark = 0;
            for (let y = 0; y < size; y += 1) {
                for (let x = 0; x < size; x += 1) {
                    const color = this.modules[y][x];
                    if (color) dark += 1;
                    if (
                        x < size - 1 && y < size - 1
                        && color === this.modules[y][x + 1]
                        && color === this.modules[y + 1][x]
                        && color === this.modules[y + 1][x + 1]
                    ) {
                        result += PENALTY_N2;
                    }
                }
            }
            const total = size * size;
            result += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * PENALTY_N4;
            return result;
        }
    }

    /**
     * Encode ``text`` and return ``{ version, size, mask, isDark(x, y) }``.
     * Throws a RangeError when the text does not fit version 40.
     */
    function encode(text, options = {}) {
        const level = LEVELS[options.level] ? options.level : 'M';
        const bytes = utf8Bytes(String(text));
        let version = 1;
        for (; version <= 40; version += 1) {
            const header = 4 + (version <= 9 ? 8 : 16);
            if (header + bytes.length * 8 <= dataCodewords(version, level) * 8) break;
        }
        if (version > 40) throw new RangeError('Data too long for a QR code');

        const matrix = new Matrix(version);
        matrix.drawFunctionPatterns();
        matrix.drawCodewords(interleaveWithEcc(encodeData(bytes, version, level), version, level));

        let bestMask = 0;
        let bestPenalty = Infinity;
        for (let mask = 0; mask < 8; mask += 1) {
            matrix.applyMask(mask);
            matrix.drawFormat(level, mask);
            const penalty = matrix.penalty();
            if (penalty < bestPenalty) {
                bestPenalty = penalty;
                bestMask = mask;
            }
            matrix.applyMask(mask);
        }
        matrix.applyMask(bestMask);
        matrix.drawFormat(level, bestMask);

        const modules = matrix.modules;
        return {
            version,
            size: matrix.size,
            mask: bestMask,
            level,
            isDark: (x, y) => modules[y][x],
        };
    }

    /** Return an SVG path covering every dark module, offset by ``border``. */
    function toPath(code, border = 4) {
        const parts = [];
        for (let y = 0; y < code.size; y += 1) {
            for (let x = 0; x < code.size; x += 1) {
                if (code.isDark(x, y)) parts.push(`M${x + border},${y + border}h1v1h-1z`);
            }
        }
        return parts.join('');
    }

    /** Build an accessible SVG element for ``text`` in ``doc``. */
    function toSvgElement(doc, text, options = {}) {
        const code = encode(text, options);
        const border = options.border ?? 4;
        const dimension = code.size + border * 2;
        const ns = 'http://www.w3.org/2000/svg';
        const svg = doc.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', `0 0 ${dimension} ${dimension}`);
        svg.setAttribute('shape-rendering', 'crispEdges');
        svg.setAttribute('role', 'img');
        if (options.label) svg.setAttribute('aria-label', options.label);
        const background = doc.createElementNS(ns, 'rect');
        background.setAttribute('width', String(dimension));
        background.setAttribute('height', String(dimension));
        background.setAttribute('fill', '#ffffff');
        const path = doc.createElementNS(ns, 'path');
        path.setAttribute('d', toPath(code, border));
        path.setAttribute('fill', '#0b1220');
        svg.append(background, path);
        return svg;
    }

    return { encode, toPath, toSvgElement };
});
