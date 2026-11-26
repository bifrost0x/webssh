// RFC 6238 codes (SHA-1, 6 digits, 30 s) for the authenticator a spec enrols.
const crypto = require('node:crypto');

function decodeBase32(value) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const character of value.replace(/=+$/, '').toUpperCase()) {
        const index = alphabet.indexOf(character);
        if (index < 0) throw new Error('Invalid base32 secret');
        bits += index.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
        bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
    }
    return Buffer.from(bytes);
}

function totp(secret, timestamp = Date.now()) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 30_000)));
    const digest = crypto.createHmac('sha1', decodeBase32(secret)).update(counter).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8) | digest[offset + 3];
    return String(binary % 1_000_000).padStart(6, '0');
}

// A code for a step that was not used yet: servers reject a replayed code.
async function freshTotp(secret, usedSteps) {
    for (;;) {
        const step = Math.floor(Date.now() / 30_000);
        if (!usedSteps.has(step)) {
            usedSteps.add(step);
            return totp(secret);
        }
        await new Promise(resolve => setTimeout(resolve, 30_000 - (Date.now() % 30_000) + 200));
    }
}

module.exports = {totp, freshTotp};
