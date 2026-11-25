const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    base64urlToBytes,
    bytesToBase64url,
    createAccountStepUpClient,
    decodeAssertionOptions,
    serializeAssertion
} = require('../../static/js/security-ui.js');

// Expected values were captured from the per-page passkey encoders in
// admin.js, webauthn.js, server-operations.js, native-credentials.js and
// automation.js before they were merged; all five produced these outputs.

const ALL_BYTES_BASE64URL = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEy'
    + 'MzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3Bx'
    + 'cnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-w'
    + 'sbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v'
    + '8PHy8_T19vf4-fr7_P3-_w';

const DECODE_VECTORS = [
    ['', []],
    ['AA', [0]],
    ['AAE', [0, 1]],
    ['-_8', [251, 255]],
    ['-_8AAT4_PzA', [251, 255, 0, 1, 62, 63, 63, 48]],
    ['AQIDBA', [1, 2, 3, 4]]
];

const EXPECTED_ASSERTION = {
    id: '-_8AAT4_',
    rawId: '-_8AAT4_',
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: { credProps: { rk: true } },
    response: {
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYWJjIn0',
        authenticatorData: 'AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tng5-71_A',
        signature: '__79gH8APg',
        userHandle: 'AQIDBA'
    }
};

function buffer(values) {
    return new Uint8Array(values).buffer;
}

function allBytes() {
    return buffer(Array.from({ length: 256 }, (_, index) => index));
}

function fixedAssertion(userHandle) {
    return {
        id: '-_8AAT4_',
        type: 'public-key',
        authenticatorAttachment: 'platform',
        rawId: buffer([0xfb, 0xff, 0x00, 0x01, 0x3e, 0x3f]),
        getClientExtensionResults: () => ({ credProps: { rk: true } }),
        response: {
            clientDataJSON: new TextEncoder()
                .encode('{"type":"webauthn.get","challenge":"abc"}').buffer,
            authenticatorData: buffer(
                Array.from({ length: 37 }, (_, index) => (index * 7) & 0xff)
            ),
            signature: buffer([0xff, 0xfe, 0xfd, 0x80, 0x7f, 0x00, 0x3e]),
            userHandle
        }
    };
}

function fixedOptions() {
    return {
        challenge: '-_8AAT4_PzA',
        rpId: 'example.test',
        timeout: 60000,
        userVerification: 'preferred',
        allowCredentials: [
            { type: 'public-key', id: 'AQIDBA', transports: ['usb', 'internal'] },
            { type: 'public-key', id: '_-8' }
        ]
    };
}

function plain(value) {
    if (value instanceof Uint8Array) { return { bytes: Array.from(value) }; }
    if (Array.isArray(value)) { return value.map(plain); }
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [key, plain(item)])
        );
    }
    return value;
}

test('base64url encoding matches the previous encoders without padding', () => {
    assert.equal(bytesToBase64url(allBytes()), ALL_BYTES_BASE64URL);
    assert.equal(bytesToBase64url(buffer([])), '');
    assert.equal(bytesToBase64url(new Uint8Array([0xff, 0xfe, 0xfd, 0x80])), '__79gA');
});

test('base64url decoding matches the previous decoders for padded and unpadded input', () => {
    for (const [encoded, expected] of DECODE_VECTORS) {
        const decoded = base64urlToBytes(encoded);
        assert.ok(decoded instanceof Uint8Array, encoded);
        assert.deepEqual(Array.from(decoded), expected, encoded);
    }
    assert.equal(base64urlToBytes(ALL_BYTES_BASE64URL).length, 256);
    assert.deepEqual(Array.from(base64urlToBytes('AQIDBA==')), [1, 2, 3, 4]);
    assert.throws(() => base64urlToBytes('A'));
    assert.throws(() => base64urlToBytes('AQ*D'));
});

test('assertion options decode the challenge and allowed credential ids', () => {
    const input = fixedOptions();

    const decoded = decodeAssertionOptions(input);

    assert.deepEqual(plain(decoded), {
        challenge: { bytes: [251, 255, 0, 1, 62, 63, 63, 48] },
        rpId: 'example.test',
        timeout: 60000,
        userVerification: 'preferred',
        allowCredentials: [
            {
                type: 'public-key',
                id: { bytes: [1, 2, 3, 4] },
                transports: ['usb', 'internal']
            },
            { type: 'public-key', id: { bytes: [255, 239] } }
        ]
    });
    assert.deepEqual(input, fixedOptions(), 'server options stay untouched');
});

test('assertion options without allowed credentials request any discoverable passkey', () => {
    assert.deepEqual(
        plain(decodeAssertionOptions({ challenge: 'AA', rpId: 'example.test' })),
        { challenge: { bytes: [0] }, rpId: 'example.test', allowCredentials: [] }
    );
});

test('assertion serialization matches the previous request bodies', () => {
    assert.deepEqual(
        serializeAssertion(fixedAssertion(buffer([1, 2, 3, 4]))),
        EXPECTED_ASSERTION
    );
    assert.deepEqual(
        Object.keys(serializeAssertion(fixedAssertion(null)).response),
        ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']
    );
    assert.deepEqual(serializeAssertion(fixedAssertion(null)), {
        ...EXPECTED_ASSERTION,
        response: { ...EXPECTED_ASSERTION.response, userHandle: null }
    });
});

test('account step-up sends the serialized assertion by default', async () => {
    const calls = [];
    const client = createAccountStepUpClient({
        api: async (route, options) => {
            calls.push([route, options]);
            if (route.endsWith('/intents')) {
                return { intent: 'intent-1', preferred_method: 'passkey', methods: ['passkey'] };
            }
            if (route.endsWith('/passkey/options')) { return fixedOptions(); }
            return { grant: 'grant-1' };
        },
        getPasskeyAssertion: async options => {
            assert.deepEqual(options, fixedOptions());
            return fixedAssertion(buffer([1, 2, 3, 4]));
        }
    });

    assert.equal(await client.authorize('credentials.vault', 'token'), 'grant-1');
    assert.deepEqual(calls[2], ['/api/account/step-up/passkey/verify', {
        method: 'POST',
        body: { intent: 'intent-1', credential: EXPECTED_ASSERTION }
    }]);
});

test('passkey clients use the shared encoding instead of local copies', () => {
    const files = [
        'admin.js',
        'automation.js',
        'native-credentials.js',
        'server-operations.js',
        'webauthn.js'
    ];
    for (const file of files) {
        const source = fs.readFileSync(
            path.join(__dirname, '../../static/js', file),
            'utf8'
        );
        assert.doesNotMatch(source, /\batob\(|\bbtoa\(/, file);
    }
});
