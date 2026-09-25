const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {addEventListener() {}, visualViewport: null};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

test('transcript export preserves text before CRLF line endings', () => {
    TerminalManager.transcripts = {
        session: ['user@host:~$ echo hello\r', '\n\x1b[32mhello\x1b[0m\r', '\nuser@host:~$ '],
    };

    assert.equal(
        TerminalManager.getCleanTranscript('session'),
        'user@host:~$ echo hello\nhello\nuser@host:~$ ',
    );
});

test('transcript export still handles a lone carriage return as an overwrite', () => {
    TerminalManager.transcripts = {session: ['Downloading 10%\rDownloading 90%\n']};

    assert.equal(TerminalManager.getCleanTranscript('session'), 'Downloading 90%\n');
});
