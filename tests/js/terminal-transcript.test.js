const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {addEventListener() {}, visualViewport: null};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

test('OSC stripping preserves text between separate BEL and ST strings', () => {
    assert.equal(TerminalManager.stripAnsiSequences('before\x1b]0;one\x1b\\middle\x1b]0;two\x07after'), 'beforemiddleafter');
});

test('unterminated OSC strings at the transcript limit are discarded', () => {
    assert.equal(TerminalManager.stripAnsiSequences('before' + '\x1b]'.repeat(100000)), 'before');
});

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

test('ANSI erase between CR and LF does not turn a cleared line into a saved line', () => {
    TerminalManager.transcripts = {session: ['text\r', '\x1b[2K\n']};

    assert.equal(TerminalManager.getCleanTranscript('session'), '\n');
});
