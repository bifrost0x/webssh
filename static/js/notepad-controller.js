(function(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.NotepadController = api;
}(typeof window !== 'undefined' ? window : null, function() {
    'use strict';

    function create(options) {
        const {socket, read, write, status} = options;
        const schedule = options.setTimeout || setTimeout;
        const cancel = options.clearTimeout || clearTimeout;
        let dirty = false;
        let edited = false;
        let revision = 0;
        let timer;
        let pending = null;
        let state = 'saved';

        function show(next) {
            state = next;
            status(state);
        }
        function save() {
            cancel(timer);
            if (!dirty || pending) return;
            if (!socket.connected) return show('offline');
            const text = read();
            // Match Python's Unicode character count, including astral characters.
            if (Array.from(text).length > 100000) return show('tooLarge');
            const attempt = {revision};
            pending = attempt;
            show('saving');
            attempt.timer = schedule(() => {
                if (pending !== attempt) return;
                pending = null;
                show('failed');
            }, 10000);
            socket.emit('save_notepad', {text}, result => {
                if (pending !== attempt) return;
                cancel(attempt.timer);
                pending = null;
                if (result?.success !== true) return show('failed');
                if (revision !== attempt.revision) return save();
                dirty = false;
                show('saved');
            });
        }
        socket.on('disconnect', () => {
            cancel(timer);
            if (pending) cancel(pending.timer);
            pending = null;
            if (dirty) show('offline');
        });
        return {
            changed() {
                dirty = true;
                edited = true;
                revision += 1;
                cancel(timer);
                show(socket.connected ? 'saving' : 'offline');
                timer = schedule(save, 300);
            },
            receive(text) {
                // A reconnect read must never replace this page's local edits,
                // even if an older read arrives after the save acknowledgement.
                if (!edited) write(text);
            },
            reconnect: save,
            hasUnsaved: () => dirty,
            render: () => status(state),
        };
    }
    return {create};
}));
