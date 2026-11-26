/* Event emitter with the listener semantics of the Socket.IO client:
 * on, once, off (one handler, one event or all), listeners and hasListeners.
 */
(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeEmitter = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    // Reports a listener error to the page's error handling without
    // interrupting the dispatch loop.
    function report(error) {
        if (typeof root.reportError === 'function') root.reportError(error);
        else setTimeout(() => { throw error; }, 0);
    }

    class Emitter {
        constructor() { this._handlers = new Map(); }

        on(event, handler) {
            if (typeof handler !== 'function') return this;
            if (!this._handlers.has(event)) this._handlers.set(event, []);
            this._handlers.get(event).push(handler);
            return this;
        }

        once(event, handler) {
            const wrapper = (...args) => {
                this.off(event, wrapper);
                handler.apply(this, args);
            };
            wrapper.fn = handler;
            return this.on(event, wrapper);
        }

        off(event, handler) {
            if (event === undefined) this._handlers.clear();
            else if (handler === undefined) this._handlers.delete(event);
            else {
                const list = (this._handlers.get(event) || []).filter(entry => entry !== handler && entry.fn !== handler);
                if (list.length) this._handlers.set(event, list);
                else this._handlers.delete(event);
            }
            return this;
        }

        listeners(event) { return [...(this._handlers.get(event) || [])]; }

        hasListeners(event) { return this.listeners(event).length > 0; }

        // A throwing listener must not starve the others.
        _dispatch(event, ...args) {
            for (const handler of this.listeners(event)) {
                try {
                    handler.apply(this, args);
                } catch (error) {
                    report(error);
                }
            }
        }
    }

    return Object.freeze({Emitter});
});
