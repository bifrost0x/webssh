/* Show messages flashed by the server during the previous request. */
(function () {
    'use strict';
    const source = document.getElementById('websshFlashedMessages');
    if (!source) return;
    const {keys = {}, messages = []} = JSON.parse(source.textContent);
    messages.forEach(([category, message]) => {
        if (!window.showNotification) {
            return;
        }
        const type = category === 'error' ? 'error' : (category === 'success' ? 'success' : 'info');
        const key = Object.hasOwn(keys, message) ? keys[message] : null;
        window.showNotification(key ? window.i18n.t(key) : message, type);
    });
})();
