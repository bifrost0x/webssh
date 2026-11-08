/* Server-provided transfer and terminal input limits, read from a JSON block
 * so the page needs no inline script. */
(function () {
    'use strict';
    const source = document.getElementById('websshRuntimeLimits');
    const limits = source ? JSON.parse(source.textContent) : {};
    window.WEBSSH_TRANSFER_LIMITS = Object.freeze(limits.transfer);
    window.WEBSSH_SSH_INPUT_LIMITS = Object.freeze(limits.sshInput);
})();
