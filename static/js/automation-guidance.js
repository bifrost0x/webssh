(function(root) {
    'use strict';
    const api = {
        stepHints(step) {
            const command = String(step.command || '');
            const upgrade = /\bapt(?:-get)?\s+(?:[^;&|\n]*\s)?(?:upgrade|full-upgrade|dist-upgrade)\b/.test(command);
            const hints = [];
            if (upgrade && !/(?:^|\s)(?:-[a-z]*y[a-z]*|--yes|--assume-yes)(?:\s|$)/.test(command)) hints.push('guidance.confirmation');
            if (upgrade && Number(step.timeout) <= 30) hints.push('guidance.packageTimeout');
            if (step.sudo && /^\s*sudo\b/.test(command)) hints.push('guidance.doubleSudo');
            return hints;
        },
        resultHint(step) {
            if (step.status !== 'failed' || step.reason !== 'nonzero_exit') return null;
            const output = String(step.stdout || '') + '\n' + String(step.stderr || '');
            if (/(?:Fortfahren\?\s*\[J\/n\]|Do you want to continue\?\s*\[Y\/n\])\s*(?:Abbruch\.|Abort\.)/i.test(output)) return 'guidance.confirmationAborted';
            return null;
        },
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.AutomationGuidance = api;
})(typeof window === 'undefined' ? null : window);
