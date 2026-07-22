(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.CommandSetUtils = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    function filterCommands(commands, query, osFilter) {
        const normalizedQuery = String(query || '').trim().toLocaleLowerCase();
        const normalizedOs = String(osFilter || 'all').toLocaleLowerCase();

        return (Array.isArray(commands) ? commands : []).filter(command => {
            if (!command || typeof command !== 'object') {
                return false;
            }
            const supportedOs = Array.isArray(command.os)
                ? command.os.map(value => String(value).toLocaleLowerCase())
                : ['all'];
            if (normalizedOs !== 'all'
                    && !supportedOs.includes('all')
                    && !supportedOs.includes(normalizedOs)) {
                return false;
            }
            if (!normalizedQuery) {
                return true;
            }
            return [
                command.name,
                command.command,
                command.parameters,
                command.description,
                command.category,
            ].some(value => String(value || '').toLocaleLowerCase().includes(normalizedQuery));
        });
    }

    function moveStep(steps, fromIndex, toIndex) {
        const result = Array.isArray(steps) ? steps.slice() : [];
        if (!Number.isInteger(fromIndex) || fromIndex < 0 || fromIndex >= result.length) {
            return result;
        }
        const destination = Math.max(0, Math.min(Number(toIndex) || 0, result.length - 1));
        const [step] = result.splice(fromIndex, 1);
        result.splice(destination, 0, step);
        return result;
    }

    return { filterCommands, moveStep };
}));
