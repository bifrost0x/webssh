const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/admin.js'), 'utf8');

function slice(startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    assert.ok(start > 0 && end > start, startMarker);
    return source.slice(start, end);
}

function renderUsernameCells(users) {
    const rows = [];
    const body = {
        innerHTML: '',
        appendChild(row) { rows.push(row); },
    };
    const context = {
        CURRENT_USER: 'adminuser',
        RECOVERY_ENABLED: false,
        OIDC_ENABLED: false,
        LDAP_ENABLED: false,
        t: (_key, fallback) => fallback,
        labelResponsiveTableRows() {},
        fmtDate: value => value || '',
        document: {
            getElementById: id => (id === 'adminUsersBody' ? body : null),
            createElement: () => ({ dataset: {}, innerHTML: '' }),
        },
    };
    vm.runInNewContext(
        `${slice('    function escapeHtml(', '    function labelResponsiveTableRows(')}
${slice('    function userActionsHtml(', '    function filterUsers(')}
${slice('    function renderUsers(', '    async function loadUsers(')}
function filterUsers() {}
renderUsers(users);`,
        { ...context, users },
    );
    return rows.map(row => row.innerHTML.split('</td>')[1]);
}

test('administrators set by ADMIN_USERS are marked in the user list', () => {
    const [listed, regular] = renderUsernameCells([
        { id: 1, username: 'adminuser', is_admin: true, admin_managed_by_config: true },
        { id: 2, username: 'other', is_admin: true, admin_managed_by_config: false },
    ]);
    assert.match(listed, /adminuser <span class="admin-muted">\(set by ADMIN_USERS\)<\/span>/);
    assert.doesNotMatch(regular, /ADMIN_USERS/);
});
