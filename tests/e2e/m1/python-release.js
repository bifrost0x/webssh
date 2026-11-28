// The Python release for the specs that need it (python-data-dir.js, and
// all M1 specs with WEBSSH_E2E_M1_BACKEND=python). It is not part of this
// repository: WEBSSH_PYTHON_ROOT names a worktree of the last Python
// release (PYTHON_RELEASE in scripts/record-python-oracles.sh) with its
// virtual environment. PYTHON overrides the interpreter.
const fs = require('node:fs');
const path = require('node:path');

function pythonRelease() {
    const root = process.env.WEBSSH_PYTHON_ROOT;
    if (!root) {
        throw new Error('the Python release is needed: set WEBSSH_PYTHON_ROOT to a worktree of it '
            + '(scripts/record-python-oracles.sh)');
    }
    const absolute = path.resolve(root);
    if (!fs.existsSync(path.join(absolute, 'app', '__init__.py'))) {
        throw new Error(`no Python release in ${absolute} (WEBSSH_PYTHON_ROOT)`);
    }
    const python = process.env.PYTHON || path.join(absolute, '.venv', 'bin', 'python');
    const launcher = path.join('tests', 'e2e', 'm1', 'python_backend.py');
    return {
        root: absolute,
        python,
        commands: () => ({serverCommand: `"${python}" ${launcher} serve`, adminCommand: `"${python}" ${launcher} cli`}),
    };
}

module.exports = {pythonRelease};
