// Reads the inventory of the local test lab (tests/lab/README.md). The M1
// journeys connect to its OpenSSH containers; without a running lab they
// fail with a pointer instead of passing without a connection.
const fs = require('node:fs');
const path = require('node:path');

const defaultInventory = path.resolve(__dirname, '../../lab/runtime/lab.json');

function loadLab() {
    const file = process.env.WEBSSH_LAB_INVENTORY || defaultInventory;
    if (!fs.existsSync(file)) {
        throw new Error(`Test lab inventory not found at ${file}. Start the lab with tests/lab/up.sh `
            + 'or point WEBSSH_LAB_INVENTORY at its runtime/lab.json.');
    }
    const inventory = JSON.parse(fs.readFileSync(file, 'utf8'));
    const runtime = inventory.runtime_dir || path.dirname(file);
    const secret = relative => fs.readFileSync(path.join(runtime, relative), 'utf8').split('\n', 1)[0];
    const service = name => {
        const entry = inventory.services?.[name];
        if (!entry) throw new Error(`lab service ${name} is missing from ${file}`);
        return entry;
    };
    return {
        service,
        // A secret file of the runtime directory, first line.
        secret,
        // The CA bundle of the lab's TLS services.
        caFile: path.join(runtime, inventory.ca_file || 'ca/ca.crt'),
        password(serviceName, user) {
            return secret(service(serviceName).users[user].password_file);
        },
        clientKey(name) {
            return fs.readFileSync(path.join(runtime, 'ssh', 'client', name), 'utf8');
        },
        fingerprints(serviceName) {
            return Object.values(service(serviceName).host_key_fingerprints || {});
        },
    };
}

module.exports = {loadLab};
