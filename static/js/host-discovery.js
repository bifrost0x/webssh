/* Manual SSH host discovery. The server does the paced probing; this module
 * collects the range, shows progress and hands a found endpoint to the
 * existing host editor. Pure helpers are exported for tests. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.HostDiscovery = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const POLL_MS = 1000;

    /** The /24 most saved IPv4 hosts share, as a starting point the user can change. */
    function suggestNetwork(profiles = []) {
        const counts = new Map();
        profiles.forEach(profile => {
            const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(profile?.host || '').trim());
            if (!match || match.slice(1).some(part => Number(part) > 255)) return;
            const network = `${match[1]}.${match[2]}.${match[3]}.0/24`;
            counts.set(network, (counts.get(network) || 0) + 1);
        });
        return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] || '';
    }

    function parsePorts(value) {
        const parts = String(value || '').split(/[\s,;]+/).filter(Boolean);
        if (!parts.length) return [22];
        const ports = parts.map(Number);
        if (ports.length > 3 || ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return null;
        return [...new Set(ports)];
    }

    /** Values for a new host: a short name from reverse DNS, else the address. */
    function prefill(entry) {
        const name = entry.name ? entry.name.split('.')[0] : '';
        return {name: name || entry.address, host: entry.address, port: entry.port};
    }

    function create({win, doc, t, request, openEditor}) {
        const $ = id => doc.getElementById(id);
        const dialog = $('hostDiscoveryDialog');
        if (!dialog) return null;
        let scan = null;
        let timer = 0;
        let returnFocus = null;
        let resultSignature = '';
        let announced = '';
        let pollFailures = 0;

        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined) element.textContent = text;
            return element;
        };
        const icon = name => {
            const element = node('span', 'material-icons', name);
            element.setAttribute('aria-hidden', 'true');
            return element;
        };
        const showError = message => {
            $('hostDiscoveryError').textContent = message || '';
            $('hostDiscoveryError').hidden = !message;
        };

        function render() {
            const running = scan?.state === 'running';
            $('hostDiscoveryStart').disabled = running;
            $('hostDiscoveryCancel').hidden = !running;
            $('hostDiscoveryNetwork').disabled = running;
            $('hostDiscoveryPorts').disabled = running;
            $('hostDiscoveryProgress').hidden = !scan;
            if (!scan) return;
            const percent = scan.total ? Math.round((scan.checked / scan.total) * 100) : 0;
            $('hostDiscoveryBar').setAttribute('aria-valuenow', String(percent));
            $('hostDiscoveryBar').firstElementChild.style.width = `${percent}%`;
            $('hostDiscoveryProgress').dataset.state = scan.state;
            $('hostDiscoveryState').textContent = {
                running: t('discovery.running', 'Scanning {network}…', {network: scan.network}),
                done: t('discovery.done', 'Finished {network}', {network: scan.network}),
                cancelled: t('discovery.cancelled', 'Stopped'),
            }[scan.state] || '';
            $('hostDiscoveryCount').textContent = t('discovery.count', '{checked} of {total} checked · {found} found',
                {checked: scan.checked, total: scan.total, found: scan.found.length})
                + (scan.blocked ? ` · ${t('discovery.blocked', '{count} not allowed', {count: scan.blocked})}` : '');
            $('hostDiscoveryEmpty').hidden = scan.state === 'running' || scan.found.length > 0;
            // Announce state changes and new results, not every progress tick.
            const message = `${$('hostDiscoveryState').textContent} ${t('discovery.foundCount', '{found} found', {found: scan.found.length})}`;
            if (message !== announced && (scan.state !== 'running' || scan.found.length || !announced)) {
                announced = message;
                $('hostDiscoveryAnnounce').textContent = message;
            }
            const signature = JSON.stringify(scan.found.map(entry => [entry.address, entry.port, entry.known, entry.name]));
            if (signature === resultSignature) return;
            resultSignature = signature;
            const list = $('hostDiscoveryResults');
            const focused = list.contains(doc.activeElement) ? doc.activeElement.dataset.result : null;
            list.replaceChildren(...scan.found.map(entry => {
                const item = node('li', 'discovery-result');
                const logo = node('span', 'discovery-logo');
                logo.append(win.HostPlatform?.render({detected_platform: entry.platform || undefined}, doc) || icon('dns'));
                const copy = node('div', 'discovery-copy');
                copy.append(node('strong', '', entry.name || entry.address),
                    node('span', 'discovery-address', `${entry.address}${entry.port === 22 ? '' : `:${entry.port}`}`),
                    node('span', 'discovery-software', [entry.software, entry.comment].filter(Boolean).join(' · ')));
                item.append(logo, copy);
                if (entry.known) {
                    const saved = node('span', 'discovery-saved');
                    saved.append(icon('check'), node('span', '', t('discovery.saved', 'Saved')));
                    item.append(saved);
                } else {
                    const add = node('button', 'btn btn-secondary discovery-add');
                    add.type = 'button';
                    add.setAttribute('aria-label', t('discovery.addLabel', 'Add {name} as a host', {name: entry.name || entry.address}));
                    add.dataset.result = `${entry.address}:${entry.port}`;
                    add.append(icon('add'), node('span', '', t('discovery.add', 'Add')));
                    add.addEventListener('click', () => {
                        dialog.close();
                        openEditor(prefill(entry));
                    });
                    item.append(add);
                }
                return item;
            }));
            if (focused) list.querySelector(`[data-result="${CSS.escape(focused)}"]`)?.focus({preventScroll: true});
        }

        async function poll() {
            win.clearTimeout(timer);
            if (!scan || scan.state !== 'running') return;
            try {
                scan = await request(`/api/discovery/scans/${encodeURIComponent(scan.id)}`);
                pollFailures = 0;
                render();
            } catch (error) {
                // The scan keeps running on the server; retry a few times before giving up.
                pollFailures += 1;
                if (pollFailures >= 3) {
                    showError(error.message);
                    return;
                }
                timer = win.setTimeout(poll, POLL_MS * 2);
                return;
            }
            if (scan.state === 'running') timer = win.setTimeout(poll, POLL_MS);
        }

        async function start(event) {
            event.preventDefault();
            showError('');
            const network = $('hostDiscoveryNetwork').value.trim();
            const ports = parsePorts($('hostDiscoveryPorts').value);
            if (!network) { showError(t('discovery.networkRequired', 'Enter the network to scan.')); $('hostDiscoveryNetwork').focus(); return; }
            if (!ports) { showError(t('discovery.portsInvalid', 'Enter up to three ports between 1 and 65535.')); $('hostDiscoveryPorts').focus(); return; }
            try {
                scan = await request('/api/discovery/scans', {method: 'POST', body: JSON.stringify({network, ports})});
                resultSignature = '';
                announced = '';
                pollFailures = 0;
                render();
                timer = win.setTimeout(poll, POLL_MS);
            } catch (error) {
                showError(error.message);
            }
        }

        async function cancel() {
            if (!scan) return;
            try {
                scan = await request(`/api/discovery/scans/${encodeURIComponent(scan.id)}`, {method: 'DELETE'});
            } catch (error) {
                showError(error.message);
            }
            render();
            $('hostDiscoveryStart').focus();
        }

        function open() {
            returnFocus = doc.activeElement;
            if (!$('hostDiscoveryNetwork').value) $('hostDiscoveryNetwork').value = suggestNetwork(win.ProfileManager?.profiles || []);
            showError('');
            render();
            dialog.showModal();
            (scan?.state === 'running' ? $('hostDiscoveryCancel') : $('hostDiscoveryNetwork')).focus();
            // A scan keeps running while the dialog is closed; reopening shows it.
            if (scan?.state === 'running') poll();
        }

        $('hostDiscoveryForm').addEventListener('submit', start);
        $('hostDiscoveryCancel').addEventListener('click', cancel);
        $('hostDiscoveryClose').addEventListener('click', () => dialog.close());
        dialog.addEventListener('close', () => {
            win.clearTimeout(timer);
            if (returnFocus?.isConnected && !doc.getElementById('profileEditorView')?.offsetParent) returnFocus.focus?.();
        });
        win.addEventListener('languageChanged', () => { if (dialog.open) render(); });
        return {open};
    }

    return {suggestNetwork, parsePorts, prefill, create};
}));
