// TR1 acceptance: transfers of the Go server against the test lab's
// Samba, through the transfer client of the page: an upload streamed
// over HTTP, its conflict and replacement, the download of the file and
// of a folder as ZIP, a host-to-host copy and a cancelled copy.
//
// Like smb.spec.js it needs the end-to-end build, which points SMB
// connections at the lab's published port:
//   WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh-e2e serve' \
//   WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh-e2e' \
//   npx playwright test -c tests/e2e/m2/playwright.config.js transfer.spec.js
const crypto = require('node:crypto');
const fs = require('node:fs');
const {test, expect} = require('playwright/test');
const {kind, freshBackend, attachLogOnFailure} = require('../m1/backend');
const {loadLab} = require('../m1/lab');
const ui = require('../m1/ui');

const admin = {username: 'm2transfer', password: 'M2-transfer-admin-password-3'};

let backend;
let lab;
let samba;

test.skip(kind !== 'go', 'the lab Samba is reachable only through the SMB port of the Go end-to-end build');

test.beforeAll(async () => {
    lab = loadLab();
    samba = lab.service('samba');
    backend = freshBackend('transfer');
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start({
        SMB_ENABLED: 'true', SMB_ALLOWED_TARGETS: samba.host, WEBSSH_E2E_SMB_PORT: String(samba.port),
        SMB_CONNECT_RATELIMIT: '100 per minute',
    });
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

const smbUser = () => samba.users.find(user => user.username === 'smbuser');

async function openShare(page) {
    await page.evaluate(() => openFileManager());
    await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
    await page.locator('#fmNewSmbSource').click();
    await page.locator('#smbSourceHost').fill(samba.host);
    await page.locator('#smbSourceShare').fill('Secure');
    await page.locator('#smbSourceDomain').fill(smbUser().domain);
    await page.locator('#smbSourceUsername').fill(smbUser().username);
    await page.locator('#smbSourcePassword').fill(lab.secret(smbUser().password_file));
    await page.locator('#smbSourceConnect').click();
    await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
    return page.evaluate(() => window.sftpFileManager.panes.left.source.sourceId);
}

// Emits a file request and waits for its push event.
function fileRequest(page, event, payload, answer) {
    return page.evaluate(({event, payload, answer}) => new Promise((resolve, reject) => {
        const socket = window.sftpFileManager.socket;
        const done = data => {
            if (data.request_id !== payload.request_id) return;
            socket.off(answer, done);
            socket.off('error', failed);
            resolve(data);
        };
        const failed = data => {
            if (data.request_id !== payload.request_id) return;
            socket.off(answer, done);
            socket.off('error', failed);
            reject(new Error(`${event}: ${data.code} ${data.error}`));
        };
        socket.on(answer, done);
        socket.on('error', failed);
        socket.emit(event, payload);
    }), {event, payload, answer});
}

async function names(page, sourceId, path) {
    const listing = await fileRequest(page, 'list_directory',
        {source_id: sourceId, request_id: `list-${crypto.randomBytes(4).toString('hex')}`, remote_path: path}, 'directory_listing');
    return listing.files.map(file => `${file.name}:${file.is_dir ? 'dir' : file.size}`).sort();
}

// Uploads bytes through the page's transfer client and resolves with the
// outcome and how often it asked about a conflict.
function upload(page, sourceId, path, base64, decision) {
    return page.evaluate(({sourceId, path, base64, decision}) => new Promise(resolve => {
        const client = window.sftpFileManager.getTransferClient();
        const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        let asked = 0;
        const id = client.uploadFile(new File([bytes], path.split('/').pop()), path, sourceId, {
            onConflict: async () => { asked += 1; return decision; },
        });
        const finish = outcome => data => { if (data.transferId === id) resolve({outcome, asked, code: data.errorCode ?? null}); };
        client.on('complete', finish('complete'));
        client.on('error', finish('error'));
        client.on('skip', finish('skip'));
        client.on('cancel', finish('cancel'));
    }), {sourceId, path, base64, decision});
}

test('files go up, come back, travel between hosts and stop when cancelled', async ({browser}) => {
    const context = await browser.newContext({baseURL: backend.baseURL, acceptDownloads: true});
    const page = await context.newPage();
    await ui.signIn(page, admin.username, admin.password);
    const sourceId = await openShare(page);
    const folder = `/e2e-tr1-${crypto.randomBytes(4).toString('hex')}`;
    const data = crypto.randomBytes(3 * 1024 * 1024 + 17);
    const sha = buffer => crypto.createHash('sha256').update(buffer).digest('hex');

    await fileRequest(page, 'create_directory', {source_id: sourceId, request_id: 'mk-1', remote_path: folder}, 'directory_created');
    try {
        await test.step('an upload streams the file and a second one asks before it replaces', async () => {
            expect(await upload(page, sourceId, `${folder}/data.bin`, data.toString('base64'), 'replace')).toEqual({outcome: 'complete', asked: 0, code: null});
            expect(await names(page, sourceId, folder)).toEqual([`data.bin:${data.length}`]);
            expect(await upload(page, sourceId, `${folder}/data.bin`, Buffer.from('short').toString('base64'), 'skip')).toEqual({outcome: 'skip', asked: 1, code: null});
            expect(await names(page, sourceId, folder)).toEqual([`data.bin:${data.length}`]);
            expect(await upload(page, sourceId, `${folder}/small.txt`, Buffer.from('small').toString('base64'), 'replace')).toMatchObject({outcome: 'complete'});
        });

        await test.step('the file downloads with its bytes and the folder as a ZIP', async () => {
            let pending = page.waitForEvent('download');
            await page.evaluate(({sourceId, path}) => window.sftpFileManager.getTransferClient().downloadFile(path, sourceId), {sourceId, path: `${folder}/data.bin`});
            let download = await pending;
            expect(download.suggestedFilename()).toBe('data.bin');
            expect(sha(fs.readFileSync(await download.path()))).toBe(sha(data));

            pending = page.waitForEvent('download');
            await page.evaluate(({sourceId, path}) => window.sftpFileManager.getTransferClient().downloadFolder(path, sourceId), {sourceId, path: folder});
            download = await pending;
            expect(download.suggestedFilename()).toBe(`${folder.slice(1)}.zip`);
            const zip = fs.readFileSync(await download.path());
            expect(zip.subarray(0, 2).toString()).toBe('PK');
            expect(zip.includes(Buffer.from(`${folder.slice(1)}/small.txt`))).toBe(true);
        });

        await test.step('a host-to-host copy reports its progress and completion', async () => {
            const result = await page.evaluate(({sourceId, folder}) => new Promise(resolve => {
                const socket = window.sftpFileManager.socket;
                const seen = [];
                socket.on('s2s_transfer_progress', data => seen.push(data.status));
                socket.on('s2s_transfer_complete', data => { if (data.request_id === 'copy-1') resolve({ok: true, seen, data}); });
                socket.on('s2s_transfer_error', data => { if (data.request_id === 'copy-1') resolve({ok: false, data}); });
                socket.emit('transfer_server_to_server', {source_id: sourceId, request_id: 'copy-1', source_path: `${folder}/data.bin`,
                    destination_source_id: sourceId, dest_path: `${folder}/copy.bin`, is_dir: false, conflict_policy: 'error'}, ack => {
                    if (!ack.success) resolve({ok: false, data: ack});
                });
            }), {sourceId, folder});
            expect(result.ok, JSON.stringify(result.data)).toBe(true);
            expect(result.data).toMatchObject({filename: 'data.bin', source_path: `${folder}/data.bin`, dest_path: `${folder}/copy.bin`,
                source_id: sourceId, destination_source_id: sourceId});
            expect(result.seen).toContain('transferring');
            expect(await names(page, sourceId, folder)).toEqual([`copy.bin:${data.length}`, `data.bin:${data.length}`, 'small.txt:5']);
        });

        await test.step('copying onto an existing name is a conflict and changes nothing', async () => {
            const result = await page.evaluate(({sourceId, folder}) => new Promise(resolve => {
                const socket = window.sftpFileManager.socket;
                socket.on('s2s_transfer_error', data => { if (data.request_id === 'copy-2') resolve(data); });
                socket.emit('transfer_server_to_server', {source_id: sourceId, request_id: 'copy-2', source_path: `${folder}/small.txt`,
                    destination_source_id: sourceId, dest_path: `${folder}/data.bin`, conflict_policy: 'error'}, () => {});
            }), {sourceId, folder});
            expect(result).toMatchObject({error_code: 'CONFLICT', retryable: false});
            expect(await names(page, sourceId, folder)).toContain(`data.bin:${data.length}`);
        });

        await test.step('a cancelled prepared transfer answers cancelled and its URL is gone', async () => {
            const result = await page.evaluate(({sourceId, folder}) => new Promise(resolve => {
                const socket = window.sftpFileManager.socket;
                socket.emit('prepare_transfer', {direction: 'download', source_id: sourceId, remote_path: `${folder}/data.bin`, request_id: 'prep-1'}, prepared => {
                    socket.emit('cancel_transfer', {transfer_id: prepared.transfer_id}, cancelled => {
                        fetch(prepared.url).then(response => resolve({prepared, cancelled, status: response.status}));
                    });
                });
            }), {sourceId, folder});
            expect(result.prepared.url).toMatch(/^\/api\/transfers\/[A-Za-z0-9_-]{43}\/download$/);
            expect(result.cancelled).toEqual({success: true, state: 'cancelled'});
            expect(result.status).toBe(404);
        });
    } finally {
        await fileRequest(page, 'delete_item', {source_id: sourceId, request_id: 'rm-1', path: folder}, 'item_deleted').catch(() => {});
    }
    await context.close();
});
