'use strict';

// SFTP through the app, as static/js/binary-transfer-client.js does it:
// prepare_transfer over Socket.IO, then one HTTP request with the CSRF
// header (POST body for upload, GET response for download).

const crypto = require('node:crypto');
const fs = require('node:fs');
const { summarize } = require('./stats');

let counter = 0;

function prepare(socket, direction, sessionId, remotePath, options = {}) {
    counter += 1;
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('prepare_transfer_timeout')), 15000);
        socket.emit('prepare_transfer', {
            direction,
            source_id: `sftp-session:${sessionId}`,
            remote_path: remotePath,
            request_id: `transfer_${Date.now()}_${counter}`,
            ...options,
        }, (acknowledgement) => {
            clearTimeout(timer);
            if (acknowledgement?.success) resolve(acknowledgement);
            else reject(new Error(`prepare_failed:${JSON.stringify(acknowledgement)}`));
        });
    });
}

async function upload(session, socket, sessionId, localFile, remotePath) {
    const started = process.hrtime.bigint();
    const prepared = await prepare(socket, 'upload', sessionId, remotePath, { conflict_policy: 'replace' });
    const body = await fs.openAsBlob(localFile);
    let response;
    try {
        response = await session.request(prepared.url, {
            method: 'POST',
            body,
            headers: { 'X-CSRFToken': session.csrfToken, Origin: session.baseUrl },
        });
    } catch (error) {
        return { ok: false, status: null, error: `${error.name}:${error.cause?.code || error.message}` };
    }
    const text = await response.text();
    const seconds = Number(process.hrtime.bigint() - started) / 1e9;
    return { ok: response.ok, status: response.status, seconds, body: response.ok ? undefined : text.slice(0, 500) };
}

async function download(session, socket, sessionId, remotePath) {
    const started = process.hrtime.bigint();
    const prepared = await prepare(socket, 'download', sessionId, remotePath);
    const response = await session.request(prepared.url, { headers: { Origin: session.baseUrl } });
    if (!response.ok) {
        return { ok: false, status: response.status, body: (await response.text()).slice(0, 500) };
    }
    const hash = crypto.createHash('sha256');
    let bytes = 0;
    for await (const chunk of response.body) {
        hash.update(chunk);
        bytes += chunk.length;
    }
    const seconds = Number(process.hrtime.bigint() - started) / 1e9;
    return { ok: true, status: response.status, seconds, bytes, sha256: hash.digest('hex') };
}

function throughput(results, bytes) {
    const ok = results.filter((item) => item.ok);
    return {
        file_bytes: bytes,
        successful_runs: ok.length,
        seconds: summarize(ok.map((item) => item.seconds)),
        mib_per_s: summarize(ok.map((item) => bytes / 1048576 / item.seconds)),
        runs: results,
    };
}

module.exports = { upload, download, throughput };
