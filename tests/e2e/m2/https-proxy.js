// A TLS-terminating reverse proxy in front of a disposable backend, as a
// homelab installation runs WebSSH behind Caddy or nginx. It answers on
// https://localhost:<port> with a self-signed certificate made per run and
// forwards plain HTTP and WebSocket upgrades to the backend with
// X-Forwarded-For and X-Forwarded-Proto: https. The backend has to trust it
// (TRUSTED_PROXIES=1, TRUSTED_PROXY_CIDRS=127.0.0.1/32); the browser context
// needs ignoreHTTPSErrors.
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');

// A key and certificate for localhost in dir, valid for one day.
function selfSignedCertificate(dir) {
    const key = path.join(dir, 'proxy.key');
    const cert = path.join(dir, 'proxy.crt');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
        '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], {stdio: 'pipe'});
    fs.chmodSync(key, 0o600);
    return {key: fs.readFileSync(key), cert: fs.readFileSync(cert)};
}

function forwardedHeaders(req) {
    const headers = {...req.headers};
    // Only what this proxy saw counts; a client cannot pass its own values.
    delete headers['x-forwarded-for'];
    delete headers['x-forwarded-proto'];
    delete headers['x-forwarded-host'];
    delete headers['x-forwarded-prefix'];
    headers['x-forwarded-for'] = req.socket.remoteAddress.replace(/^::ffff:/, '');
    headers['x-forwarded-proto'] = 'https';
    return headers;
}

// Starts the proxy on a free port of 127.0.0.1 and returns
// {port, url, close()}. backendPort is read on every request, so the
// backend may be started after the proxy.
async function startHttpsProxy(dir, backendPort) {
    const sockets = new Set();
    const server = https.createServer(selfSignedCertificate(dir), (req, res) => {
        const upstream = http.request({
            host: '127.0.0.1', port: backendPort(), method: req.method, path: req.url, headers: forwardedHeaders(req),
        }, reply => {
            res.writeHead(reply.statusCode, reply.rawHeaders);
            reply.pipe(res);
        });
        upstream.on('error', () => {
            if (!res.headersSent) res.writeHead(502);
            res.end();
        });
        req.pipe(upstream);
    });
    server.on('upgrade', (req, client, head) => {
        const upstream = net.connect(backendPort(), '127.0.0.1', () => {
            const headers = forwardedHeaders(req);
            const lines = [`${req.method} ${req.url} HTTP/1.1`];
            for (const [name, value] of Object.entries(headers)) {
                for (const item of Array.isArray(value) ? value : [value]) lines.push(`${name}: ${item}`);
            }
            upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
            if (head.length) upstream.write(head);
            upstream.pipe(client);
            client.pipe(upstream);
        });
        const end = () => { upstream.destroy(); client.destroy(); };
        upstream.on('error', end);
        client.on('error', end);
        upstream.on('close', end);
        client.on('close', end);
    });
    server.on('connection', socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    const {port} = server.address();
    return {
        port,
        url: `https://localhost:${port}`,
        close: () => new Promise(resolve => {
            for (const socket of sockets) socket.destroy();
            server.close(() => resolve());
        }),
    };
}

module.exports = {startHttpsProxy};
