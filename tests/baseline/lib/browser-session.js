'use strict';

// One browser-like account session: cookie jar, CSRF token from the rendered
// page and a Socket.IO client configured like static/js/app.js.

const { io } = require('socket.io-client');

const SOCKET_WIRE_REVISION = 2;
const CSRF_INPUT = /name="csrf_token"[^>]*value="([^"]+)"/;
const CSRF_META = /<meta name="csrf-token" content="([^"]+)"/;

class BrowserSession {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.cookies = new Map();
        this.csrfToken = null;
    }

    cookieHeader() {
        return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    }

    storeCookies(response) {
        for (const line of response.headers.getSetCookie()) {
            const [pair] = line.split(';');
            const index = pair.indexOf('=');
            const name = pair.slice(0, index).trim();
            const value = pair.slice(index + 1).trim();
            if (/max-age=0|expires=thu, 01 jan 1970/i.test(line) || value === '') {
                this.cookies.delete(name);
            } else {
                this.cookies.set(name, value);
            }
        }
    }

    // Follows redirects manually so every Set-Cookie on the way is kept.
    async request(path, options = {}) {
        let url = new URL(path, this.baseUrl);
        let method = options.method || 'GET';
        let body = options.body;
        for (let hop = 0; hop < 10; hop += 1) {
            const headers = { ...(options.headers || {}) };
            if (this.cookies.size) headers.Cookie = this.cookieHeader();
            const response = await fetch(url, {
                method,
                body,
                headers,
                redirect: 'manual',
                duplex: body && typeof body.pipe === 'function' ? 'half' : undefined,
                signal: options.signal,
            });
            this.storeCookies(response);
            if (response.status < 300 || response.status >= 400) return response;
            await response.arrayBuffer();
            url = new URL(response.headers.get('location'), url);
            if (response.status !== 307 && response.status !== 308) {
                method = 'GET';
                body = undefined;
            }
        }
        throw new Error(`Too many redirects for ${path}`);
    }

    async page(path) {
        const response = await this.request(path);
        const html = await response.text();
        return { response, html, url: response.url };
    }

    async submitForm(path, fields) {
        const { html } = await this.page(path);
        const match = CSRF_INPUT.exec(html);
        if (!match) throw new Error(`No CSRF token on ${path}`);
        const form = new URLSearchParams({ csrf_token: match[1], ...fields });
        const response = await this.request(path, {
            method: 'POST',
            body: form.toString(),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Origin: this.baseUrl,
                Referer: new URL(path, this.baseUrl).href,
            },
        });
        return { response, html: await response.text() };
    }

    async register(username, password) {
        const { html } = await this.submitForm('/register', {
            username, password, confirm_password: password,
        });
        await this.loadWorkspace(html);
    }

    async login(username, password) {
        const { html } = await this.submitForm('/login', { username, password });
        await this.loadWorkspace(html);
    }

    async loadWorkspace(html) {
        let page = html;
        if (!CSRF_META.test(page) || !page.includes('/socket.io')) {
            page = (await this.page('/')).html;
        }
        const meta = CSRF_META.exec(page);
        if (!meta || !page.includes('socket')) {
            throw new Error('Sign-in did not reach the workspace');
        }
        this.csrfToken = meta[1];
    }

    async logout() {
        await this.request('/logout', {
            method: 'POST',
            body: new URLSearchParams({ csrf_token: this.csrfToken }).toString(),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Origin: this.baseUrl,
            },
        });
        this.cookies.clear();
    }

    // Resolves with the socket once the server confirms the namespace
    // ('connected' status 'success'); rejects with the observed failure.
    openSocket(timeoutMs = 15000) {
        const socket = io(this.baseUrl, {
            path: '/socket.io',
            autoConnect: false,
            reconnection: false,
            auth: { wire_revision: SOCKET_WIRE_REVISION },
            extraHeaders: { Cookie: this.cookieHeader(), Origin: this.baseUrl },
        });
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                socket.close();
                reject(new Error('socket_timeout'));
            }, timeoutMs);
            socket.on('connected', (data) => {
                clearTimeout(timer);
                if (data?.status === 'success') {
                    resolve(socket);
                } else {
                    socket.close();
                    const error = new Error(`connected_status:${data?.status}`);
                    error.status = data?.status;
                    reject(error);
                }
            });
            socket.on('connect_error', (error) => {
                clearTimeout(timer);
                socket.close();
                const failure = new Error(`connect_error:${error.message}`);
                failure.description = error.description?.message || error.description || null;
                failure.context = error.context?.statusText || null;
                reject(failure);
            });
            socket.connect();
        });
    }
}

module.exports = { BrowserSession, SOCKET_WIRE_REVISION };
