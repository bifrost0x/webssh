'use strict';

// Accounts for one measurement run: the bootstrap administrator through the
// one-time registration, further users through open registration. Every
// account then signs out and signs in again through the login form, so each
// socket carries a session created by the real login path.

const { BrowserSession } = require('./browser-session');
const { randomSecret } = require('./environment');

async function createAccounts(baseUrl, count) {
    const accounts = [];
    for (let index = 0; index < count; index += 1) {
        const username = index === 0 ? 'benchadmin' : `benchuser${index}`;
        const password = `bench-${randomSecret(10)}`;
        const registration = new BrowserSession(baseUrl);
        await registration.register(username, password);
        await registration.logout();
        const session = new BrowserSession(baseUrl);
        await session.login(username, password);
        accounts.push({ username, session });
    }
    return accounts;
}

module.exports = { createAccounts };
