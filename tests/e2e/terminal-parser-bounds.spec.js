const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('terminal remains usable after excessive remote controls and replaced hyperlinks', async ({page}) => {
    await login(page);
    const result = await page.evaluate(async () => {
        const host = document.createElement('div');
        host.style.cssText = 'width:640px;height:400px;position:fixed;inset:60px 0 0;background:black';
        document.body.append(host);
        const terminal = new Terminal({cols:80,rows:24,allowProposedApi:true});
        terminal.open(host);
        const write = data => new Promise(resolve => terminal.write(data, resolve));
        try {
            await write('one\r\ntwo\x1b[2147483647S\x1b[2147483647T\x1b[2147483647L\x1b[2147483647M\x1b[2147483647I\x1b[2147483647Z');
            await write('A\x1b[2147483647b'.repeat(1000));
            await write(('\x1b]8;;https://example.invalid/\x1b\\X\x1b]8;;\x1b\\\r').repeat(10000));
            await write('\r\nREADY');
            const buffer = terminal.buffer.active;
            return {text:buffer.getLine(buffer.baseY+buffer.cursorY).translateToString(true),
                links:terminal._core._inputHandler._oscLinkService._dataByLinkId.size};
        } finally { terminal.dispose(); host.remove(); }
    });
    expect(result.text).toBe('READY');
    expect(result.links).toBeLessThanOrEqual(1024);
    await page.locator('#manageProfilesBtn').click();
    await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','hosts');
});
