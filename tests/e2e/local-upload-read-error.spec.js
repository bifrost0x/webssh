const {test,expect}=require('playwright/test');
const {login}=require('./helpers');

test('unreadable local drop shows an actionable error and leaves Files usable', async ({page})=>{
    await login(page);
    await page.locator('#fileTransferBtn').click();
    await page.evaluate(async ()=>{
        const manager=window.sftpFileManager;
        const broken={isFile:true,name:'unreadable.txt',file(_resolve,reject){reject(new DOMException('private-path','NotReadableError'));}};
        await manager.uploadDesktopItemsToSSH([broken],manager.panes.left);
    });
    await expect(page.locator('#notificationContainer')).toContainText('Could not read the selected local files or folders. Nothing was uploaded.');
    await expect(page.locator('#notificationContainer')).not.toContainText('private-path');
    await page.locator('#fmLayoutSplit').click();
    await expect(page.locator('#fmRightPane')).toBeVisible();
    await page.locator('#fmLayoutSingle').click();
    await expect(page.locator('#fmRightPane')).not.toBeVisible();
});
