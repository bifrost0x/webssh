const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

for (const width of [390, 1440]) {
    test(`transfer history preserves old errors and cancellation at ${width}`, async ({page}) => {
        await page.setViewportSize({width,height:900});
        await login(page);
        await page.evaluate(() => window.sftpFileManager.open());
        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            manager.transferQueue = [
                {id:'old-active',type:'s2s-queued',filename:'active.txt',status:'pending',targetPath:'/srv/active.txt',endpoints:{source:'operator@source:22 · /source/active.txt',destination:'operator@target:22 · /srv/active.txt'}},
                {id:'old-error',type:'download',filename:'<img src=x onerror=alert(1)>.txt',status:'error',errorCode:'OUTCOME_UNKNOWN',error:'Outcome unknown',sourcePath:'/srv/<unsafe>.txt'},
                ...Array.from({length:75}, (_, id) => ({id:`history-${id}`,type:'download',filename:`file-${id}.txt`,status:'complete',sourcePath:`/srv/file-${id}.txt`}))
            ];
            manager.renderTransferQueue();
        });
        await page.locator('#fmQueueHeader').click();
        await expect(page.locator('#fmQueueList .fm-transfer-item')).toHaveCount(20);
        await expect(page.locator('[data-transfer-cancel="old-active"]')).toBeInViewport();
        await expect(page.locator('[data-transfer-id="old-active"]')).toContainText('operator@source:22 · /source/active.txt → operator@target:22 · /srv/active.txt');
        await expect(page.locator('#fmQueueList img')).toHaveCount(0);
        await page.locator('#fmQueueFilter').selectOption('error');
        await expect(page.locator('#fmQueueList .fm-transfer-item')).toHaveCount(1);
        await expect(page.locator('#fmQueueList')).toContainText('Outcome unknown');
        await page.locator('#fmQueueList details summary').click();
        await page.evaluate(() => window.sftpFileManager.renderTransferQueue());
        await expect(page.locator('#fmQueueList details')).toHaveAttribute('open', '');
        await page.screenshot({path:`plans/trust-files-controls/transfers-${width}.png`,fullPage:true});
        await page.locator('#fmQueueFilter').selectOption('active');
        await page.locator('[data-transfer-cancel="old-active"]').click();
        await expect(page.locator('#fmQueueList .fm-transfer-item')).toHaveCount(0);
        expect(await page.evaluate(() => window.sftpFileManager.transferQueue[0].status)).toBe('cancelled');
        await page.locator('#fmQueueFilter').selectOption('history');
        await page.locator('#fmQueueNext').click();
        await expect(page.locator('#fmQueuePage')).toHaveText('2 / 4 · 76');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });

    test(`effective trust explains inherited and revoked keys at ${width}`, async ({page}) => {
        await page.setViewportSize({width,height:900});
        await login(page,'e2e_admin',{workspace:false});
        await page.route('**/api/host-keys/effective', route => route.fulfill({json:{targets:[
            {id:'a',name:'Main host',host:'host.example',port:22,keys:[{scope:'user',status:'effective',algorithm:'ssh-ed25519',fingerprint:'SHA256:personal'},{scope:'global',status:'overridden',algorithm:'ssh-ed25519',fingerprint:'SHA256:global'}]},
            {id:'b',name:'Blocked host',host:'blocked.example',port:22,keys:[{scope:'global',status:'revoked',algorithm:'ssh-ed25519',fingerprint:'SHA256:revoked'}]}
        ]}}));
        await page.route('**/api/host-keys',route=>route.fulfill({json:{entries:[{id:'orphan',host:'host.example',hosts:[{host:'host.example',port:22},{host:'orphan.example',port:22}],port:22,scope:'user',algorithm:'ssh-ed25519',fingerprint:'SHA256:personal'}]}}));
        await page.route('**/api/host-keys/orphan/deletion-impact', route => route.fulfill({json:{revision:'preview-revision',unresolved:true,targets:[{name:'Main host',host:'host.example',port:22,keys:[{scope:'global',status:'effective',algorithm:'ssh-ed25519',fingerprint:'SHA256:global-after-delete'}]}]}}));
        let deletions=0;
        await page.route('**/api/host-keys/orphan',route=>{deletions++;expect(route.request().headers()['if-match']).toBe('preview-revision');return route.fulfill({status:409,json:{error:'Trust changed. Reload and review the deletion again.',code:'trust_changed'}});});
        await page.goto('/security#ssh-host-trust');
        await expect(page.locator('#effectiveHostTrust')).toContainText('Main host');
        await page.locator('.effective-trust-target summary').first().click();
        await expect(page.locator('.effective-trust-target').first()).toContainText('Personal · Effective');
        await expect(page.locator('.effective-trust-target').first()).toContainText('Global · Overridden');
        await expect(page.locator('#hostKeyList')).toContainText('orphan.example');
        await page.locator('#hostKeyList button').click();
        await expect(page.locator('.trust-deletion-dialog')).toContainText('Global · Effective');
        await expect(page.locator('.trust-deletion-dialog')).toContainText('SHA256:global-after-delete');
        await expect(page.locator('.trust-deletion-dialog')).toContainText('Their remaining trust is unknown');
        await page.screenshot({path:`plans/trust-files-controls/trust-deletion-${width}.png`,fullPage:true});
        await page.locator('.trust-deletion-dialog').getByRole('button',{name:'Cancel',exact:true}).click();
        expect(deletions).toBe(0);
        await page.locator('#hostKeyList button').click();
        await page.locator('.trust-deletion-dialog').getByRole('button',{name:'Delete trust',exact:true}).click();
        await expect.poll(()=>deletions).toBe(1);
        await expect(page.locator('#hostKeyList')).toContainText('orphan.example');
        await page.locator('#effectiveHostTrust h3').scrollIntoViewIfNeeded();
        await page.screenshot({path:`plans/trust-files-controls/trust-${width}.png`,fullPage:true});
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });

    test(`invalid password assignment uses reviewed target and existing step-up at ${width}`, async ({page}) => {
        await page.setViewportSize({width,height:900});
        await login(page,'e2e_admin',{workspace:false});
        const target={id:'assignment',name:'Changed destination',kind:'ssh',host:'changed.example',port:2222,username:'operator',credential_id:'saved',credential_status:'confirmation_required',credential_assignment:'snapshot'};
        const state={enabled:true,legacy_vault:false,profiles:[target],credentials:[{id:'saved',name:'Operations password',uses:[{resource_id:'assignment',name:'Changed destination',valid:false}]}]};
        await page.route('**/api/credentials/state',route=>route.fulfill({json:state}));
        let reviewed, assignments=0;
        await page.route('**/api/credentials/intents',route=>{reviewed=route.request().postDataJSON();return route.fulfill({json:{intent:'bound-intent'}});});
        await page.route('**/api/credentials/assign',route=>{assignments++;return route.fulfill({status:403,json:{code:'step_up_required'}});});
        await page.route('**/api/account/step-up/intents',route=>route.fulfill({json:{intent:'identity-intent',methods:['password'],preferred_method:'password'}}));
        await page.evaluate(() => window.openConnectionAssetManager('passwords'));
        await page.locator('[data-credential-list] button').click();
        await expect(page.locator('[data-credential-detail]')).toContainText('Review required');
        await page.screenshot({path:`plans/trust-files-controls/password-${width}.png`,fullPage:true});
        await page.getByRole('button',{name:'Review and authorize again',exact:true}).click();
        await expect(page.locator('.credential-question')).toContainText('operator@changed.example:2222');
        await page.locator('.credential-question').getByRole('button',{name:'Confirm',exact:true}).click();
        await expect(page.locator('.credential-question input[type=password]')).toBeVisible();
        expect(reviewed.mutation.target).toMatchObject(target);
        expect(reviewed.mutation.expected_assignment).toBe('snapshot');
        await page.locator('.credential-question').getByRole('button',{name:'Cancel',exact:true}).click();
        expect(assignments).toBe(1);
        await expect(page.locator('[data-credential-detail]')).toContainText('Review required');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });
}
