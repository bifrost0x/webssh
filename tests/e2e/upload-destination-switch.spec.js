const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
for(const change of ['none','session','directory']) test(`upload picker keeps the selected destination: ${change}`,async({page})=>{
    await page.setViewportSize({width:390,height:850});
    await login(page);
    await page.evaluate(()=>{
        const manager=sftpFileManager;
        manager.open();
        manager.activePane='left';
        Object.assign(manager.panes.left,{source:{sourceId:'sftp-session:original',kind:'sftp',capabilities:['list','write']},path:'/selected',loading:false,error:null});
        window.uploadWrites=[];
        manager.getTransferClient=()=>({uploadFile(file,path,sourceId){window.uploadWrites.push({name:file.name,path,sourceId});return 'test-upload';}});
        manager.startUploadBatch=()=>({id:'test-batch'});
        manager.queueTransfer=()=>{};
        manager.renderPane('left');
        manager.updateWorkspaceActions();
    });
    const chooserPromise=page.waitForEvent('filechooser');
    await page.locator('[data-pane-toolbar="left"] [data-pane-action="upload"]').click();
    const chooser=await chooserPromise;
    await page.evaluate(change=>{
        const manager=sftpFileManager;
        if(change==='session') manager.panes.left={...manager.panes.left,source:{sourceId:'sftp-session:other',kind:'sftp',capabilities:['list','write']}};
        if(change==='directory') manager.panes.left.path='/changed';
    },change);
    await chooser.setFiles({name:'private.txt',mimeType:'text/plain',buffer:Buffer.from('private fixture')});
    if(change==='none') {
        await expect.poll(()=>page.evaluate(()=>window.uploadWrites)).toEqual([{name:'private.txt',path:'/selected/private.txt',sourceId:'sftp-session:original'}]);
    } else {
        await expect(page.locator('#notificationContainer')).toContainText('Upload destination changed');
        expect(await page.evaluate(()=>window.uploadWrites)).toEqual([]);
    }
    await expect(page.locator('#fmMobileUploadInput')).toHaveValue('');
});
