const {spawn} = require('node:child_process');
const readline = require('node:readline');
const assert = require('node:assert/strict');
const path = require('node:path');
const {chromium} = require('playwright');
const root = path.resolve(__dirname, '../..');
const driver = path.join(__dirname, 'tmux_sync_driver.py');
const linuxDriver = process.platform === 'win32'
    ? '/mnt/' + driver[0].toLowerCase() + driver.slice(2).replaceAll('\\', '/') : driver;
let child, replies;
async function remote(request) {
    child.stdin.write(JSON.stringify(request)+'\n');
    const result = await replies.next();
    assert.equal(result.done,false);
    return JSON.parse(result.value);
}
(async () => {
    const browser = await chromium.launch();
    child = process.platform === 'win32'
        ? spawn('wsl', ['-d', 'Ubuntu', '--exec', 'python3', linuxDriver], {stdio:['pipe','pipe','inherit']})
        : spawn('python3', [driver], {stdio:['pipe','pipe','inherit']});
    replies = readline.createInterface({input:child.stdout})[Symbol.asyncIterator]();
    try {
        const page = await browser.newPage();
        await page.setContent('<div id="terminal"></div>');
        await page.addScriptTag({path:path.join(root,'static/vendor/xterm/xterm.js')});
        await page.addScriptTag({path:path.join(root,'static/js/session-directory-sync.js')});
        await page.evaluate(() => {
            window.term = new Terminal({cols:80,rows:24}); term.open(document.querySelector('#terminal'));
            SessionDirectorySync.trackTerminal('test',term);
        });
        async function step(input='', extra={}) {
            if(input) await page.evaluate(s=>SessionDirectorySync.noteInput('test',s),input);
            const result = await remote({input:Buffer.from(input).toString('base64'),...extra});
            await page.evaluate(data=>new Promise(resolve=>term.write(Uint8Array.from(atob(data),c=>c.charCodeAt(0)),resolve)),result.output);
            result.ready = await page.evaluate(d=>{SessionDirectorySync.observePrompt('test',d);return SessionDirectorySync.canSend('test',d);}, result.directory);
            return result;
        }
        let r=await step(); assert.equal(r.ready,false);
        r=await step('',{activate:true}); console.log('PASS manual activation detected');
        assert.ok(r.directory.prompt); assert.equal(r.ready,false);
        r=await step('\r'); assert.equal(r.ready,true);
        for(const target of ['/tmp','/']) {
            r=await step('cd '+target); assert.equal(r.ready,false);
            r=await step('\r'); assert.equal(r.directory.path,target); assert.equal(r.ready,true);
        }
        await page.exposeFunction('tmuxRequest', request => remote(request));
        await page.evaluate(() => {
            window.syncJobs = [];
            window.sentCommands = [];
            window.syncTimers = [];
            const receive = async request => {
                const result = await window.tmuxRequest(request);
                await new Promise(resolve => term.write(Uint8Array.from(atob(result.output),c=>c.charCodeAt(0)),resolve));
                return result;
            };
            window.controller = SessionDirectorySync.createController({
                socket:{emit(_event,_data,reply){ syncJobs.push(receive({}).then(r=>reply({success:true,directory:r.directory}))); }},
                manager:{isEmbeddedOpen:()=>true,getPaneSourceId:()=>'sftp-session:test',
                    panes:{left:{path:'/'}},navigatePaneTo(){}},
                sendInput(id,data) {
                    sentCommands.push(data); SessionDirectorySync.noteInput(id,data);
                    syncJobs.push(receive({input:btoa(String.fromCharCode(...new TextEncoder().encode(data)))}));
                },
                setTimeout(fn){syncTimers.push(fn);return syncTimers.length;},
                clearTimeout(id){if(id)syncTimers[id-1]=null;}
            });
            window.drainSync = async () => {while(syncJobs.length) await syncJobs.shift();};
            controller.setContext('test',true);
        });
        await page.evaluate(()=>drainSync());
        for (const target of ['/tmp','/',r.special_path]) {
            await page.evaluate(target=>controller.navigate('test',target),target);
            await page.evaluate(()=>drainSync());
            await page.evaluate(()=>syncTimers.filter(Boolean).at(-1)());
            await page.evaluate(()=>drainSync());
            r=await step(); assert.equal(r.directory.path,target); assert.equal(r.ready,true);
        }
        assert.equal(await page.evaluate(()=>sentCommands.length),3);
        await page.evaluate(()=>controller.setEnabled(false));
        assert.equal(await page.evaluate(()=>controller.navigate('test','/')),false);
        assert.equal(await page.evaluate(()=>sentCommands.length),3);
        await page.evaluate(()=>controller.setEnabled(true));
        await page.evaluate(()=>drainSync());
        r=await step('\r'); assert.equal(r.ready,true);
        console.log('PASS real controller folder changes and existing sync off/on switch');
        for(const command of ['echo "','echo \\', 'cat <<EOF', 'for i in a; do', 'echo $(']) {
            r=await step(command); r=await step('\r');
            assert.equal(r.ready,false,command); assert.equal(r.directory.prompt.phase,'c');
            r=await step('\x03'); assert.equal(r.ready,true,'Ctrl+C '+command);
            console.log('PASS integrated continuation:',command);
        }
        r=await step('sleep 30'); r=await step('\r'); assert.equal(r.ready,false);
        r=await step('\x03'); assert.equal(r.ready,true);
        r=await step('read answer'); r=await step('\r'); assert.equal(r.ready,false);
        r=await step('\x03'); assert.equal(r.ready,true);
        console.log('PASS foreground commands and shell read block navigation; Ctrl+C recovers');
        r=await step('read answer'); r=await step('\r');
        r=await step('answer'); r=await step('\r'); assert.equal(r.ready,false);
        await page.evaluate(()=>{controller.setEnabled(false);controller.setEnabled(true);});
        await page.evaluate(()=>drainSync());
        r=await step('\r'); assert.equal(r.ready,true);
        await page.evaluate(()=>controller.dispose());
        console.log('PASS conservative recovery after application input via the existing checkbox');
        r=await step('false'); r=await step('\r');
        assert.ok(Buffer.from(r.output,'base64').toString().includes('CUSTOM(1)'));
        const verify = String.raw`[[ $PS1 == "$__original_ps1"'\[$(__webssh_sync_v1 p)\]' && $PS2 == "$__original_ps2"'\[$(__webssh_sync_v1 c)\]' && $PS0 == "$__original_ps0"'$(__webssh_sync_v1 b)' && $(declare -p PROMPT_COMMAND) == "$__original_pc" ]] && printf 'PROMPTS_PRESERVED\n'`;
        r=await step(verify); r=await step('\r');
        assert.ok(Buffer.from(r.output,'base64').toString().includes('PROMPTS_PRESERVED'));
        r=await step('',{activate:true});
        r=await step(verify); r=await step('\r');
        assert.ok(Buffer.from(r.output,'base64').toString().includes('PROMPTS_PRESERVED'));
        console.log('PASS custom PS0/PS1/PS2, array PROMPT_COMMAND, exit status and repeated activation');
        r=await step('',{copy:true}); assert.equal(r.ready,false);
        r=await step('',{cancel_copy:true});
        r=await step('unfinished'); assert.equal(r.ready,false);
        await page.evaluate(()=>SessionDirectorySync.beginReplay('test'));
        r=await step('',{reattach:true});
        await page.evaluate(()=>SessionDirectorySync.endReplay('test'));
        r=await step(); assert.equal(r.ready,false);
        r=await step('\x03'); assert.equal(r.ready,true);
        console.log('PASS copy mode and real detach/reattach; configuration hashes and both session PIDs preserved');
    } finally {
        child.stdin.end();
        if (child.exitCode === null) await new Promise(resolve=>child.once('exit',resolve));
        await browser.close();
    }
})().catch(error=>{console.error(error);process.exitCode=1;});
