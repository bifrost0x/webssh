const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
function fixture() {
    const listeners = {}, storage = new Map(), elements = {};
    let document;
    class Element {
        constructor(tag='div') { this.tagName=tag; this.children=[]; this.dataset={}; this.attributes={}; this.listeners={}; this.className=''; this.textContent=''; this.value=''; this.classList={toggle: (name, enabled) => {const names=new Set(this.className.split(' ').filter(Boolean)); enabled ? names.add(name) : names.delete(name); this.className=[...names].join(' ');}, add: name => this.classList.toggle(name,true), contains: name => this.className.split(' ').includes(name)}; }
        append(...children) {this.children.push(...children);}
        appendChild(child) {this.append(child);}
        replaceChildren(...children) {this.children=children;}
        querySelectorAll(selector) {
            const result=[];
            const visit=node=>{if((selector === '[data-favorite-type]' && node.dataset.favoriteType) || (selector === 'button' && node.tagName === 'button')) result.push(node);node.children.forEach(visit);};
            this.children.forEach(visit);return result;
        }
        addEventListener(type,callback) {this.listeners[type]=callback;}
        setAttribute(name,value) {this.attributes[name]=String(value);}
        focus() {document.activeElement=this;}
    }
    for(const name of ['Library','Favorites','Sets']) for(const part of ['Tab','Panel']) elements[`command${name}${part}`]=new Element();
    elements.commandWorkspaceModal=new Element(); elements.commandFavoritesList=new Element(); elements.commandFavoritesSearch=new Element();
    document={listeners:{},addEventListener(type,callback,capture){this.listeners[type]={callback,capture};},querySelector:()=>null,body:{dataset:{connectionHistoryScope:'alice'}},createElement: tag=>new Element(tag),getElementById: id=>elements[id],querySelectorAll:()=>{ const found=[]; const visit=node=>{ if(node.dataset.favoriteType) found.push(node); node.children.forEach(visit); }; Object.values(elements).forEach(visit); return found; }};
    const context=vm.createContext({document,localStorage:{getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value)},setTimeout:callback=>callback(),addEventListener:(type,callback)=>{(listeners[type] ||= []).push(callback);},dispatchEvent:event=>listeners[event.type]?.forEach(callback=>callback(event)),CustomEvent:class {constructor(type,options){this.type=type;this.detail=options?.detail;}}});
    context.window=context;
    for(const file of ['session-command-launcher','command-workspace']) vm.runInContext(fs.readFileSync(`static/js/${file}.js`,'utf8'),context);
    return {context,elements,document,storage};
}
test('workspace guards unsaved sets and gives three tabs keyboard focus',async()=>{
    const {context,elements,document}=fixture(); const workspace=context.CommandWorkspace; workspace.init(); workspace.select('sets');
    context.CommandSetManager={hasUnsavedChanges:()=>true,confirmDiscard:async()=>false};
    await workspace.select('favorites'); assert.equal(workspace.activeSection,'sets');
    context.CommandSetManager.confirmDiscard=async()=>true; await workspace.select('favorites');
    assert.equal(elements.commandFavoritesTab.attributes['aria-selected'],'true');
    await elements.commandFavoritesTab.listeners.keydown({key:'Home',preventDefault(){}});
    assert.equal(workspace.activeSection,'library'); assert.equal(document.activeElement,elements.commandLibraryTab);
});
test('shared stars synchronize and reload account scope before mutation',()=>{
    const {context,document,storage,elements}=fixture(); context.CommandWorkspace.init();
    const first=context.CommandWorkspace.favoriteButton('command','one'),second=context.CommandWorkspace.favoriteButton('command','one'); elements.commandLibraryPanel.append(first,second); first.listeners.click();
    assert.equal(second.attributes['aria-pressed'],'true'); document.body.dataset.connectionHistoryScope='bob';
    context.SessionCommandLauncher.toggleFavorite({type:'set',id:'two'});
    assert.deepEqual(JSON.parse(storage.get('webssh:session-commands:bob')).favorites,['set:two']); assert.equal(first.attributes['aria-pressed'],'false');
});
test('favorites render literal names and route command copy and set edit',async()=>{
    const {context,elements}=fixture(),calls=[];
    context.CommandLibrary={commands:[{id:'c',isSystem:true,name:'<img src=x>',command:'echo x',description:'Literal'}],openEditor:id=>calls.push(['command',id])};
    context.CommandSetManager={commandSets:[{id:'s',name:'Set',steps:[{}]}],openBuilder:id=>calls.push(['set',id])};
    context.CommandWorkspace.init(); context.SessionCommandLauncher.toggleFavorite({type:'command',id:'c'}); context.SessionCommandLauncher.toggleFavorite({type:'set',id:'s'}); context.CommandWorkspace.select('favorites');
    const cards=elements.commandFavoritesList.children; assert.equal(cards.length,2); assert.ok(cards.some(card=>card.children.some(node=>node.textContent==='<img src=x>')));
    await cards.find(card=>card.children[0].textContent==='<img src=x>').children.at(-1).listeners.click(); await cards.find(card=>card.children[0].textContent==='Set').children.at(-1).listeners.click(); assert.deepEqual(calls,[['command','c'],['set','s']]);
    elements.commandFavoritesSearch.value='Literal'; elements.commandFavoritesSearch.listeners.input(); assert.equal(elements.commandFavoritesList.children.length,1);
});
test('sidebar sections separate types and favorite store is bounded',()=>{
    const {context}=fixture(),launcher=context.SessionCommandLauncher; launcher.loadPreferences(); launcher.toggleFavorite({type:'command',id:'c'}); launcher.toggleFavorite({type:'set',id:'s'});
    const entries=[{type:'command',id:'c'},{type:'set',id:'s'},{type:'command',id:'other'}];
    launcher.activeSection='library'; assert.deepEqual(Array.from(launcher.sectionEntries(entries),item=>item.id),['c','other']);
    launcher.activeSection='sets'; assert.deepEqual(Array.from(launcher.sectionEntries(entries),item=>item.id),['s']);
    launcher.activeSection='favorites'; assert.equal(launcher.sectionEntries(entries).length,2);
    for(let i=0;i<120;i++) launcher.toggleFavorite({type:'command',id:String(i)}); assert.equal(launcher.favorites.size,100);
});

test('favorites survive launcher initialization order and omit deleted entries',()=>{
    const {context,elements}=fixture();
    context.CommandLibrary={commands:[{id:'c',name:'Saved',command:'pwd'}]};
    context.CommandWorkspace.init();
    context.SessionCommandLauncher.toggleFavorite({type:'command',id:'c'});
    context.SessionCommandLauncher.init();
    assert.equal(context.SessionCommandLauncher.favorites.has('command:c'),true);
    context.CommandLibrary.commands=[];
    context.CommandWorkspace.renderFavorites();
    assert.equal(elements.commandFavoritesList.children[0].textContent,'No favorites yet. Use the star on a command or command set to keep it here.');
    elements.commandFavoritesSearch.value='missing'; context.CommandWorkspace.renderFavorites();
    assert.equal(elements.commandFavoritesList.children[0].textContent,'No matching entries.');
});

test('Escape requests guarded close before generic modal dismissal and respects nested dialogs',async()=>{
    const {context,elements,document}=fixture();
    const workspace=context.CommandWorkspace, modal=elements.commandWorkspaceModal;
    let confirmCalls=0;
    context.CommandSetManager={close:async()=>{confirmCalls++; return false;}};
    workspace.init(); workspace.select('sets'); modal.classList.add('show');
    const event=()=>({key:'Escape',preventDefault(){this.defaultPrevented=true;},stopImmediatePropagation(){this.stopped=true;}});
    const handler=document.listeners.keydown;
    assert.ok(handler, 'Workspace must intercept Escape during capture');
    assert.equal(handler.capture,true);
    const first=event(); handler.callback(first);
    if(!first.stopped) modal.classList.toggle('show',false);
    assert.equal(confirmCalls,1); assert.equal(first.defaultPrevented,true); assert.equal(modal.classList.contains('show'),true);
    document.querySelector=selector=>selector==='dialog[open]'?{}:null;
    const native=event(); handler.callback(native); assert.equal(native.stopped,undefined); assert.equal(confirmCalls,1);
    document.querySelector=()=>null; modal.classList.add('primary-workspace-view');
    const primary=event(); handler.callback(primary); assert.equal(primary.stopped,undefined);
    modal.classList.toggle('primary-workspace-view',false);
    context.ModalManager={activeModal:{}};
    const nested=event(); handler.callback(nested); assert.equal(nested.stopped,undefined); assert.equal(confirmCalls,1);
});


test('favorite edit waits for section selection and never opens after rejected selection',async()=>{
    const {context,elements}=fixture(); let opened=0,finish;
    context.CommandSetManager={commandSets:[{id:'s',name:'Set'}],openBuilder:()=>opened++};
    context.CommandWorkspace.init(); context.SessionCommandLauncher.toggleFavorite({type:'set',id:'s'});
    const edit=elements.commandFavoritesList.children[0].children.at(-1);
    context.CommandWorkspace.select=()=>new Promise(resolve=>{finish=resolve;});
    const pending=edit.listeners.click(); assert.equal(opened,0);
    finish(false); await pending; assert.equal(opened,0);
    const allowed=edit.listeners.click(); assert.equal(opened,0);
    finish(true); await allowed; assert.equal(opened,1);
});


test('removing a favorite preserves keyboard focus on the next remaining favorite',()=>{
    const {context,elements,document}=fixture();
    context.CommandLibrary={commands:[{id:'a',name:'Alpha',command:'pwd'},{id:'b',name:'Beta',command:'date'}]};
    context.CommandWorkspace.init();
    context.SessionCommandLauncher.toggleFavorite({type:'command',id:'a'});
    context.SessionCommandLauncher.toggleFavorite({type:'command',id:'b'});
    context.CommandWorkspace.select('favorites');
    const first=elements.commandFavoritesList.querySelectorAll('[data-favorite-type]')[0];
    first.focus(); first.listeners.click();
    const remaining=elements.commandFavoritesList.querySelectorAll('[data-favorite-type]');
    assert.equal(remaining.length,1);
    assert.equal(document.activeElement,remaining[0]);
    remaining[0].listeners.click();
    assert.equal(document.activeElement,elements.commandFavoritesSearch);
});

test('favorite background updates preserve focus outside the replaced cards',()=>{
    const {context,elements,document}=fixture();
    context.CommandLibrary={commands:[{id:'a',name:'Alpha',command:'pwd'}]};
    context.CommandWorkspace.init(); elements.commandFavoritesSearch.focus();
    context.SessionCommandLauncher.toggleFavorite({type:'command',id:'a'});
    assert.equal(document.activeElement,elements.commandFavoritesSearch);
});


test('a favorite edit button retains its entry identity through background updates',()=>{
    const {context,elements,document}=fixture();
    context.CommandLibrary={commands:[{id:'a',name:'Alpha',command:'pwd'}]};
    context.CommandWorkspace.init();
    context.SessionCommandLauncher.toggleFavorite({type:'command',id:'a'});
    const oldEdit=elements.commandFavoritesList.children[0].children.at(-1);
    oldEdit.focus(); context.CommandWorkspace.renderFavorites();
    const newEdit=elements.commandFavoritesList.children[0].children.at(-1);
    assert.notEqual(oldEdit,newEdit);
    assert.equal(document.activeElement,newEdit);
});


test('removing the last favorite retains the star action on the previous card',()=>{
    const {context,elements,document}=fixture();
    context.CommandLibrary={commands:[{id:'a',name:'Alpha',command:'pwd'},{id:'b',name:'Beta',command:'date'}]};
    context.CommandWorkspace.init();
    for(const id of ['a','b']) context.SessionCommandLauncher.toggleFavorite({type:'command',id});
    const last=elements.commandFavoritesList.querySelectorAll('[data-favorite-type]').at(-1);
    last.focus();last.listeners.click();
    assert.equal(document.activeElement,elements.commandFavoritesList.querySelectorAll('[data-favorite-type]').at(-1));
});
