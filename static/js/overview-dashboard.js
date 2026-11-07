/* Browser-local dashboard arrangement, isolated from host/map configuration. */
(function () {
    'use strict';
    const root = document.getElementById('connectionOverview');
    if (!root) return;
    const scope = document.querySelector('meta[name="background-scope"]')?.content;
    const key = /^[a-f0-9]{64}$/.test(scope || '') ? `webssh:dashboard:${scope}` : null;
    const definitions = [
        ['inventory', '.overview-inventory-sidebar', 'Inventory', 'Inventar', 'full'],
        ['infrastructure', '.overview-primary', 'Infrastructure', 'Infrastruktur', 'half'],
        ['routes', '#overviewRouteMap', 'SSH routes', 'SSH-Verbindungen', 'half'],
        ['runs', '#overviewAutomation', 'Recent runs', 'Letzte Runs', 'half'],
        ['activity', '#overviewAnalytics', 'Automation activity', 'Automationsaktivit\u00e4t', 'half'],
        ['sessions', '.overview-session-strip', 'Sessions', 'Sitzungen', 'half'],
        ['news', '.overview-activity', 'News', 'Neuigkeiten', 'full']
    ];
    let order = definitions.map(d => d[0]);
    let sizes = {};
    let heights = {};
    let enabled = {news:false};
    try {
        const raw = key && localStorage.getItem(key);
        const saved = raw && raw.length < 10000 ? JSON.parse(raw) : null;
        if (saved?.version === 1) {
            if (Array.isArray(saved.order)) order = [...new Set(saved.order.filter(id => order.includes(id))), ...order.filter(id => !saved.order.includes(id))];
            if (!Array.isArray(saved.order) || !saved.order.includes('routes')) {
                order = order.filter(id => id !== 'routes');
                order.splice(order.indexOf('infrastructure') + 1, 0, 'routes');
            }
            for (const [id] of definitions) {
                if (typeof saved.enabled?.[id] === 'boolean') enabled[id] = saved.enabled[id];
                if (['half', 'full'].includes(saved.sizes?.[id])) sizes[id] = saved.sizes[id];
                if (['compact', 'normal', 'large'].includes(saved.heights?.[id])) heights[id] = saved.heights[id];
            }
        }
    } catch { /* Defaults remain usable when browser storage is unavailable. */ }
    const text = en => window.i18n?.t('overview.ui.' + en.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')) || en;
    const labels = [];
    const label = (element, value, attribute = null) => {
        const update = () => { const translated = typeof value === 'function' ? value() : text(value); if (attribute) element.setAttribute(attribute, translated); else element.textContent = translated; };
        labels.push(update); update();
    };
    const save = () => { try { if (key) localStorage.setItem(key, JSON.stringify({version:1,order,sizes,heights,enabled})); } catch { /* Optional browser preference. */ } };
    const grid = document.createElement('div'); grid.className = 'overview-dashboard-grid';
    const modules = new Map();
    let editing = false;
    function syncLayout() {
        root.dataset.dashboardDefault = String(!editing &&
            order.join('|') === definitions.map(d=>d[0]).join('|') &&
            definitions.every(d=>(sizes[d[0]]||d[4])===d[4]) &&
            ['infrastructure','runs','activity'].every(id=>modules.has(id) && !modules.get(id).hidden));
    }
    function apply() {
        const focused = document.activeElement;
        for (const id of order) {
            const module = modules.get(id);
            if (!module) continue;
            module.dataset.size = sizes[id] || definitions.find(d=>d[0]===id)[4];
            module.dataset.height = heights[id] || 'normal';
            module.hidden = !editing && (module.lastElementChild.hidden || enabled[id] === false);
            const controls = module.querySelector('.overview-module-tools').querySelectorAll('select');
            controls[0].value = module.dataset.size;
            if (controls[1]) controls[1].value = module.dataset.height;
            module.querySelector('input[type=checkbox]').checked = enabled[id] !== false;
            grid.append(module);
        }
        syncLayout();
        if (focused && root.contains(focused)) focused.focus({preventScroll:true});
    }
    const move = (id, delta) => {
        const index = order.indexOf(id), next = index + delta;
        if (next < 0 || next >= order.length) return;
        [order[index],order[next]] = [order[next],order[index]];
        const focus = document.activeElement; apply(); focus?.focus({preventScroll:true}); save();
    };
    for (const [id, selector, en] of definitions) {
        const content = root.querySelector(selector); if (!content) continue;
        const module = document.createElement('section'); module.className = 'overview-dashboard-module'; module.dataset.module = id;
        const tools = document.createElement('div'); tools.className = 'overview-module-tools'; tools.hidden = true;
        const handle = document.createElement('button'); handle.type = 'button'; handle.className = 'overview-module-handle';
        label(handle, () => text('Move {name}').replace('{name}', text(en)));
        let pointer = null, scrollFrame = 0;
        const stop = () => {
            pointer = null; cancelAnimationFrame(scrollFrame);
            module.classList.remove('is-dragging');
            grid.querySelectorAll('.is-drop-target').forEach(n=>n.classList.remove('is-drop-target'));
        };
        const autoScroll = () => {
            if (!pointer?.moved) return;
            const bounds = root.getBoundingClientRect();
            const top = Math.max(bounds.top, 64), bottom = Math.min(bounds.bottom, window.innerHeight - 40);
            if (pointer.y < top + 70) root.scrollTop -= 16;
            if (pointer.y > bottom - 70) root.scrollTop += 16;
            scrollFrame = requestAnimationFrame(autoScroll);
        };
        handle.addEventListener('pointerdown', event => {
            if (!editing || event.button !== 0) return;
            pointer = {id:event.pointerId,startX:event.clientX,startY:event.clientY,y:event.clientY,moved:false};
            handle.setPointerCapture(event.pointerId);
        });
        handle.addEventListener('pointermove', event => {
            if (!pointer || pointer.id !== event.pointerId) return;
            pointer.y = event.clientY;
            if (!pointer.moved && Math.hypot(event.clientX-pointer.startX,event.clientY-pointer.startY)>6) {
                pointer.moved=true;module.classList.add('is-dragging');autoScroll();
            }
            if (!pointer.moved) return;
            const target = document.elementFromPoint(event.clientX,event.clientY)?.closest('.overview-dashboard-module');
            grid.querySelectorAll('.is-drop-target').forEach(n=>n.classList.remove('is-drop-target'));
            if (target && target !== module && grid.contains(target)) target.classList.add('is-drop-target');
        });
        handle.addEventListener('pointerup', event => {
            if (!pointer || pointer.id !== event.pointerId) return;
            const target = document.elementFromPoint(event.clientX,event.clientY)?.closest('.overview-dashboard-module');
            const moved = pointer.moved;stop();
            if (!moved || !target || target===module || !grid.contains(target)) return;
            const targetIndex=order.indexOf(target.dataset.module);
            order=order.filter(item=>item!==id);order.splice(targetIndex,0,id);apply();save();
        });
        handle.addEventListener('pointercancel',stop);
        handle.addEventListener('lostpointercapture',stop);
        tools.append(handle);
        const show = document.createElement('label');
        const check = document.createElement('input');check.type='checkbox';check.checked=enabled[id]!==false;
        const showText = document.createElement('span');label(showText,'Show');show.append(check,showText);
        check.addEventListener('change',()=>{enabled[id]=check.checked;save();});tools.append(show);
        for (const [symbol,delta,english] of [['↑',-1,'Move earlier','Nach vorne'],['↓',1,'Move later','Nach hinten']]) {
            const button = document.createElement('button'); button.type = 'button'; button.textContent = symbol;
            label(button, english, 'aria-label'); button.addEventListener('click',()=>move(id,delta)); tools.append(button);
        }
        const width = document.createElement('select'); label(width, () => text('{name} width').replace('{name}', text(en)), 'aria-label');
        for (const [value,english] of [['half','Half width','Halbe Breite'],['full','Full width','Volle Breite']]) { const option=document.createElement('option');option.value=value;label(option,english);width.append(option); }
        width.value = sizes[id] || definitions.find(d=>d[0]===id)[4];width.addEventListener('change',()=>{sizes[id]=width.value;apply();save();});tools.append(width);
        if (id === 'infrastructure') {
            const height = document.createElement('select'); label(height, 'List height', 'aria-label');
            for (const [value,english] of [['compact','Compact','Kompakt'],['normal','Adaptive','Adaptiv'],['large','Large','Groß']]) {const option=document.createElement('option');option.value=value;label(option,english);height.append(option);}
            height.value=heights[id]||'normal';height.addEventListener('change',()=>{heights[id]=height.value;apply();save();});tools.append(height);
        }
        module.append(tools,content);modules.set(id,module);
        const sync = () => { module.hidden = !editing && (content.hidden || enabled[id] === false); syncLayout(); };
        new MutationObserver(sync).observe(content,{attributes:true,attributeFilter:['hidden']});sync();
    }
    const infrastructure = modules.get('infrastructure');
    const arrange = infrastructure.querySelector('.overview-arrange-bar');
    const infrastructureHeading = infrastructure.querySelector('.overview-card-heading');
    infrastructureHeading.append(arrange, arrange.querySelector('#overviewArrangePanel'));
    root.querySelector('.overview-support')?.remove();
    root.querySelector('.overview-inner').append(grid);apply();
    const customize = document.getElementById('overviewCustomize');
    customize.addEventListener('click',()=>{
        editing=!editing;root.dataset.dashboardEditing=String(editing);customize.setAttribute('aria-pressed',String(editing));
        customize.textContent=text(editing?'Done':'Customize dashboard',editing?'Fertig':'Dashboard anpassen');
        for (const module of modules.values()) {module.querySelector('.overview-module-tools').hidden=!editing;module.hidden=!editing&&(module.lastElementChild.hidden||enabled[module.dataset.module]===false);}
        syncLayout();
    });
    const reset = document.createElement('button'); reset.id='overviewResetDashboard';reset.type='button';reset.className='btn btn-secondary';
    label(reset,'Reset dashboard');
    const undo = document.createElement('button');undo.id='overviewUndoDashboard';undo.type='button';undo.className='btn btn-secondary';undo.hidden=true;label(undo,'Undo reset');
    let previous = null;
    reset.addEventListener('click',()=>{
        if (!previous) previous={order:[...order],sizes:{...sizes},heights:{...heights},enabled:{...enabled}};
        order=definitions.map(d=>d[0]);sizes={};heights={};enabled={news:false};apply();save();undo.hidden=false;
    });
    undo.addEventListener('click',()=>{if(!previous)return;({order,sizes,heights,enabled}=previous);previous=null;apply();save();undo.hidden=true;});
    const actions=document.createElement('div');actions.className='overview-dashboard-actions';customize.replaceWith(actions);actions.append(customize,reset,undo);
    const phrases = [
        ['Your lab. Your rules.','Dein Lab. Deine Spielregeln.'],
        ['Make room for the next good idea.','Platz für die nächste gute Idee.'],
        ['A little curiosity goes a long way.','Neugier ist ein guter Anfang.'],
        ['What are we building today?','Was bauen wir heute?']
    ];
    const phrase = phrases[Math.floor(Math.random()*phrases.length)];
    const greet = () => {
        const title=document.getElementById('overviewTitle');
        const hour=new Date().getHours();
        const greeting=hour<11?text('Good morning','Guten Morgen'):hour<18?text('Hello','Hallo'):text('Good evening','Guten Abend');
        title.textContent=`${greeting}, ${title.dataset.username}.`;
        document.getElementById('overviewGreetingLine').textContent=text(phrase[0]);
        const today=document.getElementById('overviewToday');today.dateTime=new Date().toISOString();today.textContent=new Date().toLocaleDateString(window.i18n?.currentLang||undefined,{weekday:'long',day:'numeric',month:'long'});
        customize.textContent=text(editing?'Done':'Customize dashboard',editing?'Fertig':'Dashboard anpassen');
        for(const update of labels)update();
    };
    greet();window.addEventListener('languageChanged',greet);
})();
