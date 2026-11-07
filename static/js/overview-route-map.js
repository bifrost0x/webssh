/* SSH route map: saved configuration only, separate from live reachability. */
(function () {
    'use strict';
    window.OverviewRouteMap = {create};
    function create({root, model, loaded, hostActions, inspect}) {
        if (!root) return {render() {}};
        const scope = document.querySelector('meta[name="background-scope"]')?.content;
        const key = /^[a-f0-9]{64}$/.test(scope || '') ? 'webssh:route-map:' + scope : null;
        const t = en => window.i18n?.t('overview.ui.' + en.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')) || en;
        const el = (tag, cls, text) => { const n=document.createElement(tag);n.className=cls||'';if(text!==undefined)n.textContent=text;return n; };
        const icon = name => { const n=el('span','material-icons',name);n.setAttribute('aria-hidden','true');return n; };
        const btn = (title, action) => { const n=el('button','',title);n.type='button';n.addEventListener('click',action);return n; };
        let camera=null, expanded=new Set(), fingerprint='', drag=null, frame=0, saveTimer, focusRoute=null;
        const positions=new Map();
        let fullCamera=null,fullCameraMode=null, restoredSize=null, fullSize=null;
        try {
            const raw=key && localStorage.getItem(key), saved=raw && raw.length<300000 ? JSON.parse(raw) : null;
            if(saved?.version===2){
                if(Array.isArray(saved.expanded)) expanded=new Set(saved.expanded.filter(x=>typeof x==='string'&&x.length<1024).slice(0,100));
                if(Array.isArray(saved.positions)) for(const entry of saved.positions.slice(-200)) {
                    if(!Array.isArray(entry)||entry.length!==2)continue;
                    const [id,pos]=entry;
                    if(typeof id==='string'&&id.length<1200&&pos&&[pos.x,pos.y].every(Number.isFinite)&&Math.abs(pos.x)<=10000&&Math.abs(pos.y)<=10000)positions.set(id,pos);
                }
                restoredSize=saved.cameraSize;fullSize=saved.fullSize;
                fullCameraMode=['wide','narrow'].includes(saved.fullCameraMode)?saved.fullCameraMode:null;
                const f=saved.fullCamera;
                if(f&&[f.x,f.y,f.scale].every(Number.isFinite)&&Math.abs(f.x)<100000&&Math.abs(f.y)<100000&&f.scale>=.01&&f.scale<=2)fullCamera=f;
                const c=saved.camera;
                if(saved.presentation==='route-summary' && c && [c.x,c.y,c.scale].every(Number.isFinite) && Math.abs(c.x)<100000 && Math.abs(c.y)<100000 && c.scale>=.01 && c.scale<=2)camera=c;
            }
        } catch { /* Optional browser preferences. */ }
        const arrangement = () => JSON.stringify([[...positions],[...expanded]]);
        const viewportSize = () => ({width:viewport.clientWidth,height:viewport.clientHeight,mode:positionMode()});
        const sameSize = size => size && size.mode===positionMode() && Math.abs(size.width-viewport.clientWidth)<2 && Math.abs(size.height-viewport.clientHeight)<2;
        function save(){
            try{if(key)localStorage.setItem(key,JSON.stringify({
                version:2,presentation:'route-summary',
                camera:dialog.open?(homeArrangement===arrangement()?homeCamera:null):camera,
                cameraSize:dialog.open?homeSize:viewportSize(),
                fullCamera:dialog.open?camera:fullCamera,
                fullSize:dialog.open?viewportSize():fullSize,
                fullCameraMode:dialog.open?positionMode():fullCameraMode,
                expanded:[...expanded].slice(-100),positions:[...positions].slice(-200)
            }));}catch{/* Keep navigation available. */}
        }

        const heading=el('div','ssh-map-heading'),title=el('h2'),count=el('span','ssh-map-count');
        heading.append(title,count);
        const toolbar=el('div','ssh-map-toolbar');
        const search=el('input');search.type='search';search.autocomplete='off';
        const minus=btn('−',()=>zoom(1/1.2)),plus=btn('+',()=>zoom(1.2)),fitButton=btn('',()=>fit()),percent=el('output');
        const resetButton=btn('',()=>{const prefix=positionMode()+':';for(const id of positions.keys())if(id.startsWith(prefix))positions.delete(id);applyPositions();camera=null;layout();save();});
        resetButton.className='ssh-map-reset';resetButton.hidden=true;
        toolbar.append(search,minus,percent,plus,fitButton,resetButton);
        const viewport=el('div','ssh-route-viewport');viewport.tabIndex=0;
        const canvas=el('div','ssh-route-canvas');viewport.append(canvas);
        const note=el('p','ssh-map-note');
        const expandButton=btn('',()=>setExpanded(!dialog.open));
        const dialog=el('dialog','ssh-map-dialog');dialog.setAttribute('aria-label',t('SSH routes'));document.body.append(dialog);
        let homeCamera=null, homeArrangement=null, homeSize=null;
        function setExpanded(open){
            if(open){homeSize=viewportSize();homeArrangement=arrangement();homeCamera=camera?{...camera}:null;dialog.append(root);dialog.showModal();camera=fullCamera&&fullCameraMode===positionMode()&&sameSize(fullSize)?{...fullCamera}:null;}
            else{fullSize=viewportSize();fullCamera=camera?{...camera}:null;fullCameraMode=positionMode();dialog.close();home.append(root);camera=homeArrangement===arrangement()&&sameSize(homeSize)?homeCamera:null;}
            root.classList.toggle('is-summary',!open);for(const control of [minus,plus,fitButton,percent])control.hidden=!open;fingerprint='';render();
            resetButton.hidden=!open;applyPositions();previousWidth=viewport.clientWidth;previousHeight=viewport.clientHeight;
            expandButton.textContent=open?t('Close map','Karte schließen'):t('Expand map','Karte vergrößern');
            layout();save();expandButton.focus();
        }
        const home=root.parentNode;
        dialog.addEventListener('cancel',e=>{e.preventDefault();setExpanded(false);});
        heading.append(expandButton);
        root.addEventListener('click',e=>{if(dialog.open&&e.target.closest('.overview-host-actions'))setExpanded(false);},true);
        root.append(heading,toolbar,viewport,note);root.classList.add('is-summary');for(const control of [minus,plus,fitButton,percent])control.hidden=true;
        function positionMode(){return window.innerWidth<600?'narrow':'wide';}
        function applyPositions(){
            canvas.querySelectorAll('[data-map-node]').forEach(node=>{
                const pos=positions.get(positionMode()+':'+node.dataset.mapNode);
                node.style.transform=dialog.open&&pos?`translate(${pos.x}px,${pos.y}px)`:'';
                const handle=node.querySelector(':scope > .ssh-node-drag');if(handle)handle.hidden=!dialog.open;
            });
        }
        function movable(node,id,label){
            node.dataset.mapNode=id;
            const handle=btn('',()=>{});handle.className='ssh-node-drag';handle.append(icon('drag_indicator'));
            handle.setAttribute('aria-label',t('Move ','Verschieben: ')+label);handle.title=t('Drag to arrange; arrow keys to move','Ziehen zum Anordnen; Pfeiltasten zum Verschieben');handle.hidden=!dialog.open;
            node.prepend(handle);
            let moving=null;
            const update=(x,y)=>{
                const pos={x:Math.max(-10000,Math.min(10000,x)),y:Math.max(-10000,Math.min(10000,y))};
                positions.set(positionMode()+':'+id,pos);node.style.transform=`translate(${pos.x}px,${pos.y}px)`;edges();
            };
            handle.addEventListener('pointerdown',e=>{
                if(!dialog.open||e.button!==0||!camera)return;
                e.preventDefault();e.stopPropagation();
                const start=positions.get(positionMode()+':'+id)||{x:0,y:0};
                moving={pointer:e.pointerId,x:e.clientX,y:e.clientY,start:{...start},scale:camera.scale};
                handle.setPointerCapture(e.pointerId);node.classList.add('is-moving');
            });
            handle.addEventListener('pointermove',e=>{if(!moving||moving.pointer!==e.pointerId)return;e.stopPropagation();update(moving.start.x+(e.clientX-moving.x)/moving.scale,moving.start.y+(e.clientY-moving.y)/moving.scale);});
            const finish=e=>{if(!moving)return;e.stopPropagation();if(e.type==='pointercancel')update(moving.start.x,moving.start.y);moving=null;node.classList.remove('is-moving');save();};
            for(const type of ['pointerup','pointercancel','lostpointercapture'])handle.addEventListener(type,finish);
            handle.addEventListener('keydown',e=>{
                const delta={ArrowLeft:[-20,0],ArrowRight:[20,0],ArrowUp:[0,-20],ArrowDown:[0,20]}[e.key];
                if(!delta||!dialog.open)return;e.preventDefault();e.stopPropagation();
                const old=positions.get(positionMode()+':'+id)||{x:0,y:0};update(old.x+delta[0],old.y+delta[1]);save();
            });
        }
        function paint(){
            if(!camera)return;
            if(!dialog.open){canvas.style.transform='';canvas.dataset.scale='1';return;}
            canvas.style.transform=`translate(${camera.x}px,${camera.y}px) scale(${camera.scale})`;
            canvas.dataset.scale=String(camera.scale);
            percent.textContent=Math.round(camera.scale*100)+'%';
            clearTimeout(saveTimer);saveTimer=setTimeout(save,180);
        }
        function fit(){
            if(!dialog.open){camera={x:0,y:0,scale:1};paint();return;}
            if(!viewport.clientWidth || !canvas.offsetWidth)return;
            const box=canvas.getBoundingClientRect(),oldScale=Number.parseFloat(canvas.dataset.scale)||1;
            const rects=[...canvas.querySelectorAll('[data-map-node]')].map(n=>n.getBoundingClientRect());
            const left=rects.length?Math.min(...rects.map(r=>(r.left-box.left)/oldScale)):0;
            const top=rects.length?Math.min(...rects.map(r=>(r.top-box.top)/oldScale)):0;
            const right=rects.length?Math.max(...rects.map(r=>(r.right-box.left)/oldScale)):canvas.offsetWidth;
            const bottom=rects.length?Math.max(...rects.map(r=>(r.bottom-box.top)/oldScale)):canvas.offsetHeight;
            const width=right-left,height=bottom-top;
            const scale=Math.max(.01,Math.min(1,(viewport.clientWidth-32)/width,(viewport.clientHeight-32)/height));
            camera={scale,x:Math.max(16,(viewport.clientWidth-width*scale)/2)-left*scale,y:Math.max(16,(viewport.clientHeight-height*scale)/2)-top*scale};
            paint();
        }
        function zoom(factor,center={x:viewport.clientWidth/2,y:viewport.clientHeight/2}){
            if(!camera)return;
            const scale=Math.max(.01,Math.min(2,camera.scale*factor)),ratio=scale/camera.scale;
            camera={scale,x:center.x-(center.x-camera.x)*ratio,y:center.y-(center.y-camera.y)*ratio};paint();
        }
        function edges(){
            const svg=canvas.querySelector(':scope > svg');if(!svg)return;
            svg.replaceChildren();
            const box=canvas.getBoundingClientRect(),scale=dialog.open?(camera?.scale||1):1;
            function connect(a,b){
                const x=a.getBoundingClientRect(),y=b.getBoundingClientRect();
                const vertical=window.innerWidth<600||(!dialog.open&&viewport.clientWidth<620);
                const sx=(vertical?x.left+x.width/2-box.left:x.right-box.left)/scale,sy=(vertical?x.bottom-box.top:x.top+x.height/2-box.top)/scale;
                const tx=(vertical?y.left+y.width/2-box.left:y.left-box.left)/scale,ty=(vertical?y.top-box.top:y.top+y.height/2-box.top)/scale;
                const path=document.createElementNS('http://www.w3.org/2000/svg','path');
                path.setAttribute('d',vertical?`M ${sx} ${sy} C ${sx} ${(sy+ty)/2}, ${tx} ${(sy+ty)/2}, ${tx} ${ty} m -4 -6 l 4 6 l 4 -6`:`M ${sx} ${sy} C ${(sx+tx)/2} ${sy}, ${(sx+tx)/2} ${ty}, ${tx} ${ty} m -6 -4 l 6 4 l -6 4`);
                if(vertical && a===server && b.classList.contains('ssh-route-source')) {
                    const left=(x.left-box.left)/scale,top=(x.top+x.height/2-box.top)/scale;
                    const end=(y.left-box.left)/scale,level=(y.top+y.height/2-box.top)/scale;
                    path.setAttribute('d',`M ${left} ${top} H 6 V ${level} H ${end} m -6 -4 l 6 4 l -6 4`);
                }
                svg.append(path);
            }
            const server=canvas.querySelector('.ssh-map-server');
            canvas.querySelectorAll('.ssh-route-branch').forEach(branch=>{
                const source=branch.querySelector('.ssh-route-source');
                const target=branch.querySelector('.ssh-route-destinations');
                if(source){connect(server,source);connect(source,target);}else connect(server,target);
            });
        }
        function layout(){cancelAnimationFrame(frame);frame=requestAnimationFrame(()=>{if(!root.getClientRects().length||!loaded()||!canvas.querySelector('[data-map-node]'))return;applyPositions();if(restoredSize){if(!sameSize(restoredSize))camera=null;restoredSize=null;}if(!camera)fit();else paint();
                if(dialog.open&&focusRoute){
                    const target=[...canvas.querySelectorAll('[data-map-node]')].find(n=>n.dataset.mapNode===focusRoute);
                    focusRoute=null;
                    if(target){
                        const base=canvas.getBoundingClientRect(),rect=target.getBoundingClientRect(),oldScale=Number(canvas.dataset.scale)||1;
                        const x=(rect.left-base.left)/oldScale,y=(rect.top-base.top)/oldScale;
                        const scale=Math.max(.01,Math.min(1,(viewport.clientWidth-32)/(rect.width/oldScale),(viewport.clientHeight-32)/(rect.height/oldScale)));
                        camera={scale,x:(viewport.clientWidth-rect.width/oldScale*scale)/2-x*scale,y:(viewport.clientHeight-rect.height/oldScale*scale)/2-y*scale};paint();
                    }
                }
                edges();});}
        function render(){
            title.textContent=t('SSH routes','SSH-Verbindungen');
            search.placeholder=t('Find a host or jump host…','Host oder Jump Host suchen…');search.setAttribute('aria-label',t('Search SSH routes','SSH-Verbindungen durchsuchen'));
            minus.setAttribute('aria-label',t('Zoom out SSH routes','SSH-Karte verkleinern'));plus.setAttribute('aria-label',t('Zoom in SSH routes','SSH-Karte vergrößern'));
            fitButton.textContent=t('Fit map','Karte einpassen');
            resetButton.textContent=t('Reset arrangement','Anordnung zurücksetzen');
            expandButton.textContent=dialog.open?t('Close map','Karte schließen'):t('Expand map','Karte vergrößern');
            viewport.setAttribute('aria-label',dialog.open?t('SSH route map. Drag to pan; scroll to zoom.','SSH-Karte. Ziehen zum Verschieben, Mausrad zum Zoomen.'):t('SSH routes. Choose a route to view its hosts.','SSH-Wege. Verbindung auswählen, um die Hosts anzuzeigen.'));
            note.textContent=t('Saved SSH routes · not a reachability check','Gespeicherte SSH-Wege · keine Erreichbarkeitsprüfung');
            if(!loaded()){count.textContent='';canvas.replaceChildren(el('p','ssh-map-empty',t('Loading hosts…','Hosts werden geladen…')));fingerprint='';return;}
            const all=model(),query=search.value.trim().toLocaleLowerCase();
            const hosts=all.filter(h=>!query || [h.name,h.group,h.jump?.name||''].join(' ').toLocaleLowerCase().includes(query));
            count.textContent=hosts.length+' / '+all.length+' '+t('hosts');
            const signature=JSON.stringify([hosts,query,[...expanded],window.i18n?.currentLang,dialog.open]);
            if(signature===fingerprint){layout();return;}fingerprint=signature;
            const focused=document.activeElement?.dataset.sshMapFocus;
            const branches=new Map();
            for(const h of hosts){
                const id=h.route==='none'?'direct':h.route+':'+h.routeRef;
                if(!branches.has(id))branches.set(id,{sample:h,groups:new Map()});
                const groups=branches.get(id).groups;if(!groups.has(h.group))groups.set(h.group,[]);groups.get(h.group).push(h);
            }
            canvas.replaceChildren();
            const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('aria-hidden','true');
            const server=el('div','ssh-map-server');server.append(icon('terminal'),el('strong','','WebSSH'));
            const lanes=el('div','ssh-route-lanes');movable(server,'server','WebSSH');canvas.append(svg,server,lanes);
            for(const [id,{sample,groups}] of branches){
                const branch=el('section','ssh-route-branch');branch.dataset.route=id;
                const direct=sample.route==='none';
                const sourceName=direct?t('Direct SSH','Direktes SSH'):sample.jump?.name||t('Unresolved jump host','Ungeklärter Jump Host');
                if(!direct){
                    const source=el('div','ssh-route-source');source.append(icon('vpn_key'),el('strong','',sourceName),el('small','',window.i18n.t('connection.jumpHost')));movable(source,id+':gateway',sourceName);branch.append(source);
                }
                const items=[...groups.values()].flat(), destinations=el('div','ssh-route-destinations');
                const header=el('div','ssh-destination-heading');header.append(el('strong','',direct?t('Direct connections','Direkte Verbindungen'):t('Via ','Über ')+sourceName),el('span','',items.length+' '+t('hosts')));destinations.append(header);movable(destinations,id+':hosts',direct?t('Direct connections','Direkte Verbindungen'):t('Via ','\u00dcber ')+sourceName);
                const groupKey=id;
                if(!dialog.open){
                    const summary=btn('',()=>{expanded.add(groupKey);focusRoute=id+':hosts';setExpanded(true);});
                    summary.className='ssh-route-summary';
                    summary.append(el('strong','',String(items.length)),el('span','',t('hosts','Hosts')),icon('arrow_forward'));
                    summary.setAttribute('aria-label',t('Show hosts: ','Hosts anzeigen: ')+sourceName);
                    destinations.append(summary);
                    const names=[...groups.keys()].map(g=>g||t('Ungrouped','Ohne Gruppe'));
                    const groupLabels=el('div','ssh-summary-groups',names.slice(0,2).join(' · ')+(names.length>2?' +'+(names.length-2):''));groupLabels.title=names.join(', ');destinations.append(groupLabels);
                    branch.append(destinations);lanes.append(branch);continue;
                }
                const visible=query||expanded.has(groupKey)?items:items.slice(0,2);
                const hostList=el('div','ssh-route-host-list');destinations.append(hostList);
                hostList.addEventListener('wheel',e=>{if(hostList.scrollHeight>hostList.clientHeight)e.stopPropagation();},{passive:true});
                for(const host of visible){
                    const row=el('div','ssh-route-host');row.dataset.sshMapHost=host.id;
                    const target=btn('',()=>{if(dialog.open)setExpanded(false);inspect(host);});target.className='ssh-route-target';target.dataset.sshMapFocus=host.id;target.setAttribute('aria-label',t('Inspect ','Ansehen: ')+host.name);
                    const label=el('span','ssh-host-label');label.append(el('strong','',host.name),el('small','',host.group||t('Ungrouped','Ohne Gruppe')));
                    target.append(window.HostPlatform?.render(host.platform,document)||icon('dns'),label);row.append(target,hostActions(host,'route-map'));hostList.append(row);
                }
                if(items.length>2&&!query){
                    const more=btn(expanded.has(groupKey)?t('Show less','Weniger anzeigen'):t('Show all ','Alle anzeigen: ')+items.length,()=>{if(expanded.has(groupKey))expanded.delete(groupKey);else expanded.add(groupKey);save();render();});
                    more.className='ssh-route-more';more.setAttribute('aria-label',t('Show hosts: ','Hosts anzeigen: ')+sourceName);more.dataset.sshMapFocus=groupKey;more.setAttribute('aria-expanded',String(expanded.has(groupKey)));destinations.insertBefore(more,hostList);
                }
                branch.append(destinations);lanes.append(branch);
            }
            if(!hosts.length)canvas.append(el('p','ssh-map-empty',t('No matching hosts','Keine passenden Hosts')));
            layout();
            if(focused){const target=[...canvas.querySelectorAll('[data-ssh-map-focus]')].find(n=>n.dataset.sshMapFocus===focused);target?.focus({preventScroll:true});}
        }
        search.addEventListener('input',()=>{camera=null;render();});
        viewport.addEventListener('wheel',e=>{if(!dialog.open)return;e.preventDefault();const r=viewport.getBoundingClientRect();zoom(Math.exp(-Math.max(-100,Math.min(100,e.deltaY))*.002),{x:e.clientX-r.left,y:e.clientY-r.top});},{passive:false});
        viewport.addEventListener('pointerdown',e=>{if(!dialog.open||e.button!==0||!camera||e.target.closest('button,input,a,select'))return;drag={id:e.pointerId,x:e.clientX,y:e.clientY,start:{...camera}};viewport.setPointerCapture(e.pointerId);viewport.dataset.dragging='true';});
        viewport.addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId)return;camera={...camera,x:drag.start.x+e.clientX-drag.x,y:drag.start.y+e.clientY-drag.y};paint();});
        const end=()=>{drag=null;delete viewport.dataset.dragging;save();};
        for(const event of ['pointerup','pointercancel','lostpointercapture'])viewport.addEventListener(event,end);
        viewport.addEventListener('keydown',e=>{
            if(!dialog.open||e.target!==viewport||!camera)return;
            const shift={ArrowLeft:[60,0],ArrowRight:[-60,0],ArrowUp:[0,60],ArrowDown:[0,-60]}[e.key];
            if(shift){e.preventDefault();camera.x+=shift[0];camera.y+=shift[1];paint();}
            else if(['+','=','-','0'].includes(e.key)){e.preventDefault();if(e.key==='0')fit();else zoom(e.key==='-'?1/1.2:1.2);}
        });
        viewport.addEventListener('focusin',e=>{
            if(!dialog.open||e.target===viewport||!camera||!e.target.matches(':focus-visible'))return;
            const v=viewport.getBoundingClientRect(),r=e.target.getBoundingClientRect();
            if(r.left<v.left||r.right>v.right||r.top<v.top||r.bottom>v.bottom){camera.x+=v.left+v.width/2-r.left-r.width/2;camera.y+=v.top+v.height/2-r.top-r.height/2;paint();}
        });
        let previousWidth=0,previousHeight=0,previousMode=positionMode();
        new ResizeObserver(()=>{
            const width=viewport.clientWidth;
            const height=viewport.clientHeight,mode=positionMode();
            if(width&&height&&previousWidth&&(Math.abs(width-previousWidth)>1||Math.abs(height-previousHeight)>1||mode!==previousMode))camera=null;
            if(height)previousHeight=height;previousMode=mode;
            if(width)previousWidth=width;
            layout();
        }).observe(viewport);
        window.addEventListener('pagehide',save);
        return {render};
    }
})();
