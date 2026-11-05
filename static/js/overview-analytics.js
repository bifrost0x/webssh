(function(root,factory){
    const api=factory(root);
    if(typeof module==='object'&&module.exports)module.exports=api;
    if(root?.document){root.OverviewAnalytics=api;api.init();}
}(typeof globalThis!=='undefined'?globalThis:this,function(root){
    'use strict';
    const outcomes=['succeeded','failed','unknown','other'];
    function dayKey(date){return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`;}
    function summarize(runs,days=7,now=new Date()){
        days=days===14?14:7;
        const bins=Array.from({length:days},(_,index)=>{
            const date=new Date(now.getFullYear(),now.getMonth(),now.getDate()-days+1+index);
            return {key:dayKey(date),date,counts:{succeeded:0,failed:0,unknown:0,other:0},runs:[]};
        });
        const byDay=new Map(bins.map(bin=>[bin.key,bin]));
        let available=0;
        for(const run of Array.isArray(runs)?runs:[]){
            const date=new Date(run.created_at);
            if(Number.isNaN(date.getTime()))continue;
            available++;
            const bin=byDay.get(dayKey(date));
            if(!bin)continue;
            bin.runs.push(run);
            bin.counts[outcomes.includes(run.outcome)?run.outcome:'unknown']++;
        }
        return {bins,available,total:bins.reduce((sum,bin)=>sum+bin.runs.length,0),maximum:Math.max(1,...bins.map(bin=>bin.runs.length))};
    }
    function init(){
        const document=root.document;
        const mount=document.getElementById('overviewAnalytics');
        if(!mount||mount.dataset.initialized)return;
        mount.dataset.initialized='true';
        let period=7, selected=null, signature='';
        const revealObserver=root.IntersectionObserver?new root.IntersectionObserver(entries=>{
            entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('is-visible');revealObserver.unobserve(entry.target);}});
        },{threshold:0.15}):null;
        let snapshot=root.WebSSHAutomation?.getRunSnapshot?.()||{enabled:false,runs:[]};
        const tr=(key,values)=>root.AutomationText?.t(key,values)||key;
        const node=(tag,text,cls)=>{const element=document.createElement(tag);if(text!==undefined)element.textContent=text;if(cls)element.className=cls;return element;};
        function render(){
            const focus=document.activeElement;
            const focusKey=mount.contains(focus)?focus.dataset.analyticsFocus:null;
            const restoreFocus=()=>{
                if(!focusKey)return;
                const controls=[...mount.querySelectorAll('[data-analytics-focus]')];
                const target=controls.find(element=>element.dataset.analyticsFocus===focusKey)
                    ||controls.find(element=>element.dataset.analyticsFocus===selected)
                    ||controls.find(element=>element.dataset.analyticsFocus==='period');
                target?.focus({preventScroll:true});
            };
            mount.hidden=!snapshot.enabled;
            revealObserver?.disconnect();
            mount.replaceChildren();
            if(!snapshot.enabled)return;
            mount.className='overview-analytics';
            const model=summarize(snapshot.runs,period);
            if(selected&&!model.bins.some(bin=>bin.key===selected))selected=null;
            const header=node('header');
            const title=node('div');title.append(node('h2',tr('analyticsTitle')),node('p',tr('analyticsSubtitle')));
            const label=node('label',tr('analyticsPeriod'));
            const select=node('select');select.dataset.analyticsFocus='period';
            [7,14].forEach(days=>{const option=node('option',tr('analyticsDays',{days}));option.value=days;select.append(option);});
            select.value=String(period);select.addEventListener('change',()=>{period=Number(select.value);render();});
            label.append(select);header.append(title,label);mount.append(header);
            const scope=node('p',tr('analyticsScope',{count:model.available}),'overview-analytics-scope');mount.append(scope);
            if(snapshot.stale){const warning=node('p',tr('runsStale'),'overview-analytics-notice');warning.setAttribute('role','status');mount.append(warning);}
            if(!snapshot.loaded){mount.append(node('p',tr(snapshot.stale?'analyticsError':'hostRunsLoading')));restoreFocus();return;}
            if(!model.available){mount.append(node('p',tr('noRuns'),'overview-analytics-empty'));restoreFocus();return;}
            const totals=outcomes.map(outcome=>({outcome,count:model.bins.reduce((sum,bin)=>sum+bin.counts[outcome],0)}));
            const summary=node('div',undefined,'overview-analytics-summary');
            const total=node('div');total.append(node('strong',String(model.total)),node('span',tr('analyticsRuns',{days:period})));summary.append(total);
            const legend=node('ul',undefined,'overview-analytics-legend');
            totals.forEach(({outcome,count})=>{const item=node('li');item.dataset.outcome=outcome;item.append(node('i'),node('span',`${tr('analyticsOutcome.'+outcome)} ${count}`));legend.append(item);});summary.append(legend);mount.append(summary);
            const chart=node('div',undefined,'overview-analytics-chart');chart.setAttribute('aria-label',tr('analyticsSubtitle'));
            model.bins.forEach(bin=>{
                const dateLabel=bin.date.toLocaleDateString(root.i18n?.getLanguage?.()||[],{day:'numeric',month:'short'});
                const button=node('button',undefined,'overview-analytics-day');button.type='button';button.dataset.analyticsFocus=bin.key;
                button.setAttribute('aria-pressed',String(selected===bin.key));
                button.setAttribute('aria-label',`${dateLabel}: ${outcomes.map(outcome=>`${tr('analyticsOutcome.'+outcome)} ${bin.counts[outcome]}`).join(', ')}`);
                const count=node('span',String(bin.runs.length),'overview-analytics-day-count');
                const track=node('span',undefined,'overview-analytics-track');track.setAttribute('aria-hidden','true');
                outcomes.forEach(outcome=>{if(!bin.counts[outcome])return;const bar=node('span',undefined,'overview-analytics-segment');bar.dataset.outcome=outcome;bar.style.height=`${bin.counts[outcome]/model.maximum*100}%`;track.append(bar);});
                button.append(count,track,node('span',dateLabel,'overview-analytics-date'));
                button.addEventListener('click',()=>{selected=selected===bin.key?null:bin.key;render();});chart.append(button);
            });mount.append(chart);
            if(revealObserver)revealObserver.observe(chart);else chart.classList.add('is-visible');
            if(selected){
                const bin=model.bins.find(bin=>bin.key===selected);
                const result=node('section',undefined,'overview-analytics-selection');
                const heading=node('div');heading.append(node('h3',bin.date.toLocaleDateString(root.i18n?.getLanguage?.()||[],{year:'numeric',month:'long',day:'numeric'})));
                const clear=node('button',tr('analyticsClear'),'btn btn-secondary');clear.type='button';clear.dataset.analyticsFocus='clear';clear.onclick=()=>{const previous=selected;selected=null;render();[...mount.querySelectorAll('[data-analytics-focus]')].find(element=>element.dataset.analyticsFocus===previous)?.focus({preventScroll:true});};heading.append(clear);result.append(heading);
                if(!bin.runs.length)result.append(node('p',tr('analyticsNoDayRuns')));
                bin.runs.forEach(run=>{const button=node('button',undefined,'overview-analytics-run');button.type='button';button.dataset.analyticsFocus='run-'+run.id;button.append(node('strong',run.name),node('span',tr('analyticsOutcome.'+(outcomes.includes(run.outcome)?run.outcome:'unknown'))),node('span',tr('viewRunLog')));button.onclick=()=>root.WebSSHAutomation?.openRun?.(run.id);result.append(button);});
                mount.append(result);
            }
            restoreFocus();
        }
        root.addEventListener('automation-runs-updated',event=>{
            const next=dayKey(new Date())+'|'+JSON.stringify(event.detail);if(next===signature)return;signature=next;snapshot=event.detail;render();
        });
        root.addEventListener('languageChanged',render);
        root.addEventListener('primary-workspace-change',event=>{if(event.detail?.view==='overview')render();});
        render();
    }
    return {summarize,dayKey,init};
}));
