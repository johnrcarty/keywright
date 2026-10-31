/* Page state, camera, input and snapshot refresh. Discovery remains server-owned. */
(()=>{
'use strict';
const $=id=>document.getElementById(id),T=KeywrightTopology,V=KeywrightTopologyView;
let graph=JSON.parse($('net-data').textContent),loadedAt=Date.now(),busy=false,lastAttempt=0;
if(!graph.sources.length){$('net-freshness').textContent='No controller connected';return;}
const surface=$('network-svg'),scene=$('net-scene'),renderer=new V.Renderer(scene);
const ui={expanded:new Set(),pages:new Map(),selected:'',branch:'',status:''};
let mobile=matchMedia('(max-width: 700px)').matches,model,geometry,layoutKey='',camera={x:0,y:0,s:1},size={w:1,h:1};
let returnFocus=null,searchTimer=0,animation=0;
const date=v=>v?new Date(v).toLocaleString():'Not yet collected';
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function button(text,action,cls='btn'){const b=el('button',text,cls);b.type='button';b.onclick=action;return b;}
function error(message){$('net-error').textContent=message;$('net-error').hidden=!message;}
function setCamera(next){camera=next;scene.setAttribute('transform',`translate(${camera.x} ${camera.y}) scale(${camera.s})`);$('net-scale').textContent=Math.round(camera.s*100)+'%';}
function moveCamera(next,animate=false){
 cancelAnimationFrame(animation);
 if(!animate||matchMedia('(prefers-reduced-motion: reduce)').matches){setCamera(next);return;}
 const start={...camera},at=performance.now();
 function frame(now){const t=Math.min(1,(now-at)/180),ease=1-(1-t)**3;setCamera({x:start.x+(next.x-start.x)*ease,y:start.y+(next.y-start.y)*ease,s:start.s+(next.s-start.s)*ease});if(t<1)animation=requestAnimationFrame(frame);}
 animation=requestAnimationFrame(frame);
}
function focusBounds(b,animate=true){
 // Automatic camera operations never shrink labels below their designed size.
 const s=Math.max(1,Math.min(1.15,(size.w-24)/b.width,(size.h-32)/b.height));
 const x=size.w/2-(b.x+b.width/2)*s;
 const y=b.height*s>size.h-32?16-b.y*s:size.h/2-(b.y+b.height/2)*s;
 moveCamera({x,y,s},animate);
 $('net-view-note').textContent=b.width*s>size.w||b.height*s>size.h?'Pan to explore · labels stay at readable size':'Drag to pan · pinch or use + / − to zoom';
}
function zoom(factor,anchor={x:size.w/2,y:size.h/2}){
 const s=Math.max(.45,Math.min(4,camera.s*factor)),ratio=s/camera.s;
 moveCamera({s,x:anchor.x-(anchor.x-camera.x)*ratio,y:anchor.y-(anchor.y-camera.y)*ratio});
}
function rebuild(force=false){
 model=T.normalize(graph,$('net-site').value);
 for(const id of ui.expanded)if(!model.groups.has(id))ui.expanded.delete(id);
 if(ui.selected&&!model.nodes.has(ui.selected)&&!model.groups.has(ui.selected))ui.selected='';
 if(ui.branch&&!model.groups.has(ui.branch)){ui.branch='';closeDetails(false);}
 const key=JSON.stringify([model.signature,mobile,[...ui.expanded].sort(),[...ui.pages].sort()]);
 if(force||key!==layoutKey){geometry=T.layout(model,{mobile,...ui});layoutKey=key;}
 renderer.draw(model,geometry,ui);branchBar();counts();deviceList();searchResults(false);
 $('net-map-empty').hidden=!!model.nodes.size;
 if(!$('net-details').hidden&&ui.selected)details(ui.selected,false);
}
function defaults(){
 ui.expanded.clear();ui.pages.clear();ui.branch='';ui.selected='';closeDetails(false);rebuild(true);
 // Expand only clusters that fit comfortably; dense networks keep an honest overview.
 if(!mobile){for(const [id,g] of model.groups){if(!g.clients.length)continue;ui.expanded.add(id);const trial=T.layout(model,{mobile,...ui});if(trial.bounds.width>size.w-32||trial.bounds.height>size.h-32)ui.expanded.delete(id);}rebuild();}
 focusBounds(geometry.bounds,false);
}
function overview(){ui.expanded.clear();ui.branch='';ui.selected='';closeDetails(false);rebuild();focusBounds(geometry.bounds);}
function branchBar(){
 const group=model.groups.get(ui.branch),bar=$('net-branch');bar.hidden=!group;
 if(!group){$('net-path').textContent='Infrastructure overview · select a switch or AP to explore';return;}
 const block=geometry.blocks.get(ui.branch),total=block.total;
 $('net-branch-name').textContent=group.node.name;
 $('net-page').textContent=total?(ui.expanded.has(ui.branch)?`${block.page*block.pageSize+1}–${Math.min(total,(block.page+1)*block.pageSize)} of ${total} clients`:`${total} clients collapsed`):'No directly connected clients';
 $('net-prev').disabled=!ui.expanded.has(ui.branch)||block.page===0;
 $('net-next').disabled=!ui.expanded.has(ui.branch)||(block.page+1)*block.pageSize>=total;
 $('net-collapse').disabled=!total;$('net-collapse').textContent=ui.expanded.has(ui.branch)?'Collapse clients':'Expand clients';
 $('net-show-details').disabled=group.synthetic;
 const path=[],seen=new Set();let id=ui.selected||ui.branch;
 while(id&&!seen.has(id)){seen.add(id);path.unshift(model.nodes.get(id)?.name||model.groups.get(id)?.node.name||'Unknown');id=model.groupOf.get(id)||model.parent.get(id);}
 $('net-path').textContent=path.join(' › ');
}
function select(id,showDetails=false){
 if(!model.nodes.has(id)&&!model.groups.has(id))return;
 ui.selected=id;const group=model.groups.has(id)?id:model.groupOf.get(id);ui.branch=group||'';
 if(group){
  ui.expanded.add(group);
  if(group!==id)ui.pages.set(group,Math.floor(model.groups.get(group).clients.indexOf(id)/(mobile?8:10)));
 }
 rebuild();
 const rect=geometry.positions.get(id);
 focusBounds(group===id?geometry.clusterBounds.get(id):rect||geometry.bounds);
 if(group!==id||showDetails)details(id,true);else closeDetails(false);
}
function closeDetails(restore=true){$('net-details').hidden=true;if(restore&&returnFocus?.isConnected)returnFocus.focus({preventScroll:true});}
function revealAboveSheet(id){
 if(!matchMedia('(max-width: 900px)').matches||$('net-details').hidden)return;
 const p=geometry.positions.get(id);if(!p)return;
 const canvas=surface.getBoundingClientRect(),sheet=$('net-details').getBoundingClientRect();
 const top=Math.max(canvas.top,document.querySelector('.site-header')?.getBoundingClientRect().bottom||0);
 const bottom=Math.min(canvas.bottom,sheet.top-12);
 if(bottom-top>80)moveCamera({...camera,y:(top+bottom)/2-canvas.top-(p.y+p.height/2)*camera.s});
}
function details(id,focus){
 const n=model.nodes.get(id);if(!n)return;
 const box=$('net-details');box.hidden=false;$('net-detail-title').textContent=n.name;
 const body=$('net-detail-body');body.replaceChildren(el('p',n.virtual?'Recorded connection · not monitored':V.states[n.state]||'Unknown','pill'));
 const dl=el('dl');
 const fields=[['Connected to',n.attachment_label||'Not reported'],['Connection source',n.attachment_source||'Not reported'],['Connection',n.hub&&n.medium==='wifi'?'Mesh Wi-Fi':({wifi:'Wi-Fi',wired:'Wired'})[n.medium]||'Unspecified'],['Port / SSID',n.port||'Not reported'],['IP address',n.addresses.join(', ')||'Not reported'],['MAC',n.mac||'Not reported'],['Site',n.site||n.site_id||'Not reported'],['Device',n.model||n.role],['Last observed',date(n.last_observed)],['First observed',date(n.first_observed)],['Source state',n.source_status||'Unknown']];
 for(const [key,value] of fields)dl.append(el('dt',key),el('dd',value));body.append(dl);
 if(n.uplink_note&&!n.attachment)body.append(el('p',n.uplink_note,'help'));
 if(n.missing)body.append(el('p','Absent from the latest successful refresh. This is its last recorded connection.','help'));
 if(n.unreviewed)body.append(el('p','Unreviewed in inventory. DHCP reservation status is unknown.','help'));
 for(const [url,label] of [[n.review_url,'Review observation'],[n.asset_url,'Open inventory record']])if(url?.startsWith('/ui/')){const a=el('a',label,'btn');a.href=url;body.append(a);}
 if(focus){returnFocus=renderer.nodeElements.get(id)||document.activeElement;$('net-detail-close').focus({preventScroll:true});requestAnimationFrame(()=>revealAboveSheet(id));}
}
function matches(n,q){return [n.name,n.mac,...n.addresses,n.port,n.site,n.model].join(' ').toLowerCase().includes(q);}
function statusMatch(n){return !ui.status||ui.status==='unreviewed'&&n.unreviewed||ui.status==='inactive'&&['inactive','missing'].includes(n.state)||ui.status==='unknown'&&['unknown','stale'].includes(n.state)||n.state===ui.status;}
function counts(){
 const ns=[...model.nodes.values()].filter(n=>!n.virtual),count={};ns.forEach(n=>count[n.state]=(count[n.state]||0)+1);
 const values=[['',ns.length,'All'],['online',count.online||0,'Online'],['inactive',(count.inactive||0)+(count.missing||0),'Inactive / missing'],['old',count.old||0,'24h+'],['unknown',(count.unknown||0)+(count.stale||0),'Unknown / stale'],['unreviewed',ns.filter(n=>n.unreviewed).length,'Unreviewed']];
 const active=document.activeElement?.dataset?.status;
 $('net-counts').replaceChildren(...values.map(([state,value,label])=>{const b=button(`${value} ${label}`,()=>{ui.status=state;renderer.emphasize(model,ui);counts();deviceList();},'net-status-button '+state);b.setAttribute('aria-pressed',String(ui.status===state));b.dataset.status=state;return b;}));
 if(active!==undefined)[...$('net-counts').children].find(n=>n.dataset.status===active)?.focus({preventScroll:true});
}
function deviceList(){
 const q=$('net-search').value.trim().toLowerCase(),nodes=[...model.nodes.values()].filter(n=>matches(n,q)&&statusMatch(n)).sort((a,b)=>a.name.localeCompare(b.name));
 $('net-list-summary').textContent=`Device list · ${nodes.length} matching`;
 const body=$('net-list');body.replaceChildren();
 for(const n of nodes){const row=el('tr'),name=el('td');name.dataset.label='Device';name.append(button(n.name,()=>{select(n.id,true);surface.scrollIntoView({block:'center'});},'net-list-button'));row.append(name);
 for(const [key,value] of [['State',(V.states[n.state]||'Unknown')+(n.unreviewed?' · Unreviewed':'')],['Connected to',n.attachment_label||'Not reported'],['IP address',n.addresses.join(', ')||'—']]){const td=el('td',value);td.dataset.label=key;row.append(td);}body.append(row);}
 $('net-empty-list').hidden=!!nodes.length;
}
function searchResults(auto){
 const q=$('net-search').value.trim().toLowerCase(),box=$('net-search-results');box.replaceChildren();box.hidden=!q;
 if(!q)return;
 const matchesList=[...model.nodes.values()].filter(n=>matches(n,q)).sort((a,b)=>a.name.localeCompare(b.name));
 box.append(el('p',`${matchesList.length} matching devices${matchesList.length>8?' · refine your search or use the device list':''}`,'help'));
 for(const n of matchesList.slice(0,8))box.append(button(n.name,()=>{select(n.id,true);box.hidden=true;surface.scrollIntoView({block:'center'});},'net-search-result'));
 if(auto&&matchesList.length===1){select(matchesList[0].id);box.hidden=true;surface.scrollIntoView({block:'center'});}
}
function sites(){
 const current=$('net-site').value,unique=new Map();graph.nodes.forEach(n=>unique.set(n.site_id,n.site||n.site_id));
 $('net-site').replaceChildren(new Option('All sites',''));[...unique].sort((a,b)=>a[1].localeCompare(b[1])).forEach(([id,name])=>$('net-site').add(new Option(name,id)));
 if(unique.has(current))$('net-site').value=current;
}
function freshness(){
 const elapsed=Date.now()-loadedAt,age=graph.last_success?Math.max(0,new Date(graph.generated_at)-new Date(graph.last_success)+elapsed):Infinity;
 if(graph.fresh&&(age>graph.fresh_seconds*1000||elapsed>graph.fresh_seconds*1000)){graph.fresh=false;graph.nodes.forEach(n=>n.state='stale');rebuild();}
 $('net-freshness').textContent=(graph.fresh?'Current snapshot':'Snapshot not current')+' · Refreshed '+date(graph.last_success)+(graph.configuration_changed?' · Controller configuration changed':'');
}
function accept(data){const empty=!graph.nodes.length;graph=data;loadedAt=Date.now();sites();rebuild();if(empty)defaults();freshness();}
async function readCached(){
 const response=await fetch('/ui/inventory/map/data?source='+encodeURIComponent(graph.source),{headers:{Accept:'application/json'}});
 if(!response.ok||response.redirected)throw new Error('Unable to load observations. Sign in again or reload this page.');accept(await response.json());
}
async function refresh(){
 if(busy||!graph.source)return;busy=true;lastAttempt=Date.now();$('net-refresh').disabled=true;$('net-refresh').textContent='Refreshing…';error('');
 try{
  const response=await fetch('/ui/inventory/map/refresh',{method:'POST',body:new URLSearchParams({resource_id:graph.source}),headers:{Accept:'application/json'}});
  if(response.redirected||!response.headers.get('content-type')?.includes('application/json'))throw new Error('Your session may have expired. Sign in again or reload this page.');
  const data=await response.json();if(data.nodes)accept(data);
  if(!response.ok){if(response.status===409){await readCached();error(data.error);return;}throw new Error(data.error||'Refresh failed. Previous observations have been retained.');}
 }catch(e){error(e.message);if(graph.fresh){graph.fresh=false;graph.nodes.forEach(n=>n.state='stale');rebuild();}freshness();}
 finally{busy=false;$('net-refresh').disabled=false;$('net-refresh').textContent='Refresh now';}
}
// Pointer gestures share one camera. Pinch is anchored to the fingers' midpoint.
const pointers=new Map();let gesture=null,suppressClick=false;
function point(e){const r=surface.getBoundingClientRect();return {x:e.clientX-r.left,y:e.clientY-r.top};}
function beginGesture(){
 const ps=[...pointers.values()];if(!ps.length){gesture=null;return;}
 gesture={camera:{...camera},points:ps.map(p=>({...p})),moved:false};
}
surface.addEventListener('pointerdown',e=>{
 if(e.button!==0)return;cancelAnimationFrame(animation);pointers.set(e.pointerId,point(e));surface.setPointerCapture(e.pointerId);beginGesture();suppressClick=false;
});
surface.addEventListener('pointermove',e=>{
 if(!pointers.has(e.pointerId)||!gesture)return;pointers.set(e.pointerId,point(e));
 const ps=[...pointers.values()],start=gesture.points,c=gesture.camera;
 if(ps.length>=2&&start.length>=2){
  const midpoint=a=>({x:(a[0].x+a[1].x)/2,y:(a[0].y+a[1].y)/2}),a=midpoint(start),b=midpoint(ps);
  const distance=a=>Math.hypot(a[0].x-a[1].x,a[0].y-a[1].y);
  const s=Math.max(.45,Math.min(4,c.s*distance(ps)/Math.max(1,distance(start))));
  setCamera({s,x:b.x-(a.x-c.x)*s/c.s,y:b.y-(a.y-c.y)*s/c.s});gesture.moved=true;suppressClick=true;
 }else{
  const dx=ps[0].x-start[0].x,dy=ps[0].y-start[0].y;
  if(Math.hypot(dx,dy)>4||gesture.moved){gesture.moved=true;suppressClick=true;setCamera({s:c.s,x:c.x+dx,y:c.y+dy});}
 }
});
function endPointer(e){
 if(!pointers.has(e.pointerId))return;
 // Capture retargets pointerup: use hit testing to distinguish a node tap from panning.
 const tap=e.type==='pointerup'&&!suppressClick&&pointers.size===1;
 pointers.delete(e.pointerId);if(surface.hasPointerCapture(e.pointerId))surface.releasePointerCapture(e.pointerId);
 if(tap){const n=document.elementFromPoint(e.clientX,e.clientY)?.closest('[data-action="select"]');if(n)select(n.dataset.id);}
 beginGesture();
}
surface.addEventListener('pointerup',endPointer);surface.addEventListener('pointercancel',endPointer);
surface.addEventListener('lostpointercapture',e=>{pointers.delete(e.pointerId);beginGesture();});
surface.addEventListener('click',e=>{if(e.detail===0){const n=e.target.closest('[data-action="select"]');if(n)select(n.dataset.id);}});
surface.addEventListener('keydown',e=>{
 const node=e.target.closest('[data-action="select"]');
 if(node&&(e.key==='Enter'||e.key===' ')){e.preventDefault();select(node.dataset.id);return;}
 const delta={ArrowLeft:[40,0],ArrowRight:[-40,0],ArrowUp:[0,40],ArrowDown:[0,-40]}[e.key];
 if(delta){e.preventDefault();moveCamera({...camera,x:camera.x+delta[0],y:camera.y+delta[1]});}
 else if(e.key==='+'||e.key==='='){e.preventDefault();zoom(1.2);}else if(e.key==='-'){e.preventDefault();zoom(1/1.2);}
});
surface.addEventListener('wheel',e=>{if(e.ctrlKey||e.metaKey){e.preventDefault();zoom(Math.exp(-e.deltaY*.008),point(e));}},{passive:false});
$('net-zoom-in').onclick=()=>zoom(1.2);$('net-zoom-out').onclick=()=>zoom(1/1.2);
$('net-fit').onclick=()=>focusBounds(ui.branch?geometry.clusterBounds.get(ui.branch):geometry.bounds);
$('net-overview').onclick=overview;$('net-reset').onclick=()=>{ui.status='';$('net-search').value='';defaults();};
$('net-collapse').onclick=()=>{ui.selected=ui.branch;closeDetails(false);if(ui.expanded.has(ui.branch))ui.expanded.delete(ui.branch);else ui.expanded.add(ui.branch);rebuild();focusBounds(geometry.clusterBounds.get(ui.branch));};
function page(delta){const b=geometry.blocks.get(ui.branch);ui.pages.set(ui.branch,b.page+delta);ui.selected=ui.branch;closeDetails(false);rebuild();focusBounds(geometry.clusterBounds.get(ui.branch));}
$('net-prev').onclick=()=>page(-1);$('net-next').onclick=()=>page(1);
$('net-show-details').onclick=()=>{ui.selected=ui.branch;details(ui.branch,true);renderer.emphasize(model,ui);};
$('net-detail-close').onclick=()=>closeDetails();document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeDetails();$('net-search-results').hidden=true;}});
$('net-search').addEventListener('input',()=>{clearTimeout(searchTimer);deviceList();searchResults(false);searchTimer=setTimeout(()=>searchResults(true),350);});
$('net-search').addEventListener('keydown',e=>{if(e.key==='Enter'){clearTimeout(searchTimer);const q=e.target.value.trim().toLowerCase(),n=[...model.nodes.values()].find(n=>matches(n,q));if(q&&n){select(n.id,true);$('net-search-results').hidden=true;surface.scrollIntoView({block:'center'});}}});
$('net-site').onchange=()=>{ui.status='';defaults();};
$('net-source').onchange=()=>{location.href='/ui/inventory/map?source='+encodeURIComponent($('net-source').value);};
$('net-refresh').onclick=refresh;
function tick(){freshness();if(!document.hidden&&$('net-auto').checked&&!busy&&Date.now()-lastAttempt>=graph.refresh_seconds*1000)refresh();}
$('net-auto').onchange=()=>{if($('net-auto').checked)tick();};
function resize(){
 const rect=surface.getBoundingClientRect(),next={w:rect.width,h:rect.height};if(next.w===size.w&&next.h===size.h)return;
 const first=size.w===1,wasMobile=mobile;mobile=matchMedia('(max-width: 700px)').matches;size=next;
 surface.setAttribute('viewBox',`0 0 ${size.w} ${size.h}`);
 if(first||wasMobile!==mobile)defaults();else focusBounds(ui.branch?geometry.clusterBounds.get(ui.branch):geometry.bounds,false);
}
sites();resize();new ResizeObserver(resize).observe(surface);
lastAttempt=graph.fresh?Date.now():0;freshness();if(graph.error)error(graph.error);
setInterval(tick,1000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)tick();});
})();
