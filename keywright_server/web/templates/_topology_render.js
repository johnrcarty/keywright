/* SVG presentation only. Geometry and topology are supplied by the pure layout module. */
(function(root) {
  'use strict';
  const NS='http://www.w3.org/2000/svg';
  const states={online:'Online (reported)',inactive:'Inactive (reported)',missing:'Not in latest snapshot',
    old:'Not observed for 24h+',unknown:'Unknown',stale:'Stale / unverified'};
  function svg(tag,attrs={},parent){
    const node=document.createElementNS(NS,tag);
    for(const [key,value] of Object.entries(attrs))node.setAttribute(key,String(value));
    if(parent)parent.append(node);return node;
  }
  const paths={
    internet:'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20M2 12h20M12 2c6 6 6 14 0 20M12 2c-6 6-6 14 0 20',
    router:'M4 11h16v9H4zM7 11V5m10 6V3M7 16h.1M11 16h.1M15 16h2',
    switch:'M3 6h18v13H3zM6 10h3v3H6zM11 10h3v3h-3zM16 10h2v3h-2M6 16h12',
    ap:'M2 8q10-10 20 0M5 12q7-7 14 0M8 16q4-4 8 0M12 20h.1',
    network:'M9 3h6v5H9zM2 16h6v5H2zM16 16h6v5h-6zM12 8v4M5 16v-4h14v4',
    camera:'M3 7h12v13H3zM15 11l6-3v11l-6-3M6 7l2-3h5l2 3',
    phone:'M7 2h10v20H7zM10 5h4M11 19h2',
    tablet:'M4 2h16v20H4zM11 19h2',
    computer:'M2 3h20v14H2zM12 17v4M7 21h10',
    laptop:'M5 3h14v14H5zM5 17l-3 4h20l-3-4',
    server:'M4 2h16v8H4zM4 14h16v8H4zM7 6h.1M7 18h.1M11 6h6M11 18h6',
    printer:'M7 8V2h10v6M5 17H2V8h20v9h-3M6 13h12v9H6zM17 11h.1',
    tv:'M2 5h20v14H2zM8 22h8M8 1l4 4 4-4',
    speaker:'M6 2h12v20H6zM9 6h6M12 11a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
    iot:'M9 3h6v3h3v3h3v6h-3v3h-3v3H9v-3H6v-3H3V9h3V6h3zM9 9h6v6H9z',
    device:'M5 3h14v18H5zM9 7h6M9 11h6M11 17h2'
  };
  function icon(parent,category,x,y){
    const group=svg('g',{transform:`translate(${x} ${y})`,class:'topo-icon','aria-hidden':'true'},parent);
    svg('path',{d:paths[category]||paths.device},group);return group;
  }
  const canvas=document.createElement('canvas'),context=canvas.getContext('2d');
  function width(text,font=13){context.font=`${font}px system-ui, sans-serif`;return context.measureText(text).width;}
  function truncate(text,available,font=13){
    if(width(text,font)<=available)return text;
    let out=text;while(out.length&&width(out+'…',font)>available)out=out.slice(0,-1);
    return out+'…';
  }
  function lines(text,available){
    if(width(text)<=available)return [text];
    const words=text.split(/(?<=[\s\-_/])/);let first='';
    while(words.length&&width(first+words[0])<=available)first+=words.shift();
    if(!first){while(text.length&&width(first+text[0])<=available){first+=text[0];text=text.slice(1);}return [first,truncate(text,available)];}
    return [first.trim(),truncate(words.join('').trim(),available)];
  }
  function text(parent,value,attrs){const t=svg('text',attrs,parent);t.textContent=value;return t;}
  class Renderer {
    constructor(scene){this.scene=scene;this.nodeElements=new Map();this.edgeElements=new Map();}
    draw(model,geometry,ui){
      const active=document.activeElement?.dataset?.id;
      this.scene.replaceChildren();this.nodeElements.clear();this.edgeElements.clear();
      const edges=svg('g',{'aria-hidden':'true'},this.scene);
      for(const route of geometry.routes){
        const line=svg('path',{d:route.path,class:`topo-edge ${route.backbone?'backbone':'client'} ${route.medium||'unknown'}${route.historical?' historical':''}`,
          'data-edge':route.key},edges);
        const a=model.nodes.get(route.source),b=model.nodes.get(route.target);
        const title=svg('title',{},line);title.textContent=`${a.name} → ${b.name} · ${route.label||route.medium} · ${route.provenance||'Source unknown'}`;
        this.edgeElements.set(route.key,line);
      }
      for(const [id,p] of geometry.positions){
        const group=model.groups.get(id),n=model.nodes.get(id)||group?.node;if(!n)continue;
        const block=geometry.blocks.get(id),synthetic=!!group?.synthetic;
        const label=synthetic?`${n.name}, ${block.total} devices. Select to explore.`:
          `${n.name}, ${n.virtual?'not monitored':states[n.state]||'Unknown'}${n.unreviewed?', unreviewed':''}${p.hub?`, ${block.total} clients. Select to focus.`:''}`;
        const g=svg('g',{transform:`translate(${p.x} ${p.y})`,class:`topo-node ${p.hub?'hub':'client'} ${n.state||'unknown'}${synthetic?' unplaced':''}`,
          role:'button',tabindex:0,'aria-label':label,'data-id':id,'data-action':'select','data-x':p.x,'data-y':p.y},this.scene);
        svg('rect',{width:p.width,height:p.height,rx:p.hub?12:8,class:'node-surface'},g);
        svg('rect',{x:0,y:10,width:3,height:p.height-20,rx:1.5,class:'state-rail'},g);
        icon(g,synthetic?'device':KeywrightTopology.category(n),10,p.hub?13:10);
        const available=p.width-47;
        if(p.hub){
          const nameLines=lines(n.name,available);
          nameLines.forEach((line,i)=>text(g,line,{x:40,y:nameLines.length>1?23+i*16:29,class:'node-name'}));
          const count=block.total?`${block.total} client${block.total===1?'':'s'} ${ui.expanded.has(id)?'−':'+'}`:
            n.role==='external'?'Not monitored':({gateway:'Gateway',router:'Router',switch:'Switch',ap:'Access point'})[n.role]||'Infrastructure';
          text(g,count,{x:10,y:57,class:'node-meta'});
          if(block.total)svg('circle',{cx:p.width-13,cy:55,r:3,class:ui.expanded.has(id)?'expanded-dot':'collapsed-dot'},g);
        }else{
          text(g,truncate(n.name,available),{x:40,y:19,class:'node-name'});
          text(g,truncate(n.addresses[0]||states[n.state]||'Unknown',available,11),{x:40,y:34,class:'node-meta'});
        }
        if(n.unreviewed){svg('circle',{cx:p.width-5,cy:5,r:5,class:'review-dot'},g);}
        if(!synthetic&&p.hub&&!model.parent.has(id)&&n.role!=='external'&&n.role!=='gateway'&&n.role!=='router'){
          const mark=svg('circle',{cx:p.width-12,cy:12,r:3,class:'unknown-uplink'},g);
          const title=svg('title',{},mark);title.textContent='Upstream connection not reported';
        }
        const title=svg('title',{},g);title.textContent=label;
        this.nodeElements.set(id,g);
      }
      this.emphasize(model,ui);
      if(active&&this.nodeElements.has(active))this.nodeElements.get(active).focus({preventScroll:true});
    }
    emphasize(model,ui){
      const selected=ui.selected,branch=ui.branch;
      const ancestry=selected&&model.nodes.has(selected)?KeywrightTopology.upstream(model,selected):
        branch&&model.nodes.has(branch)?KeywrightTopology.upstream(model,branch):{nodes:new Set(),edges:new Set()};
      const related=new Set(ancestry.nodes);
      if(branch){related.add(branch);for(const id of model.groups.get(branch)?.clients||[])related.add(id);}
      for(const [id,g] of this.nodeElements){
        const n=model.nodes.get(id)||model.groups.get(id)?.node;
        const matches=!ui.status||ui.status==='unreviewed'&&n.unreviewed||
          ui.status==='inactive'&&['inactive','missing'].includes(n.state)||
          ui.status==='unknown'&&['unknown','stale'].includes(n.state)||n.state===ui.status;
        g.classList.toggle('selected',id===selected);
        g.classList.toggle('on-path',ancestry.nodes.has(id));
        g.classList.toggle('dimmed',!!branch&&!related.has(id)||!matches);
      }
      for(const e of model.edges){const line=this.edgeElements.get(e.key);if(!line)continue;
        line.classList.toggle('on-path',ancestry.edges.has(e.key));
        line.classList.toggle('dimmed',!!branch&&!ancestry.edges.has(e.key)&&e.source!==branch);
      }
    }
  }
  root.KeywrightTopologyView={Renderer,svg,states,truncate};
})(globalThis);
