/* Pure topology model and geometry. No DOM, network requests, or device-specific coordinates. */
(function(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.KeywrightTopology = api;
})(globalThis, function() {
  'use strict';
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const roles = {external: 0, gateway: 1, router: 1, switch: 2, network: 3, ap: 4};
  const order = (a, b) => (roles[a.role] ?? 5) - (roles[b.role] ?? 5) || compare(a.id, b.id);

  function normalize(graph, site = '') {
    const nodes = new Map((graph.nodes || []).filter(n => !site || n.site_id === site)
      .map(n => [n.id, {...n, name: n.name || n.mac || 'Unnamed device', addresses: n.addresses || []}]));
    const edges = [], dangling = [], seen = new Set(), incoming = new Map();
    for (const edge of graph.edges || []) {
      if (!nodes.has(edge.target)) continue;
      if (!nodes.has(edge.source)) { dangling.push(edge); continue; }
      const key = JSON.stringify([edge.source, edge.target, edge.medium, edge.provenance, edge.label]);
      if (seen.has(key)) continue;
      seen.add(key);
      const e = {...edge, key, backbone: !!(nodes.get(edge.source).hub && nodes.get(edge.target).hub)};
      edges.push(e);
      if (!incoming.has(e.target)) incoming.set(e.target, []);
      incoming.get(e.target).push(e);
    }
    edges.sort((a, b) => compare(a.key, b.key));
    const groups = new Map(), parent = new Map(), groupOf = new Map(), cycles = new Set();
    for (const n of nodes.values()) if (n.hub) groups.set(n.id, {node: n, clients: [], children: [], synthetic: false});
    function reportedParent(n) {
      const choices = (incoming.get(n.id) || []).filter(e => e.source !== n.id && nodes.get(e.source).hub)
        .sort((a, b) => compare(a.source, b.source));
      return choices.find(e => e.source === n.attachment)?.source || choices[0]?.source;
    }
    for (const n of nodes.values()) {
      const upstream = reportedParent(n);
      if (n.hub) { if (upstream) parent.set(n.id, upstream); continue; }
      let group = upstream;
      if (!group) {
        group = '@unplaced:' + (n.site_id || '');
        while (nodes.has(group)) group = '@' + group;
        if (!groups.has(group)) groups.set(group, {synthetic: true, children: [], clients: [], node: {
          id: group, name: 'Connection unknown', hub: true, role: 'unknown', site: n.site,
          site_id: n.site_id, state: 'unknown', unreviewed: false, virtual: true
        }});
      }
      groups.get(group).clients.push(n.id);
      groupOf.set(n.id, group);
    }
    // Use a spanning forest for placement only. Every reported edge is retained for rendering.
    for (const id of groups.keys()) {
      const path = [], at = new Map(); let cursor = id;
      while (parent.has(cursor)) {
        if (at.has(cursor)) {
          const cycle = path.slice(at.get(cursor));
          cycle.forEach(key => cycles.add(key));
          parent.delete([...cycle].sort(compare)[0]);
          break;
        }
        at.set(cursor, path.length); path.push(cursor); cursor = parent.get(cursor);
      }
    }
    for (const [child, upstream] of parent) groups.get(upstream).children.push(child);
    const sortGroups = (a, b) => order(groups.get(a).node, groups.get(b).node);
    for (const group of groups.values()) {
      group.clients.sort(compare); group.children.sort(sortGroups);
    }
    const roots = [...groups.keys()].filter(id => !parent.has(id)).sort(sortGroups);
    const signature = JSON.stringify({nodes: [...nodes.values()].sort((a,b)=>compare(a.id,b.id))
      .map(n => [n.id, n.hub, n.role, n.site_id]), edges: edges.map(e=>[e.source,e.target,e.medium]), parents: [...parent].sort((a,b)=>compare(a[0],b[0])), roots});
    return {nodes, edges, incoming, dangling, groups, groupOf, parent, roots, cycles, signature};
  }

  function bounds(rects) {
    if (!rects.length) return {x: 0, y: 0, width: 300, height: 220};
    const x = Math.min(...rects.map(r=>r.x)), y = Math.min(...rects.map(r=>r.y));
    return {x, y, width: Math.max(...rects.map(r=>r.x+r.width))-x,
      height: Math.max(...rects.map(r=>r.y+r.height))-y};
  }

  function layout(model, options = {}) {
    const mobile = !!options.mobile, expanded = options.expanded || new Set(), pages = options.pages || new Map();
    const pageSize = mobile ? 8 : 10;
    const hubW = mobile ? 132 : 164, hubH = 68, clientW = mobile ? 148 : 172, clientH = 44;
    const rowGap = 56, siblingGap = mobile ? 18 : 34, levelGap = mobile ? 28 : 52;
    const positions = new Map(), blocks = new Map(), levels = new Map(), spans = new Map(), depth = new Map();
    const sides = new Map();
    function sideWalk(id, side) {
      sides.set(id, side);
      const children = model.groups.get(id).children;
      children.forEach((child, i) => sideWalk(child, children.length > 1 ? (i < children.length / 2 ? -1 : 1) : side));
    }
    model.roots.forEach((id,i)=>sideWalk(id,model.roots.length > 1 && i < model.roots.length/2 ? -1 : 1));
    function measure(id, level) {
      const group = model.groups.get(id), total = group.clients.length;
      const page = Math.min(Math.max(0,pages.get(id)||0), Math.max(0,Math.ceil(total/pageSize)-1));
      const clients = expanded.has(id) ? group.clients.slice(page*pageSize,(page+1)*pageSize) : [];
      const side = sides.get(id), wing = clients.length ? clientW + 44 : 0;
      const height = Math.max(hubH, clients.length*rowGap-12);
      blocks.set(id, {width:hubW+wing, height, side, clients, page, total, pageSize});
      depth.set(id, level); levels.set(level, Math.max(levels.get(level)||0,height));
      const widths = group.children.map(child=>measure(child,level+1));
      const span = Math.max(hubW+wing, widths.reduce((a,b)=>a+b,0)+Math.max(0,widths.length-1)*siblingGap);
      spans.set(id,span); return span;
    }
    model.roots.forEach(id=>measure(id,0));
    let nextY = 16; const centers = new Map();
    for (const [level,height] of [...levels].sort((a,b)=>a[0]-b[0])) {
      centers.set(level,nextY+height/2); nextY += height+levelGap;
    }
    function place(id, left) {
      const group=model.groups.get(id), block=blocks.get(id), span=spans.get(id), y=centers.get(depth.get(id));
      const blockLeft=left+(span-block.width)/2;
      const x=blockLeft+(block.side<0?block.width-hubW/2:hubW/2);
      positions.set(id,{id,x:x-hubW/2,y:y-hubH/2,width:hubW,height:hubH,hub:true,group:id});
      block.clients.forEach((client,i)=>{
        const fraction=block.clients.length===1?0:i/(block.clients.length-1)*2-1;
        const bow=18*Math.cos(fraction*Math.PI/2);
        const cx=block.side>0?x+hubW/2+26+bow:x-hubW/2-26-bow-clientW;
        positions.set(client,{id:client,x:cx,y:y+(i-(block.clients.length-1)/2)*rowGap-clientH/2,
          width:clientW,height:clientH,hub:false,group:id,side:block.side});
      });
      const childrenWidth=group.children.reduce((sum,c)=>sum+spans.get(c),0)+Math.max(0,group.children.length-1)*siblingGap;
      let childLeft=left+(span-childrenWidth)/2;
      for(const child of group.children){place(child,childLeft);childLeft+=spans.get(child)+siblingGap;}
    }
    let rootLeft=16;
    for(const id of model.roots){place(id,rootLeft);rootLeft+=spans.get(id)+siblingGap*2;}
    const routes=[];
    for(const e of model.edges){
      const a=positions.get(e.source),b=positions.get(e.target);if(!a||!b)continue;
      let path;
      if(e.source===e.target){path=`M${a.x+a.width} ${a.y+15} c40 -30 40 70 0 40`;}
      else if(e.backbone){
        const ax=a.x+a.width/2,ay=a.y+a.height,bx=b.x+b.width/2,by=b.y;
        const mid=(ay+by)/2;
        path=`M${ax} ${ay} C${ax} ${mid} ${bx} ${mid} ${bx} ${by}`;
      }else{
        const side=b.side||1,ax=side>0?a.x+a.width:a.x,ay=a.y+a.height/2;
        const bx=side>0?b.x:b.x+b.width,by=b.y+b.height/2;
        path=`M${ax} ${ay} C${ax+side*14} ${ay} ${bx-side*14} ${by} ${bx} ${by}`;
      }
      routes.push({...e,path});
    }
    const clusterBounds=new Map([...blocks].map(([id,block])=>[id,bounds([positions.get(id),...block.clients.map(c=>positions.get(c))])]));
    return {positions,blocks,routes,clusterBounds,pageSize,bounds:bounds([...positions.values()]),
      infrastructureBounds:bounds([...positions.values()].filter(p=>p.hub))};
  }

  function upstream(model, id) {
    const nodes=new Set([id]), edges=new Set(), pending=[id];
    while(pending.length){for(const e of model.incoming.get(pending.pop())||[]){
      edges.add(e.key);if(!nodes.has(e.source)){nodes.add(e.source);pending.push(e.source);}
    }}
    return {nodes,edges};
  }

  function category(n) {
    if(n.hub) return ({external:'internet',gateway:'router',router:'router',ap:'ap',switch:'switch'})[n.role]||'network';
    const value=[n.category,n.device_type,n.model,n.name].filter(Boolean).join(' ').toLowerCase();
    if(/camera|doorbell|webcam|\bipc\b/.test(value))return 'camera';
    if(/iphone|android|smartphone|\bphone\b|pixel/.test(value))return 'phone';
    if(/ipad|tablet/.test(value))return 'tablet';
    if(/macbook|laptop|notebook/.test(value))return 'laptop';
    if(/computer|desktop|\bpc\b|\bmac\b|imac/.test(value))return 'computer';
    if(/server|\bnas\b|storage|proxmox/.test(value))return 'server';
    if(/printer/.test(value))return 'printer';
    if(/television|\btv\b|roku|display/.test(value))return 'tv';
    if(/speaker|sonos|audio/.test(value))return 'speaker';
    if(/sensor|thermostat|plug|light|bulb|vacuum|feeder|kettle|iot|home assistant/.test(value))return 'iot';
    return 'device';
  }
  return {normalize,layout,bounds,upstream,category};
});
