const {test}=require('node:test'),assert=require('node:assert/strict');
const T=require('../keywright_server/web/templates/_topology_layout.js'),fixture=require('./topology_fixture.cjs');
function noOverlaps(geometry){
 const rectangles=[...geometry.positions.values()];
 for(let i=0;i<rectangles.length;i++)for(let j=i+1;j<rectangles.length;j++){
  const a=rectangles[i],b=rectangles[j];
  assert.ok(a.x+a.width<=b.x||b.x+b.width<=a.x||a.y+a.height<=b.y||b.y+b.height<=a.y,`Collision: ${a.id} / ${b.id}`);
 }
 for(const p of rectangles)for(const v of [p.x,p.y,p.width,p.height])assert.ok(Number.isFinite(v));
}
for(const size of [25,88,160,350])for(const mobile of [true,false])test(`${size} devices, ${mobile?'mobile':'desktop'}: collision-free pages and complete evidence`,()=>{
 const graph=fixture(size),m=T.normalize(graph),expanded=new Set(m.groups.keys());
 assert.equal(m.nodes.size,size);assert.equal(m.edges.length,graph.edges.length);
 const overview=T.layout(m,{mobile});noOverlaps(overview);assert.equal(overview.positions.size,7);
 if(mobile){assert.ok(overview.bounds.width<=340);assert.ok(overview.bounds.height<=490);}
 const visited=new Set();
 for(let page=0;page<Math.ceil(size/8);page++){
  const g=T.layout(m,{mobile,expanded,pages:new Map([...expanded].map(id=>[id,page]))});noOverlaps(g);
  for(const id of g.positions.keys())visited.add(id);
 }
 assert.equal(visited.size,size,'All clients must be reachable through pages');
});
test('positions remain stable across input reorder, state and label refreshes',()=>{
 const graph=fixture(88),m=T.normalize(graph),opts={expanded:new Set(m.groups.keys()),mobile:true};
 const a=T.layout(m,opts);
 const changed={...graph,nodes:graph.nodes.toReversed().map(n=>({...n,name:'A new name',state:'stale',unreviewed:!n.unreviewed})),edges:graph.edges.toReversed()};
 const b=T.normalize(changed);assert.equal(m.signature,b.signature);
 assert.deepEqual([...a.positions].sort(),[...T.layout(b,opts).positions].sort());
});
test('unknown connections are separate, not fabricated',()=>{
 const graph=fixture(25);graph.edges=graph.edges.filter(e=>e.target!=='client-0007');graph.edges.push({source:'missing-switch',target:'client-0008',medium:'unknown'});
 const m=T.normalize(graph),g=T.layout(m,{expanded:new Set(m.groups.keys())});
 assert.ok(m.groupOf.get('client-0007').startsWith('@unplaced:'));
 assert.equal(m.dangling.length,1);
 assert.ok(!m.edges.some(e=>e.target==='client-0007'));
 assert.ok(!g.routes.some(e=>e.target==='client-0007'));noOverlaps(g);
});
test('cycles and multiple parents retain all edges with finite placement and paths',()=>{
 const graph=fixture(25);graph.edges.push({source:'ap3',target:'core',medium:'wifi'},{source:'switch',target:'ap1',medium:'wired'},{source:'ap2',target:'ap2',medium:'wifi'});
 graph.nodes.find(n=>n.id==='core').attachment='ap3';
 const m=T.normalize(graph),g=T.layout(m,{expanded:new Set(m.groups.keys())});
 assert.ok(m.cycles.size);assert.equal(g.routes.length,graph.edges.length);noOverlaps(g);
 assert.ok(T.upstream(m,'ap3').nodes.has('wan'));assert.ok(T.upstream(m,'ap3').edges.size<=graph.edges.length);
});
test('connection changes recalculate ownership and preserve collapsed state',()=>{
 const graph=fixture(88),before=T.normalize(graph),client=graph.nodes.find(n=>n.id==='client-0007');
 client.attachment='ap3';graph.edges.find(e=>e.target===client.id).source='ap3';const after=T.normalize(graph);
 assert.notEqual(after.signature,before.signature);assert.equal(after.groupOf.get(client.id),'ap3');
 const g=T.layout(after,{expanded:new Set(['ap1'])});assert.ok(!g.positions.has(client.id));assert.ok(g.positions.has('ap3'));
});
test('empty graphs and isolated infrastructure work without invented links',()=>{
 const empty=T.layout(T.normalize({nodes:[],edges:[]}));assert.equal(empty.positions.size,0);
 const graph=fixture(25);graph.edges=[];const m=T.normalize(graph);noOverlaps(T.layout(m,{expanded:new Set(m.groups.keys())}));assert.equal(m.edges.length,0);
});
