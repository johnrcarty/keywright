// Deterministic controller-shaped graphs; deliberately includes missing and cyclic evidence in tests.
function fixture(count=88){
 const stamp=new Date().toISOString();
 const graph={sources:[{id:'fixture',name:'Test controller'}],source:'fixture',nodes:[],edges:[],counts:{},refresh_seconds:60,fresh_seconds:180,generated_at:stamp,last_success:stamp,latest_status:'succeeded',fresh:true,error:''};
 function node(id,name,role='client',parent='',medium='wired'){
  const i=graph.nodes.length,hub=role!=='client';
  graph.nodes.push({id,name,role,hub,attachment:parent,attachment_label:graph.nodes.find(n=>n.id===parent)?.name||'',attachment_source:parent?'Omada':'',medium,site_id:'home',site:'Home',addresses:hub?[]:[`192.0.2.${i}`],mac:`aa:bb:cc:dd:ee:${i.toString(16)}`,state:['online','online','online','inactive','old','unknown','stale'][i%7],unreviewed:!hub&&i%3===0,last_observed:stamp,first_observed:stamp,model:'',port:medium==='wifi'?'Home Wi-Fi':'',virtual:role==='external'});
  if(parent)graph.edges.push({source:parent,target:id,medium,provenance:'Omada',label:medium==='wifi'?'5 GHz':'Port 8',historical:false});
 }
 node('wan','Internet / WAN','external');node('gateway','Gateway','gateway','wan');node('core','Core switch','switch','gateway');node('switch','Office switch','switch','core');node('ap1','Upstairs AP','ap','core');node('ap2','Downstairs AP','ap','switch');node('ap3','Mesh AP','ap','ap1','wifi');
 const parents=['core','ap1','ap2','ap3','switch'];
 const names=['Office laptop','Hall camera','Phone','Television','Sensor','Speaker','Printer','Tablet','NAS'];
 for(let i=7;i<count;i++){const parent=parents[(i-7)%parents.length];node('client-'+String(i).padStart(4,'0'),names[i%names.length]+' '+i,'client',parent,parent.startsWith('ap')?'wifi':'wired');}
 return graph;
}
module.exports=fixture;
if(require.main===module)process.stdout.write(JSON.stringify(fixture(Number(process.argv[2])||88)));
