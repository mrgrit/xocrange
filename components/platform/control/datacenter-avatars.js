/* xOC helmet and jumpsuit figures on kt66's original 24 × 44 sprite grid. */
'use strict';
window.DataCenterAvatars=(()=>{
 const styles={
  'facility-engineer':['#b99b54','#d8c58f','engineer'],
  'physical-security':['#6470ab','#b7b1dc','guard'],
  'network-engineer':['#399c9a','#a79cdd','engineer'],
  'systems-engineer':['#8265bb','#c2a7ee','engineer'],
  'gpu-platform-engineer':['#718e52','#cad4aa','engineer'],
  'service-desk':['#ad648f','#dcc0e6','specialist'],
  'soc-analyst':['#4f80ab','#93c6d8','guard'],
  'ops-lead':['#c7c0d7','#bd9de9','lead'],
  'compliance-auditor':['#7b9a8e','#e1dfec','auditor'],
  'application-developer':['#5b76b9','#afa4df','specialist'],
  'skill-researcher':['#a265b8','#d1adea','researcher'],
  'skill-evaluator':['#5b9ea8','#c1e0df','auditor'],
  'agent-supervisor':['#7256a3','#d3b8ed','lead'],
  'content-curator':['#a77cae','#ded0ed','researcher'],
  'learning-guide':['#618fa5','#a9cfd9','specialist'],
  'red-instructor':['#b66287','#d9a0c5','lead'],
  'blue-instructor':['#408f99','#a3d7d9','guard']
 };
 const NS='http://www.w3.org/2000/svg';
 function draw(worker,seated=false){
  const [suit,helmet,rank]=styles[worker.id]||styles['application-developer'];
  const svg=document.createElementNS(NS,'svg');
  for(const [k,v] of Object.entries({viewBox:'0 0 24 44','shape-rendering':'crispEdges','data-avatar-design':'xoc-helmet-jumpsuit','data-avatar-seated':String(seated),'data-avatar-role':worker.id,'data-avatar-rank':rank,'aria-hidden':'true'}))svg.setAttribute(k,v);
  const node=(tag,attrs)=>{const n=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,v);svg.append(n);return n;};
  const r=(x,y,width,height,fill)=>node('rect',{x,y,width,height,fill});
  const dark='#24183f',ink='#140c2d',cyan='#42e5df',highlight='#ece5ff';
  // Boots, joint panels and a continuous zipped jumpsuit.
  r(6,32,5,10,suit);r(13,32,5,10,suit);r(6,36,2,5,dark);r(16,36,2,5,dark);
  if(seated){r(4,33,7,4,suit);r(13,33,7,4,suit);}
  r(5,41,6,3,ink);r(13,41,6,3,ink);r(6,22,12,13,suit);
  r(3,24,3,10,suit);r(18,24,3,10,suit);r(3,32,3,3,ink);r(18,32,3,3,ink);
  r(6,23,12,2,helmet);r(11,25,2,9,dark);r(11,26,1,7,highlight);r(6,32,12,2,dark);
  r(7,28,3,3,dark);r(14,27,3,3,helmet);r(14,27,3,1,cyan);r(3,25,3,2,helmet);r(18,25,3,2,helmet);
  // The logo's broad helmet, deep violet visor, cyan rim and magenta chin vents.
  node('path',{d:'M7 1H17V3H20V6H22V10H24V17H22V21H18V24H6V22H2V18H0V10H2V6H4V3H7Z',fill:ink});
  node('path',{d:'M7 3H17V5H19V8H21V17H19V20H16V22H8V20H5V18H3V10H5V6H7Z',fill:helmet});
  node('path',{d:'M7 8H18V10H20V15H18V18H7V16H4V12H6Z',fill:dark});
  node('path',{d:'M7 8H18V10H20V12H18V10H8V12H6V16H4V12H6V10H7Z',fill:cyan});
  node('path',{d:'M9 10H13V12H11V14H8V16H6V13H8V11H9Z',fill:'#c4ffff'});
  node('path',{d:'M16 12H19V15H17V18H13V16H15V14H16Z',fill:'#7035b8'});
  r(7,4,9,2,highlight);r(5,6,3,2,highlight);r(1,12,2,5,cyan);r(21,12,2,5,cyan);
  r(5,19,3,2,'#dd63bb');r(17,18,3,2,'#dd63bb');r(10,19,4,1,cyan);r(10,21,4,1,cyan);
  if(rank==='lead'){r(9,1,6,2,'#e6c67e');r(9,4,6,1,'#f3dfa1');r(14,29,1,2,'#f3dfa1');r(16,29,1,2,'#f3dfa1');}
  else if(rank==='engineer'){r(10,3,4,3,dark);r(11,4,2,1,cyan);r(19,5,2,3,suit);}
  else if(rank==='guard'){r(2,2,1,7,helmet);r(1,2,3,2,cyan);r(9,4,6,1,suit);}
  else if(rank==='researcher'){r(11,1,3,4,'#e783cf');r(10,2,5,1,'#f0b8e8');}
  else if(rank==='auditor'){r(9,3,7,1,highlight);r(8,5,9,1,highlight);r(15,29,2,2,highlight);}
  else{r(10,3,5,2,suit);r(11,3,3,1,'#e5cffa');}
  if(worker.facing==='rear'){
   svg.setAttribute('data-avatar-facing','rear');
   node('path',{d:'M7 3H17V5H19V8H21V17H19V20H16V22H8V20H5V18H3V10H5V6H7Z',fill:helmet});
   r(7,4,9,2,highlight);r(5,6,3,2,highlight);r(4,10,2,7,cyan);r(19,10,2,7,cyan);
   r(8,10,9,9,dark);r(9,11,7,1,'#a98ce0');r(9,14,7,1,cyan);r(9,17,7,1,'#dd63bb');
   if(rank==='lead'){r(9,5,6,1,'#e6c67e');r(9,7,6,1,'#e6c67e');}
  }
  return svg;
 }
 return {draw,width:24,height:44};
})();
