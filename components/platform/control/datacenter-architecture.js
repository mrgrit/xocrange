/* Adapted visual geometry from mrgrit/kt66 NOC. See docs/provenance/datacenter-source.json.
 * No original telemetry, agent execution, HTTP access or control code is included.
 * Furniture and facility shapes are architectural references, never live assets. */
'use strict';
window.DataCenterArchitecture=(()=>{
 const SVGNS='http://www.w3.org/2000/svg',GW=12,GD=8,XS=28,ZS=32;
 let YS=14,LAYOUT,ST,svgHost,learning;
 const iso=(x,y,z)=>[(x-y)*XS,(x+y)*YS-z*ZS];
 const pts=a=>a.map(p=>p.join(',')).join(' ');
 const $=()=>svgHost;
 const shade=(hex,f)=>'#'+[1,3,5].map(i=>Math.min(255,Math.round(parseInt(hex.slice(i,i+2),16)*f)).toString(16).padStart(2,'0')).join('');
 function el(tag,attrs={},kids=[]){
  const n=document.createElementNS(SVGNS,tag==='a'?'g':tag);
  for(const [k,v] of Object.entries(attrs)){
   if(v==null||['on','href','tabindex','role'].includes(k))continue;
   if(k==='text')n.textContent=v;else n.setAttribute(k,String(['fill','stroke'].includes(k)?({'#647e8c':'#746c8b','#657f8d':'#716b88','#6c8794':'#7c7593','#d0b77e':'#ad86d9','#b2d8e5':'#88e2db'}[v]||v):v));
  }
  (Array.isArray(kids)?kids:[kids]).filter(Boolean).forEach(c=>n.append(c));return n;
 }
 const quad=(x,y,z,w,d,a)=>el('polygon',{points:pts([iso(x,y,z),iso(x+w,y,z),iso(x+w,y+d,z),iso(x,y+d,z)]),...a});
 const zoneColor=id=>({ext:'#ff718b',pipe:'#ffb16b',dmz:'#e5cb74',int:'#7ad6b5',app:'#b29cde',mgmt:'#9aaeba',ot:'#80c7dc',office:'#8fb4e8'}[id]||'#a1b3be');
 const racksOf=f=>LAYOUT.racks.filter(r=>r.floor===f);
 const assetsOf=f=>LAYOUT.it_assets.filter(a=>a.floor===f);
 const alive=a=>a.health?.state==='running';
 const assetDown=a=>['exited','dead','missing'].includes(a.health?.state);
 const assetState=()=>({kw:0,util:0});
 const assetIndicator=a=>alive(a)?'#b5ef9f':a.health?.state==='unknown'?'#a9bac6':a.health?'#e9ad79':'#a9bac6';
 const assetStatusLabel=()=>'';
 const tipify=()=>{},pill=()=>{},openFacility=()=>{},dcURL=()=>'';
 const warnBadge=()=>el('g');
 const facilityDown=()=>false,facilityGuide=()=>({});
 const workerAttributes=()=>({});
 const workerInfo=g=>g;
 function drawWorkerFigure(worker,x,y,z,seated=false){
  const [sx,sy]=iso(x,y,z),width=seated?22:24,height=width*44/24;
  const g=el('g',{'data-worker-figure':worker.id,'data-avatar-position':[x,y,z].join(','),'data-avatar-width':width,transform:`translate(${sx} ${sy})`,'pointer-events':'none'});
  g.append(el('ellipse',{cx:0,cy:1,rx:width*.7,ry:width*.24,fill:'#170d2c55',stroke:'#b99bcb','stroke-width':.6}));
  const sprite=DataCenterAvatars.draw(worker,seated);sprite.setAttribute('x',-width/2);sprite.setAttribute('y',-height);sprite.setAttribute('width',width);sprite.setAttribute('height',height);g.append(sprite);
  g.append(el('title',{text:worker.name||worker.id}));return g;
 }
 const drawRoomWorker=(worker,x,y,z)=>drawWorkerFigure(worker,x,y,z);

 const DESIGN_CREW=[{"id":"facility-engineer","name":"시설 담당(전기/기계)","floor":"B1"},{"id":"physical-security","name":"물리보안(출입/CCTV)","floor":"1F"},{"id":"network-engineer","name":"네트워크 엔지니어","floor":"2F"},{"id":"systems-engineer","name":"시스템/스토리지 엔지니어","floor":"2F"},{"id":"gpu-platform-engineer","name":"GPU/플랫폼 엔지니어","floor":"3F"},{"id":"service-desk","name":"서비스데스크","floor":"4F"},{"id":"soc-analyst","name":"SOC 분석가","floor":"XOC"},{"id":"ops-lead","name":"운영 리드","floor":"4F"},{"id":"compliance-auditor","name":"컴플라이언스 감사인","floor":"4F"},{"id":"application-developer","name":"애플리케이션 개발자","floor":"4F"},{"id":"skill-researcher","name":"AI 연구원","floor":"5F"},{"id":"skill-evaluator","name":"AI 모델 평가자","floor":"5F"},{"id":"agent-supervisor","name":"AI 에이전트 운영 담당","floor":"XOC"}];
 const crewOf=f=>DESIGN_CREW.filter(w=>w.floor===f);
 const allFacilities=()=>Object.entries(LAYOUT.facility).flatMap(([system,rows])=>rows.map(i=>({...i,system_kind:system,subtype:i.kind,kind:['security','automation','microgrid'].includes(system)?i.kind:system})));
 const physicalFacilitiesOf=f=>allFacilities().filter(i=>(f==='SITE'?i.location==='outdoor':i.location!=='outdoor'&&i.floor===f)&&!['containment','raised_floor','cold_plate'].includes(i.kind));
const REFERENCE={"facility":{"utility":[{"id":"utility-01","floor":null,"location":"outdoor","site_pos":[0.7,0.7],"name":"수전설비","pos":[1,1]}],"substation":[{"id":"sub-01","floor":null,"location":"outdoor","site_pos":[3.4,0.7],"name":"수전 변전소","pos":[0,1]}],"switchgear":[{"id":"swgr-01","floor":"B1","name":"특고압 개폐기","pos":[0.55,0.65]}],"transformer":[{"id":"tr-01","floor":"B1","name":"주변압기","pos":[2.52,0.65]}],"ats":[{"id":"ats-01","floor":"B1","name":"자동절체스위치","pos":[0.55,2.52]}],"generator":[{"id":"gen-01","floor":null,"location":"outdoor","site_pos":[0.7,3.1],"name":"비상 발전기","pos":[1,5]}],"fuel_tank":[{"id":"tank-fuel-01","floor":null,"location":"outdoor","site_pos":[3.4,3.1],"name":"비상발전 연료탱크","pos":[0,6]}],"ups":[{"id":"ups-01","floor":"B1","name":"무정전 전원장치","pos":[1.63,2.52]}],"battery":[{"id":"batt-01","floor":"B1","name":"배터리 스트링 A","pos":[0.5,5.78]},{"id":"batt-02","floor":"B1","name":"배터리 스트링 B","pos":[1.36,5.78]}],"microgrid":[{"id":"pv-01","floor":null,"location":"outdoor","site_pos":[6.1,3.1],"kind":"solar","name":"옥외 태양광","pos":[10,0]},{"id":"bess-01","floor":null,"location":"outdoor","site_pos":[6.1,0.7],"kind":"storage","name":"에너지저장장치(BESS)","pos":[6,1]},{"id":"fc-01","floor":null,"location":"outdoor","site_pos":[8.8,0.7],"kind":"fuel_cell","name":"연료전지","pos":[7,1]}],"busway":[{"id":"bus-2f-a","floor":"2F","name":"2F A열 부스바","pos":[3,4]},{"id":"bus-3f-b","floor":"3F","name":"3F B열 부스바","pos":[4,3]}],"pdu":[{"id":"pdu-01","floor":"2F","pos":[2,3]},{"id":"pdu-02","floor":"2F","pos":[2,5]},{"id":"pdu-03","floor":"3F","pos":[3,4]},{"id":"pdu-04","floor":"4F","pos":[7,2]}],"cooling_tower":[{"id":"ct-01","floor":null,"location":"outdoor","site_pos":[0.7,5.5],"name":"냉각탑 1호기","pos":[10,5]},{"id":"ct-02","floor":null,"location":"outdoor","site_pos":[3.4,5.5],"name":"냉각탑 2호기","pos":[11,5]}],"chiller":[{"id":"chiller-01","floor":"B1","name":"냉동기","pos":[6.25,0.82]}],"pump":[{"id":"pump-pcw-01","floor":"B1","name":"냉수 펌프 A","pos":[6.32,2.66]},{"id":"pump-pcw-02","floor":"B1","name":"냉수 펌프 B","pos":[7.55,2.66]},{"id":"pump-cw-01","floor":"B1","name":"냉각수 펌프","pos":[9.02,2.3]}],"heat_exchanger":[{"id":"hx-01","floor":"B1","name":"판형 열교환기","pos":[9.2,0.67]}],"economizer":[{"id":"eco-01","floor":"B1","name":"프리쿨링 장치","kind":"water","pos":[10.45,0.67]}],"crac":[{"id":"crac-01","floor":"2F","aisle":"A","name":"항온항습기 A","kind":"chilled-water","pos":[9,4]},{"id":"crac-02","floor":"3F","aisle":"B","name":"항온항습기 B","kind":"chilled-water","pos":[9,4]},{"id":"crac-03","floor":"4F","aisle":"C","name":"항온항습기 C","kind":"dx","pos":[10,2]}],"fan_coil":[{"id":"fcu-3f-01","floor":"3F","aisle":"B","name":"인로우 쿨러","pos":[5,4]}],"containment":[{"id":"cont-a","floor":"2F","aisle":"A","kind":"hot-aisle","pos":[3,4]},{"id":"cont-b","floor":"3F","aisle":"B","kind":"hot-aisle","pos":[4,4]},{"id":"cont-c","floor":"4F","aisle":"C","kind":"none","pos":[8,2]}],"raised_floor":[{"id":"rf-2f","floor":"2F","name":"2F 이중마루","pos":[6,6]}],"cdu":[{"id":"cdu-01","floor":"3F","name":"냉각분배장치","pos":[6,4]}],"cold_plate":[{"id":"cp-dgx-01","floor":"3F","name":"DGX 콜드플레이트 루프","pos":[4,5]}],"immersion":[{"id":"imm-01","floor":"3F","name":"침지냉각 시험 탱크","pos":[8,6]}],"water_tank":[{"id":"tank-water-01","floor":null,"location":"outdoor","site_pos":[6.1,5.5],"name":"축열조·보충수 탱크","pos":[11,6]}],"weather":[{"id":"wx-01","floor":null,"location":"outdoor","site_pos":[8.8,3.1],"name":"외기","pos":[0,0]}],"fire":[{"id":"fm200-01","floor":"B1","name":"지하 소화설비","pos":[8.85,5.85]},{"id":"fm200-02","floor":"2F","name":"소화설비 2F","pos":[10,6]},{"id":"fm200-03","floor":"3F","name":"소화설비 3F","pos":[10,6]},{"id":"vesda-01","floor":"B1","kind":"aspirating","name":"조기연기감지(VESDA)","pos":[4.72,0.18]},{"id":"vesda-02","floor":"3F","kind":"aspirating","name":"조기연기감지(VESDA)","pos":[9,7]},{"id":"fp-01","floor":"1F","kind":"panel","name":"소방 수신반","pos":[4.1,0.18]}],"security":[{"id":"door-main","floor":"1F","name":"정문 출입구","kind":"door","pos":[8,7.91]},{"id":"door-2f","floor":"2F","name":"전산실 출입문","kind":"door","pos":[0,4]},{"id":"door-3f","floor":"3F","name":"AI 전산실 출입문","kind":"door","pos":[0,4]},{"id":"cctv-01","floor":"1F","name":"로비 CCTV","kind":"cctv","pos":[10.65,3.18]},{"id":"cctv-02","floor":"2F","name":"전산실 CCTV","kind":"cctv","pos":[11,1]},{"id":"cctv-03","floor":"3F","name":"AI 전산실 CCTV","kind":"cctv","pos":[11,1]},{"id":"mantrap-01","floor":"1F","name":"인터록 포털(맨트랩)","kind":"mantrap","pos":[8.2,2.9]},{"id":"mdet-01","floor":"1F","name":"금속탐지기","kind":"metal_detector","pos":[8.36,5.3]},{"id":"guard-01","floor":null,"location":"outdoor","site_pos":[8.8,5.5],"name":"경비 초소","kind":"guard_post","pos":[1,3]},{"id":"badge-3f","floor":"3F","name":"AI 전산실 카드리더","kind":"badge_reader","pos":[0,5]}],"automation":[{"id":"robot-01","floor":"2F","kind":"rack_mover","name":"랙 무버 로봇","pos":[6,7]},{"id":"shred-01","floor":"B1","kind":"disk_shredder","name":"디스크 파쇄기","pos":[3.67,6.51]}]},"racks":[{"id":"R-2F-01","floor":"2F","aisle":"A","u":42,"pos":[3,3]},{"id":"R-2F-02","floor":"2F","aisle":"A","u":42,"pos":[3,5]},{"id":"R-2F-03","floor":"2F","aisle":"A","u":42,"pos":[5.6,3]},{"id":"R-3F-01","floor":"3F","aisle":"B","u":42,"pos":[1.55,3.0],"style":"nvidia-ai","name":"NVIDIA AI COMPUTE"},{"id":"R-4F-01","floor":"4F","aisle":"C","u":24,"pos":[8,2]}]};

function sceneDefs() {
  const lg = (id, stops, x2 = 0, y2 = 1) => el('linearGradient',
    { id, x1: 0, y1: 0, x2, y2 },
    stops.map(([o, c, a]) => el('stop', { offset: o, 'stop-color': c, 'stop-opacity': a })));
  return el('defs', {}, [
    // 면 위를 흐르는 빛. 윗면·앞면·옆면이 감쇠 세기가 다르다.
    lg('holoGlass', [[0, '#c2fff5', .20], [.4, '#45c9d5', .035], [1, '#a479ee', .15]], 1, 1),
    lg('holoViolet', [[0, '#d0b8ff', .23], [.5, '#7967cb', .045], [1, '#47d9df', .12]], 1, 1),
    lg('fTop', [[0, '#ffffff', .20], [.55, '#ffffff', .05], [1, '#000000', .10]]),
    lg('fFront', [[0, '#ffffff', .13], [1, '#000000', .26]]),
    lg('fSide', [[0, '#ffffff', .05], [1, '#000000', .34]]),
    // 바닥판 — 가운데가 살짝 밝다. 시선이 가운데로 모인다.
    el('radialGradient', { id: 'plate', cx: .5, cy: .42, r: .72 }, [
      el('stop', { offset: 0, 'stop-color': '#2ee6ff', 'stop-opacity': .055 }),
      el('stop', { offset: .55, 'stop-color': '#2ee6ff', 'stop-opacity': .012 }),
      el('stop', { offset: 1, 'stop-color': '#000000', 'stop-opacity': .34 })]),
    // 경보용 번짐. 개수가 적어 필터를 써도 된다.
    el('filter', { id: 'bloom', x: '-60%', y: '-60%', width: '220%', height: '220%' }, [
      el('feGaussianBlur', { stdDeviation: 3.6, result: 'b' }),
      el('feMerge', {}, [el('feMergeNode', { in: 'b' }), el('feMergeNode', { in: 'SourceGraphic' })])]),
    // 층 바닥판이 바닥에서 떠 보이게 하는 넓은 그림자. 층당 1개뿐이다.
    el('filter', { id: 'plateShadow', x: '-25%', y: '-25%', width: '150%', height: '160%' }, [
      el('feDropShadow', { dx: 0, dy: 16, stdDeviation: 14,
        'flood-color': '#000814', 'flood-opacity': .55 })]),
  ]);
}

function contactShadow(x, y, z, w, d, h) {
  const o = 1.6 + Math.min(h, 2.2) * 2.4;
  return el('g', { 'pointer-events': 'none' }, [
    quad(x, y, z, w, d, { fill: '#000308', opacity: .38,
      transform: `translate(${-o * .45},${o * .95})` }),
    quad(x, y, z, w, d, { fill: '#000308', opacity: .16,
      transform: `translate(${-o * .95},${o * 1.9})` }),
  ]);
}

/** 아이소메트릭 프리즘.
 *  형태가 배경에서 떨어져 나오려면 짙은 외곽선이 필요하고, 입체로 읽히려면
 *  면마다 명도가 달라야 하며, **바닥에 붙어 보이려면 그림자가 있어야 한다.** */
function prism(x, y, z, w, d, h, color, o = {}) {
  const T = [iso(x, y, z + h), iso(x + w, y, z + h), iso(x + w, y + d, z + h), iso(x, y + d, z + h)];
  const Bt = [iso(x + w, y, z), iso(x + w, y + d, z), iso(x, y + d, z)];
  const face = (p, base, grad) => [
    el('polygon', { points: pts(p), fill: base }),
    el('polygon', { points: pts(p), fill: `url(#${grad})`, 'pointer-events': 'none' })];
  return el('g', {}, [
    o.flat ? null : contactShadow(x, y, z, w, d, h),
    el('polygon', {                                   // 외곽선(실루엣)
      points: pts([T[0], T[1], Bt[0], Bt[1], Bt[2], T[3]]),
      fill: 'none', stroke: '#04080f', 'stroke-width': 2.6, 'stroke-linejoin': 'round',
      class: o.glow ? 'glow' : null }),
    ...face([T[3], T[2], Bt[1], Bt[2]], shade(color, .54), 'fSide'),
    ...face([T[1], T[2], Bt[1], Bt[0]], shade(color, .78), 'fFront'),
    ...face(T, color, 'fTop'),
    el('polyline', {                                  // 윗면 앞모서리 하이라이트
      points: pts([T[3], T[2], T[1]]), fill: 'none',
      stroke: 'rgba(255,255,255,.42)', 'stroke-width': 1.2, 'stroke-linejoin': 'round' }),
    el('polyline', {                                  // 뒷모서리 림라이트 — 배경과 분리
      points: pts([T[3], T[0], T[1]]), fill: 'none',
      stroke: 'rgba(120,205,255,.30)', 'stroke-width': 1, 'stroke-linejoin': 'round' }),
  ]);
}


function roomLine(a, b, color, width = 1, extra = {}) {
  const [x1,y1] = iso(...a), [x2,y2] = iso(...b);
  return el('line', {x1,y1,x2,y2,stroke:color,'stroke-width':width,...extra});
}
function roomFace(x,y,z,side=false) {
  const [sx,sy] = iso(x,y,z);
  return `matrix(${side ? -XS : XS},${YS},0,${-ZS},${sx},${sy})`;
}
function roomRect(x,y,w,h,fill,extra={}) {
  return el('rect',{x,y,width:w,height:h,fill,...extra});
}
function cabinetDoor(x,y,z,w,h,accent,slots=[]) {
  const face = el('g',{transform:roomFace(x,y,z)});
  face.appendChild(roomRect(.08,.08,w-.16,h-.16,'#101b22', {rx:.045}));
  face.appendChild(roomRect(.13,.13,w-.26,h-.26,'#25323a', {rx:.025}));
  // The unoccupied area is a perforated blanking panel, not extra servers.
  for(let row=.25;row<h-.2;row+=.17) {
    for(let col=.24;col<w-.2;col+=.13)
      face.appendChild(roomRect(col,row,.055,.032,'#111d24'));
  }
  face.appendChild(roomRect(.12,.15,.045,h-.3,'#74838a'));
  face.appendChild(roomRect(w-.16,.15,.045,h-.3,'#778890'));
  let top=h-.27;
  slots.forEach(a=>{
    const height=Math.max(.16,(a.u || 1)*.105), up=alive(a), color=zoneColor(a.zone);
    top-=height+.025;
    if(top < .2)return;
    const row=el('g',{'data-asset':a.id,class:'hit',on:{click:e=>{e.stopPropagation();openAsset(a.id)}}});
    row.appendChild(roomRect(.19,top,w-.38,height,'#60717b',{rx:.017}));
    row.appendChild(roomRect(.22,top+.025,w-.44,height-.05,'#35464f'));
    for(let c=.3;c<w-.5;c+=.14)row.appendChild(roomRect(c,top+.045,.07,height-.09,'#14252e'));
    row.appendChild(roomRect(w-.38,top+.047,.04,.042,assetIndicator(a)));
    row.appendChild(roomRect(.19,top,.035,height,color));
    tipify(row,{title:a.name,sub:`${a.id} · ${a.ip || ''}`,color,
      rows:[['상태',up?'가동':'정지'],['존',a.zone],['환산 전력',`${assetState(a.id).kw.toFixed(2)} kW`]],foot:'선택하면 자산 상세를 엽니다'});
    face.appendChild(row);
  });
  face.appendChild(roomRect(w-.1,h*.42,.025,.32,'#c5cfd3',{rx:.01}));
  face.appendChild(roomRect(.16,h-.115,w-.32,.025,accent));
  return face;
}
function drawRoomRack(rack,x,y,z) {
  if(rack.style==='nvidia-ai')return drawNvidiaRack(rack,x,y,z);
  const list=(LAYOUT.it_assets || []).filter(a=>a.rack===rack.id);
  const aisle=ST?.aisles?.[rack.aisle], load=list.reduce((s,a)=>s+assetState(a.id).kw,0);
  const bad=list.some(assetDown) || load>rack.design_kw;
  const w=1.65,d=1.5,h=rack.u>=42?3.3:2.35;
  const g=el('g',{'data-rack':rack.id,class:'hit',on:{click:e=>{e.stopPropagation();openRack(rack.id)}}});
  g.appendChild(prism(x,y,z,w,d,h,'#52626b'));
  // Powder coated side panel and small ventilation slits.
  const side=el('g',{transform:roomFace(x+w,y,z,true)});
  side.appendChild(roomRect(.1,.15,d-.2,h-.3,'#283b45',{rx:.02}));
  for(let i=0;i<12;i++)side.appendChild(roomRect(.25,.45+i*.085,d-.5,.022,'#4d626d'));
  side.appendChild(roomRect(.17,h-.32,d-.34,.09,'#1b2a32'));
  g.appendChild(side);
  g.appendChild(cabinetDoor(x,y+d,z,w,h,list.some(a=>a.health?.state==='running')?'#b2de86':'#87959d',list));
  // Top exhaust grilles; no animated lights on empty rack units.
  for(let j=0;j<2;j++) {
    const fan=el('g',{transform:`translate(${iso(x+.46+j*.71,y+.72,z+h+.015).join(',')}) scale(1,${YS/XS})`});
    fan.appendChild(el('circle',{r:7.5,fill:'#1b2d37',stroke:'#7a909e','stroke-width':.7}));
    for(let k=-4;k<=4;k+=2)fan.appendChild(el('line',{x1:-5.5,x2:5.5,y1:k,y2:k,stroke:'#596e79','stroke-width':.8}));
    g.appendChild(fan);
  }
  for(const dx of [.15,w-.15])g.appendChild(prism(x+dx,y+d-.2,z-.06,.08,.12,.14,'#141f25'));
  if(bad){const p=iso(x+w/2,y+d/2,z+h);g.appendChild(warnBadge(p[0],p[1]-13))}
  tipify(g,{title:rack.id,color:bad?'#f48181':'#b9df90',sub:`${rack.floor} / ${rack.u}U / ${rack.aisle} 아일`,
    rows:[['자산',`${list.length}대`],['부하',`${load.toFixed(2)} / ${rack.design_kw} kW`],['온도',aisle?`${aisle.temp_c} °C`:'센서 없음'],['존',[...new Set(list.map(a=>a.zone))].join(' · ')]],
    bar:load/rack.design_kw,barColor:'#b9df90',foot:'랙 선택으로 탑재 자산을 확인합니다'});
  return g;
}
/* NVIDIA desktop systems sit on a display rack; the illustration is not a
   claim that Spark/Thor are full-size enterprise rack servers. */
function roomLettering(x,y,z,text,size,color,extra={}) {
  const [sx,sy]=iso(x,y,z);
  return el('text',{transform:'matrix('+XS+','+YS+',0,'+ZS+','+sx+','+sy+')',
    x:0,y:0,'font-family':'Arial,sans-serif','font-size':size,'font-weight':700,
    fill:color,text,...extra});
}
function drawNvidiaDevice(asset,x,y,z,scale=1) {
  const thor=asset.form_factor==='jetson-thor',w=1.43,d=.86,h=thor?.48:.39;
  const color=thor?'#343b3d':'#c6af83';
  const open=e=>{e.stopPropagation();openAsset(asset.id)};
  const g=el('g',{'data-asset':asset.id,'data-nvidia-device':asset.form_factor,
    class:'hit',role:'button',tabindex:0,'aria-label':asset.name+' 자산 상세',
    on:{click:open,keydown:e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open(e)}}}});
  const body=el('g',{'data-device-body':asset.id});
  if(scale!==1){const [px,py]=iso(x,y,z);body.setAttribute('transform',`translate(${px},${py}) scale(${scale}) translate(${-px},${-py})`)}
  // 선반 장비에는 바닥용 긴 그림자를 사용하지 않는다.
  body.appendChild(prism(x,y,z,w,d,h,color,{flat:true}));
  const face=el('g',{transform:roomFace(x,y+d,z)});
  face.appendChild(roomRect(.05,.055,w-.1,h-.1,thor?'#13191b':'#88764f',{rx:.045}));
  for(let v=.12;v<w-.12;v+=thor?.105:.065)
    face.appendChild(roomRect(v,.085,thor?.042:.021,h-.16,thor?'#566363':'#d8c495'));
  face.appendChild(roomRect(w-.19,.075,.065,.024,assetIndicator(asset),{rx:.008}));
  body.appendChild(face);
  if(thor) {
    // Black heat-spreader, exposed fan and deep fin stack.
    for(let v=.12;v<1.28;v+=.12)
      body.appendChild(quad(x+v,y+.1,z+h+.012,.045,.63,{fill:'#172122'}));
    const p=iso(x+w*.68,y+d*.47,z+h+.02);
    const fan=el('g',{transform:'translate('+p.join(',')+') scale(1,'+(YS/XS)+')'});
    fan.appendChild(el('circle',{r:7.4,fill:'#0a1112',stroke:'#63726c','stroke-width':.8}));
    for(let k=0;k<7;k++)fan.appendChild(el('path',{d:'M0,-1 Q3,-6 6,-2 L1,1Z',fill:'#8b9991',transform:'rotate('+(k*360/7)+')'}));
    fan.appendChild(el('circle',{r:1.5,fill:'#76b900'}));body.appendChild(fan);
  } else {
    body.appendChild(quad(x+.04,y+.04,z+h+.009,w-.08,d-.08,{fill:'#cbb88e',stroke:'#e0cca1','stroke-width':.6}));
    body.appendChild(roomLettering(x+.17,y+d+.007,z+.27,'DGX SPARK',.102,'#f4e6c5'));
    for(let v=.2;v<1.3;v+=.14)
      body.appendChild(roomLine([x+v,y+.07,z+h+.018],[x+v,y+.73,z+h+.018],'#9b865e',.34));
  }
  g.appendChild(body);
  tipify(g,{title:asset.name,sub:asset.ip || asset.remote,color:assetIndicator(asset),
    rows:[['제품',asset.product],['GPU',asset.gpu_model],['접속 상태',assetStatusLabel(asset)],
      ['성능 수집',asset.telemetry?.mode==='inventory'?'등록 시 SSH 점검 · 실시간 미연동':'Ollama 기반 추정']],
    foot:'선택하면 사양·확인 시각·SSH 접속 정보를 엽니다'});
  return g;
}
function drawNvidiaRack(rack,x,y,z) {
  const list=(LAYOUT.it_assets||[]).filter(a=>a.rack===rack.id);
  const devices=list.filter(a=>a.vendor==='NVIDIA');
  const utility=list.filter(a=>a.vendor!=='NVIDIA');
  const w=5.9,d=1.0,h=3.9,green='#76b900';
  const g=el('g',{'data-rack':rack.id,'data-rack-style':'nvidia-ai',class:'hit',
    on:{click:e=>{e.stopPropagation();openRack(rack.id)}}});
  g.appendChild(prism(x-.15,y-.07,z,w+.3,d+.18,.17,'#1b2829'));
  g.appendChild(prism(x,y,z+.17,w,.12,h-.17,'#202c2c'));
  // 제품별로 선반을 나눈다. 증설 시 고정 슬롯 밖으로 장비가 튀어나가지 않게 한다.
  const columns=devices.length>9?4:3,slots=[];
  for(const kind of ['dgx-spark','jetson-thor']){
    const group=devices.filter(a=>a.form_factor===kind);
    for(let i=0;i<group.length;i+=columns)slots.push(group.slice(i,i+columns));
  }
  for(const asset of utility){
    let row=slots.find(row=>row.filter(Boolean).length<columns);
    if(!row){row=[];slots.push(row)}
    // 보조 장비는 우측 끝에 두어 낮은 시점에서도 전면 출입문에 가리지 않는다.
    let column=columns-1;while(row[column])column--;
    row[column]=asset;
  }
  const inset=.23,frontInset=.07,step=(w-2*inset)/columns,rowStep=2.94/Math.max(1,slots.length);
  // 전면 구획에 투영되는 깊이까지 계산한다. 카메라 각도가 바뀌어도
  // 본체·팬·이름표가 각자의 구획을 벗어나지 않도록 크기와 중심을 맞춘다.
  const scale=Math.min(.42,(step-.28)/(1.43+.86),
    (rowStep-.20-2*frontInset*YS/ZS)/(.48+2*.86*YS/ZS));
  const levels=slots.map((_,i)=>.47+(slots.length-1-i)*2.94/slots.length);
  g.setAttribute('data-rack-columns',columns);g.setAttribute('data-rack-shelves',slots.length);
  // 얕은 선반과 전면 구획을 먼저 그린다. 큰 선반 상판이 윗단을 가리지 않는다.
  levels.forEach((level,row)=>{
    g.appendChild(prism(x+.16,y+.1,z+level-.15,w-.32,d-.12,.05,'#39473f',{flat:true}));
    for(let column=0;column<columns;column++){
      const bay=el('g',{transform:roomFace(x+inset+column*step,y+d,z+level-.12)});
      bay.appendChild(roomRect(.025,0,step-.05,rowStep-.06,'#1c2a28',
        {stroke:'#4c6252','stroke-width':.018,rx:.025,'data-rack-bay':`${row}:${column}`}));
      g.appendChild(bay);
    }
  });
  levels.forEach((level,row)=>{
    slots[row].forEach((asset,column)=>{
      const slotX=x+inset+column*step;
      const dx=slotX+(step-(1.43+.86)*scale)/2-frontInset,dy=y+d-frontInset-.86*scale;
      let device;
      if(asset.vendor==='NVIDIA'){
        device=drawNvidiaDevice(asset,dx,dy,z+level,scale);
      }else{
        device=el('g',{'data-asset':asset.id,class:'hit',role:'button',tabindex:0,'aria-label':asset.name,
          on:{click:e=>{e.stopPropagation();openAsset(asset.id)},keydown:e=>{if(e.key==='Enter'){e.stopPropagation();openAsset(asset.id)}}}});
        const body=prism(dx,dy,z+level,1.43*scale,.86*scale,.18*scale,'#526066',{flat:true});
        body.setAttribute('data-device-body',asset.id);device.appendChild(body);
      }
      device.setAttribute('data-rack-slot',`${row}:${column}`);
      // 이름표는 본체 축소와 분리해 모든 선반에서 같은 크기로 읽히게 한다.
      const label=asset.id==='dgx-spark-01'?'SPARK-01':asset.id.toUpperCase();
      device.appendChild(roomLettering(slotX+step/2,y+d+.006,z+level-.09,label,.105,'#e0e7d5',{'text-anchor':'middle'}));
      g.appendChild(device);
    });
  });
  // 외곽 프레임은 마지막에 그린다. 장비는 이 프레임보다 안쪽에 있어야 한다.
  for(const dx of [0,w-.15]) {
    const depth=dx===0?.10:d; // 시야 쪽 측면은 개방하고 반대쪽은 선반 끝을 감싼다.
    g.appendChild(prism(x+dx,y+d-depth,z+.17,.15,depth,h-.17,'#36433e',{flat:true}));
    g.appendChild(roomLine([x+dx+.065,y+d+.007,z+.24],[x+dx+.065,y+d+.007,z+h-.08],green,1.5));
  }
  g.appendChild(prism(x,y,z+h-.4,w,d,.4,'#172121',{flat:true}));
  for(let i=0;i<17;i++)g.appendChild(quad(x+.28+i*.32,y+.12,z+h+.013,.14,d-.24,{fill:'#3d5144'}));
  g.appendChild(roomLettering(x+.25,y+d+.018,z+h-.135,'NVIDIA',.265,'#a6df43'));
  if(devices.some(assetDown)){const p=iso(x+w-.25,y+d,z+h);g.appendChild(warnBadge(p[0],p[1]-12))}
  tipify(g,{title:'NVIDIA AI COMPUTE',sub:rack.id+' · 3층 AI 전산실',color:green,
    rows:[['DGX Spark',devices.filter(a=>a.form_factor==='dgx-spark').length+'대'],
      ['Jetson Thor',devices.filter(a=>a.form_factor==='jetson-thor').length+'대'],
      ['인프라',utility.length+'대'],['배치','실물 장비의 교육용 전시 캐비닛']],
    foot:'각 장비를 개별 선택할 수 있습니다'});
  return g;
}
function drawLeadOffice(worker,x,y,z,detail) {
  const w=3.15,d=2.75;
  const g=el('g',{'data-office-zone':'ops-lead','data-office-bounds':[x,y,w,d].join(',')});
  g.appendChild(quad(x,y,z+.022,w,d,{fill:'#304540',stroke:'#c5b581','stroke-width':1}));
  // Rear partition and east glazing leave the front open for picking and sight.
  g.appendChild(prism(x,y,z,.075,d,1.12,'#566c67'));
  g.appendChild(prism(x,y,z,w,.08,1.12,'#4b615d'));
  const glass=[[x+w,y,z+.2],[x+w,y+d-.3,z+.2],[x+w,y+d-.3,z+1.4],[x+w,y,z+1.4]];
  g.appendChild(el('polygon',{points:pts(glass.map(p=>iso(...p))),fill:'#9ac5b4',opacity:.2,stroke:'#d7e6d6','stroke-width':.8}));
  g.appendChild(roomLettering(x+.28,y+.1,z+1.02,'OPERATIONS LEAD',.14,'#e5d8a7'));
  g.appendChild(prism(x+.25,y+.2,z,.9,.28,.48,'#33463d'));
  g.appendChild(quad(x+.27,y+.21,z+.49,.86,.26,{fill:'#b8a57d'}));
  g.appendChild(drawWorkstation(worker,x+.85,y+.67,z,detail));
  return g;
}

function equipmentKind(kind) {
  if(['cooling_tower','crac','chiller','fan_coil','economizer','heat_exchanger','cdu','water_tank','pump','immersion','weather','cold_plate','containment','raised_floor'].includes(kind))return 'cooling';
  if(['utility','generator','ups','pdu','substation','switchgear','transformer','ats','battery','fuel_tank','microgrid','busway','solar','storage','fuel_cell'].includes(kind))return 'power';
  return 'security';
}
function drawWorkstation(worker,x,y,z,detail) {
  const g=el('g');
  // Steel frame, worktop, two displays and an ergonomic chair.
  for(const dx of [0,1.2])g.appendChild(prism(x+dx,y,z,.07,.68,.65,'#344a57'));
  g.appendChild(prism(x-.08,y-.04,z+.65,1.43,.83,.065,'#8798a2'));
  for(let k=0;k<2;k++){
    g.appendChild(prism(x+.13+k*.61,y+.12,z+.715,.035,.12,.14,'#263e4d'));
    g.appendChild(prism(x+.03+k*.62,y+.1,z+.86,.57,.04,.35,'#273f50'));
    const screen=el('g',{transform:roomFace(x+.03+k*.62,y+.145,z+.86)});
    screen.appendChild(roomRect(.025,.025,.52,.3,'#193647'));
    for(let a=0;a<4;a++)screen.appendChild(roomRect(.065,.08+a*.045,.12+a*.07,.012,k?'#7cabc2':'#a3ca86'));
    g.appendChild(screen);
  }
  g.appendChild(quad(x+.4,y+.55,z+.72,.65,.16,{fill:'#394f5f'}));
  g.appendChild(prism(x+.5,y+1.05,z,.08,.08,.45,'#45616f'));
  g.appendChild(prism(x+.27,y+.88,z+.45,.52,.5,.08,'#2b4352'));
  // Keep the chair behind the front-facing sprite so faces stay visible.
  g.appendChild(prism(x+.27,y+1.27,z+.52,.52,.09,.57,'#2c4352'));
  if(worker.id)g.appendChild(drawWorkerFigure(worker,x+.53,y+1.1,z,true));
  return g;
}
function drawRoom(fid,detail) {
  if(fid==='B1')return drawFacilityFloor(detail);
  if(fid==='1F')return drawLobbyFloor(detail);
  if(fid==='3F')return drawAIFloor(detail);
  if(fid==='5F'||fid==='XOC')return drawControlCenterRoom(fid,detail);
  const g=el('g'),z=.22, racks=racksOf(fid), fac=physicalFacilitiesOf(fid);
  g.appendChild(el('g',{filter:'url(#plateShadow)'},[prism(0,0,0,GW,GD,z,'#647c8b',{flat:true})]));
  g.appendChild(quad(0,0,z+.004,GW,GD,{fill:'#647e8c'}));
  // Raised access floor: alternating panels and metal perimeter trim.
  for(let x=0;x<GW;x+=.5)for(let y=0;y<GD;y+=.5)
    g.appendChild(quad(x+.008,y+.008,z+.01,.484,.484,{fill:(Math.round((x+y)*2)%2)?'#657f8d':'#6c8794',stroke:'#8da1ac','stroke-width':.24}));
  g.appendChild(quad(.3,.3,z+.02,GW-.6,GD-.6,{fill:'none',stroke:'#d0b77e','stroke-width':1.15,opacity:.7}));
  // Cutaway walls stay at the back so equipment is never covered by a facade.
  g.appendChild(prism(0,0,z,GW,.14,1.65,'#8296a3'));
  g.appendChild(prism(0,0,z,.14,GD,1.3,'#738e9e'));
  for(let x=.8;x<GW;x+=2.1){
    g.appendChild(prism(x,0,z,.07,.25,1.68,'#b0bfc7'));
    g.appendChild(roomLine([x,.16,z+1.3],[Math.min(x+1.7,GW-.2),.16,z+1.3],'#b2d8e5',1.8));
  }
  // Glazed sections sit above the structural back wall, with a readable frame.
  for(let y=.5;y<GD-1;y+=1.5){
    const points=[[.15,y,z+.55],[.15,y+1.22,z+.55],[.15,y+1.22,z+1.22],[.15,y,z+1.22]];
    g.appendChild(el('polygon',{points:pts(points.map(p=>iso(...p))),fill:'#83bac6',opacity:.42,stroke:'#b7d1de','stroke-width':.8}));
  }
  const objects=[];
  const put=(x,y,node)=>objects.push({depth:x+y,node});
  if(racks.length) {
    racks.forEach((r,i)=>{
      const [x,y]=r.pos || [3+i*2.3,3];
      const aisle=ST?.aisles?.[r.aisle], rackWidth=r.style==='nvidia-ai'?6.2:2.05;
      g.appendChild(quad(x-.15,y+1.57,z+.027,rackWidth,.62,{fill:aisle?.cooling_kw>0?'#5cbed4':'#927b79',opacity:.75}));
      g.appendChild(quad(x-.15,y-.45,z+.027,rackWidth,.36,{fill:'#d6ac7a',opacity:.65}));
      // Perforated cold aisle tiles.
      for(let ix=0;ix<8;ix++)for(let iy=0;iy<3;iy++)g.appendChild(quad(x+ix*.23,y+1.65+iy*.14,z+.032,.12,.025,{fill:'#27748e',opacity:.75}));
      put(x+.85,y+.75,drawRoomRack(r,x,y,z));
      // Overhead cable tray, correctly connected to each physical cabinet.
      const tray=el('g',{'pointer-events':'none'});
      tray.appendChild(prism(x+.52,.4,z+3.65,.44,Math.max(y-.5,.3),.09,'#718995'));
      for(let yy=.55;yy<y;yy+=.3)tray.appendChild(roomLine([x+.5,yy,z+3.76],[x+.99,yy,z+3.76],'#bdc6c8',.7));
      tray.appendChild(roomLine([x+.65,.4,z+3.77],[x+.65,y+.2,z+3.77],'#e8b577',1.5));
      tray.appendChild(roomLine([x+.82,.4,z+3.77],[x+.82,y+.2,z+3.77],'#75c4d5',1.2));
      tray.appendChild(roomLine([x+.65,y+.2,z+3.77],[x+.65,y+.2,z+3.3],'#e8b577',1.5));
      put(x+.8,y+.35,tray);
          });
  }
  // Equipment is laid out deterministically from the ledger. The layout is a
  // schematic placement; it does not claim surveyed real-world dimensions.
  fac.forEach((item,i)=>{
    // Back wall first, then right wall. Keep the rack fronts unobstructed.
    const x=i<8?.55+i*1.38:10.35,y=i<8?.4:2+(i-8)*1.3;
    put(x+.5,y+.4,drawRoomEquipment(item,x,y,z));
  });
  if(fid==='4F') {
    const workers=crewOf(fid),lead=workers.find(w=>w.id==='ops-lead');
    const staff=workers.filter(w=>w.id!=='ops-lead'),rows=Math.ceil(staff.length/2);
    staff.forEach((worker,i)=>{
      const x=1.85+(i%2)*3.15,y=rows<=1?3.65:2.55+Math.floor(i/2)*2.9/Math.max(rows-1,1);
      const node=drawWorkstation(worker,x,y,z,detail);
      node.setAttribute('data-workstation-bounds',[x-.08,y-.04,1.43,1.5].join(','));
      put(x+.7,y+1.1,node);
    });
    if(lead)put(10,6.2,drawLeadOffice(lead,8.25,4.85,z,detail));
    // Operations video wall, rendered as instrument panels without invented numbers.
    for(let n=0;n<3;n++){
      const x=2+n*1.6;g.appendChild(prism(x,.17,z+1.05,1.45,.05,.83,'#263f50'));
      const f=el('g',{transform:roomFace(x,.23,z+1.05)});
      f.appendChild(roomRect(.06,.06,1.33,.71,'#173242'));
      assetsOf(fid).slice(0,5).forEach((a,k)=>f.appendChild(roomRect(.15,.16+k*.10,Math.max(.04,Math.min(assetState(a.id).util,1)*1.1),.035,n===1?'#a7c883':'#6a9fb9')));
      g.appendChild(f);
    }
    const control=el('a',{href:dcURL('agentops'),'aria-label':'운영 사무실 AI 에이전트 화면 열기'});
    // The wall uses positive z-up coordinates; lettering needs a y-down face.
    // Starting at the sign's top edge keeps the plate and text upright together.
    const [signX,signY]=iso(2,.24,z+2.27);
    const sign=el('g',{'data-office-sign':'agent-control',transform:`matrix(${XS},${YS},0,${ZS},${signX},${signY})`});
    sign.appendChild(roomRect(0,0,4.65,.34,'#223b32',{rx:.04}));
    sign.appendChild(el('text',{x:.2,y:.235,'font-size':.205,'font-family':'sans-serif','font-weight':600,fill:'#dcf2c4',text:'OPERATIONS OFFICE  ›'}));
    control.appendChild(sign);g.appendChild(control);
  } else {
    const workers=crewOf(fid),columns=Math.min(workers.length,3);
    workers.forEach((w,i)=>{
      const x=columns===1?(fid==='3F'?2.4:7.8):2.3+(i%columns)*8/(columns-1),y=(fid==='3F'?6.3:7)-Math.floor(i/columns)*1.3;
      put(x,y,drawRoomWorker(w,x,y,z,detail));
    });
  }
  // Discrete zone stripes on physical rack panels convey mixed logical zones.
  // Zone detail remains in the rail rather than placing duplicate assets in rooms.
  objects.sort((a,b)=>a.depth-b.depth).forEach(o=>g.appendChild(o.node));
  g.appendChild(roomLine([0,GD,z+.02],[GW,GD,z+.02],'#c0d1db',1.2));
  g.appendChild(roomLine([GW,0,z+.02],[GW,GD,z+.02],'#a5c1d2',1.2));
  return g;
}

/* 작은 설비도 팬·루버·실린더·절연애자·배관의 형태로 구분한다. 실측 도면은 아니다. */
function facilityCylinder(g,x,y,z,r,h,color) {
  const [cx,cy]=iso(x,y,z),ry=r*YS*1.25,rx=r*XS*1.4,top=cy-h*ZS;
  g.appendChild(el('path',{d:`M${cx-rx},${top} L${cx-rx},${cy} A${rx},${ry} 0 0 0 ${cx+rx},${cy} L${cx+rx},${top}Z`,fill:color,stroke:'#263e49','stroke-width':.65}));
  g.appendChild(el('ellipse',{cx,cy:top,rx,ry,fill:color,stroke:'#c9d5d2','stroke-width':.7}));
}
function facilityFan(g,x,y,z,r) {
  const p=iso(x,y,z),fan=el('g',{transform:`translate(${p.join(',')}) scale(1,${YS/XS})`});
  fan.appendChild(el('circle',{r,fill:'#263942',stroke:'#b0c2c8','stroke-width':1}));
  for(let k=0;k<5;k++)fan.appendChild(el('path',{d:`M0,-1 Q${r*.25},${-r*.85} ${r*.9},0 L0,2Z`,fill:'#75969d',transform:`rotate(${k*72})`}));
  fan.appendChild(el('circle',{r:1.6,fill:'#d0dcdb'}));g.appendChild(fan);
}
// 수평 압력용기: x축으로 놓인 원통과 원형 플랜지를 투영한다.
function facilityVessel(g,x,y,z,length,r,color) {
  const ring=(xx,fill)=>{
    const face=el('g',{transform:roomFace(xx,y,z,true)});
    face.appendChild(el('circle',{r,fill,stroke:'#b8cccb','stroke-width':.025}));
    return face;
  };
  g.appendChild(ring(x,color));
  g.appendChild(el('polygon',{points:pts([[x,y,z+r],[x+length,y,z+r],[x+length,y,z-r],[x,y,z-r]].map(p=>iso(...p))),fill:color,stroke:'#52757a','stroke-width':.5}));
  g.appendChild(roomLine([x,y,z+r*.56],[x+length,y,z+r*.56],'#d3ded6',1.2));
  const end=ring(x+length,'#668f94');
  end.appendChild(el('circle',{r:r*.71,fill:'#8dafad',stroke:'#d2dfd5','stroke-width':.015}));
  for(let n=0;n<8;n++)end.appendChild(el('circle',{cx:Math.cos(n*Math.PI/4)*r*.84,cy:Math.sin(n*Math.PI/4)*r*.84,r:.017,fill:'#374f56'}));
  g.appendChild(end);
}
function drawRoomEquipment(item,x,y,z,compact=false,placement=null) {
  const kind=item.kind,type=equipmentKind(kind),bad=facilityDown(item),out=item.location==='outdoor';
  const accent=bad?'#f48181':type==='cooling'?'#7dd5dd':type==='power'?'#e8bd79':kind==='fire'?'#ec9c92':'#b9cbd1';
  const open=e=>{e.stopPropagation();openFacility(item)};
  const g=el('g',{class:'hit','data-facility':item.id,role:'button',tabindex:0,
    'aria-label':(item.name||item.id)+' 설비 상세',on:{click:open,keydown:e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();open(e)}}}});
  const [w,d,h]=placement?.size||[out?1.65:compact?.96:1.08,out?1.1:.7,
    ['ups','battery','switchgear','ats','crac','fan_coil','cdu','storage','fuel_cell'].includes(kind)?1.45:1];
  const box=(xx,yy,zz,ww,dd,hh,color)=>g.appendChild(prism(xx,yy,zz,ww,dd,hh,color));
  const pipe=(a,b,color=accent,width=2)=>g.appendChild(roomLine(a,b,color,width));
  const vents=(height=h,color='#293f48')=>{
    const front=el('g',{transform:roomFace(x,y+d,z)});
    for(let n=.16;n<height-.15;n+=.12)front.appendChild(roomRect(.09,n,w-.18,.025,color));
    g.appendChild(front);
  };
  const faceRect=(xx,zz,ww,hh,color)=>{
    const front=el('g',{transform:roomFace(x,y+d+.01,z)});front.appendChild(roomRect(xx,zz,ww,hh,color));g.appendChild(front);
  };
  if(kind==='transformer' && !out) {
    // 실내 건식 변압기: 환기 외함 안에 3상 몰드 코일이 보인다.
    box(x,y,z,w,d,h,'#bac2b7');
    faceRect(w*.08,h*.13,w*.84,h*.7,'#31484c');
    for(let i=0;i<3;i++){
      faceRect(w*(.13+i*.26),h*.25,w*.21,h*.47,'#ad7b54');
      for(let n=0;n<6;n++)faceRect(w*(.14+i*.26),h*(.28+n*.065),w*.19,h*.014,'#d0a078');
      faceRect(w*(.21+i*.26),h*.35,w*.045,h*.27,'#535955');
    }
    for(let i=0;i<8;i++)faceRect(w*(.1+i*.105),h*.16,w*.014,h*.63,'#a3b5ae');
    faceRect(w*.42,h*.89,w*.16,h*.035,'#e9c375');
  } else if(['utility','substation','transformer'].includes(kind)) {
    if(kind==='utility') {
      for(const dx of [.2,w-.2])box(x+dx,y+.35,z,.07,.1,1.75,'#8b9695');
      pipe([x+.12,y+.4,z+1.5],[x+w-.1,y+.4,z+1.5],'#d5ba7c',3);
      for(let i=0;i<3;i++){box(x+.3+i*.35,y+.3,z+1.25,.08,.15,.35,'#94b9ac');pipe([x+.34+i*.35,y+.37,z+1.65],[x+.34+i*.35,y+.75,z+.35],'#b8915d',1.5)}
    } else {
      box(x,y,z,w,d,.85,'#7f9693');
      for(let i=.12;i<w-.1;i+=.15)box(x+i,y+d,z+.12,.06,.13,.56,'#526f70');
      for(let i=0;i<3;i++){const dx=w*(i+1)/4;box(x+dx,y+.3,z+.85,.07,.09,.43,'#6b8b77');for(let j=0;j<3;j++)box(x+dx-.055,y+.245,z+.94+j*.11,.18,.2,.025,'#b4c5a3')}
    }
  } else if(kind==='generator') {
    box(x,y,z,w,d,.92,'#a7a78e');vents(.92);
    faceRect(.08,.12,.5,.5,'#747e70');faceRect(.16,.4,.21,.13,'#243e3a');
    pipe([x+w*.7,y+.2,z+.92],[x+w*.7,y+.2,z+1.47],'#566a70',3);
    pipe([x+w*.7,y+.2,z+1.47],[x+w*.9,y+.2,z+1.47],'#566a70',3);
  } else if(['fuel_tank','water_tank'].includes(kind)) {
    g.appendChild(quad(x-.1,y-.1,z+.01,w+.2,d+.2,{fill:'#657b81',stroke:'#d4b87b','stroke-width':1.2}));
    facilityCylinder(g,x+w/2,y+d/2,z+.06,kind==='fuel_tank'?.42:.53,kind==='fuel_tank'?.8:1.5,kind==='fuel_tank'?'#b9a78b':'#aec3c8');
    pipe([x+w*.75,y+d/2,z+.15],[x+w,y+d/2,z+.15],'#6bc4d4',2);
    if(kind==='water_tank')for(let zz=.3;zz<1.45;zz+=.25)pipe([x+.4,y+d,z+zz],[x+w-.4,y+d,z+zz],'#647f8b',.6);
  } else if(kind==='cooling_tower') {
    for(const dx of [.1,w-.2])box(x+dx,y+.1,z,.12,d-.2,.22,'#657d83');
    box(x,y,z+.22,w,d,.96,'#94afb6');vents(1.1);
    facilityFan(g,x+w*.3,y+d/2,z+1.21,9);facilityFan(g,x+w*.72,y+d/2,z+1.21,9);
    pipe([x+w,y+.3,z+.75],[x+w+.1,y+.3,z+.75],'#76cbd7',2);
    pipe([x+w+.1,y+.3,z+.75],[x+w+.1,y+.3,z+.07],'#76cbd7',2);
  } else if(kind==='solar') {
    for(const dx of [.15,w-.2])box(x+dx,y+.18,z,.06,.5,.6,'#7b9097');
    const panel=el('g');
    for(let i=0;i<4;i++)for(let j=0;j<3;j++)panel.appendChild(quad(x+i*w/4,y+j*d/3,z+.63,w/4-.035,d/3-.035,{fill:'#345b8f',stroke:'#b2c9d7','stroke-width':.65}));
    g.appendChild(panel);
  } else if(kind==='chiller') {
    box(x,y,z,w,d,h*.12,'#4b747a');
    for(const dy of [.26,.73])facilityVessel(g,x+w*.04,y+d*dy,z+h*.37,w*.83,Math.min(d*.22,h*.23),'#adc7c3');
    for(const dx of [.16,.51]){
      box(x+w*dx,y+d*.14,z+h*.61,w*.23,d*.47,h*.24,'#426e73');
      for(let n=0;n<5;n++)box(x+w*(dx+.025+n*.041),y+d*.14,z+h*.61,w*.012,d*.47,h*.24,'#86a7a5');
    }
    box(x+w*.75,y+d*.5,z+h*.57,w*.23,d*.41,h*.43,'#d5d8c5');
    const controls=el('g',{transform:roomFace(x+w*.75,y+d*.91,z+h*.57)});
    controls.appendChild(roomRect(w*.035,h*.17,w*.16,h*.16,'#2d5258'));g.appendChild(controls);
    for(const dy of [.26,.73])pipe([x+w*.9,y+d*dy,z+h*.37],[x+w,y+d*dy,z+h*.37],'#70bdc8',2.5);
  } else if(kind==='pump') {
    box(x,y,z,w,d,h*.15,'#627e82');
    facilityVessel(g,x+w*.4,y+d*.5,z+h*.53,w*.5,h*.27,'#4c888c');
    for(let n=0;n<5;n++)box(x+w*(.42+n*.09),y+d*.22,z+h*.27,w*.025,d*.57,h*.51,'#739f9e');
    const volute=el('g',{transform:roomFace(x+w*.29,y+d*.5,z+h*.49,true)});
    volute.appendChild(el('circle',{r:h*.36,fill:'#8cacaa',stroke:'#456f78','stroke-width':.035}));g.appendChild(volute);
    pipe([x,y+d*.5,z+h*.49],[x+w*.28,y+d*.5,z+h*.49],'#83c4c9',2.6);
    pipe([x+w*.25,y+d*.5,z+h*.55],[x+w*.25,y+d*.5,z+h],'#83c4c9',2.5);
    pipe([x+w*.16,y+d*.5,z+h*.88],[x+w*.34,y+d*.5,z+h*.88],'#d2b477',1.4);
  } else if(kind==='heat_exchanger') {
    box(x,y,z,w,d,h*.1,'#617e85');
    for(let i=0;i<9;i++)box(x+w*(.16+i*.071),y+d*.12,z+h*.15,w*.04,d*.68,h*.74,i%2?'#b8c8bc':'#749395');
    for(const dx of [.07,.8])box(x+w*dx,y+d*.04,z+h*.07,w*.1,d*.88,h*.91,'#527d85');
    for(const zz of [.24,.78])pipe([x+w*.15,y+d,z+h*zz],[x+w*.83,y+d,z+h*zz],zz>.5?'#d8a77a':'#77c7da',2);
  } else if(kind==='economizer') {
    // 프리쿨링 전환용 배관·밸브 스키드, 냉동기나 공랭 팬과 구분한다.
    box(x,y,z,w,d,h*.1,'#637f7e');
    for(const dx of [.1,.85])box(x+w*dx,y+d*.2,z,w*.045,d*.65,h*.96,'#8eaaa5');
    for(const zz of [.36,.77]){
      pipe([x+w*.09,y+d*.5,z+h*zz],[x+w*.93,y+d*.5,z+h*zz],zz>.5?'#d1ad82':'#73bbca',3);
      box(x+w*.43,y+d*.37,z+h*(zz-.07),w*.15,d*.26,h*.14,'#c0b697');
      pipe([x+w*.5,y+d*.5,z+h*zz],[x+w*.5,y+d*.5,z+h*(zz+.17)],'#d1b677',1.3);
      pipe([x+w*.4,y+d*.5,z+h*(zz+.17)],[x+w*.61,y+d*.5,z+h*(zz+.17)],'#d1b677',1.3);
    }
  } else if(kind==='fire' && !item.subtype) {
    for(let i=0;i<3;i++){
      const dx=w*(.18+i*.31);
      facilityCylinder(g,x+dx,y+d*.45,z,w*.12,h*.78,'#b05f54');
      pipe([x+dx,y+d*.45,z+h*.78],[x+dx,y+d*.45,z+h*.94],'#c7b49a',1.5);
      const gauge=iso(x+dx,y+d*.58,z+h*.84);g.appendChild(el('circle',{cx:gauge[0],cy:gauge[1],r:1.25,fill:'#e1ded0',stroke:'#617475','stroke-width':.5}));
    }
    pipe([x+w*.09,y+d*.45,z+h*.95],[x+w*.95,y+d*.45,z+h*.95],'#b49c7a',2);
    pipe([x+w*.93,y+d*.45,z+h*.95],[x+w*.93,y+d*.45,z+h],'#b49c7a',2);
  } else if(kind==='fire') {
    box(x,y,z,w,d,h,item.subtype==='panel'?'#b87870':'#d0d8cd');
    faceRect(w*.12,h*.45,w*.76,h*.35,'#344f53');
    faceRect(w*.17,h*.59,w*.34,h*.09,'#80b9ac');
    for(let i=0;i<4;i++)faceRect(w*(.16+i*.18),h*.23,w*.09,h*.07,i?'#c8b590':'#d97762');
  } else if(kind==='mantrap') {
    // 원형 인터록 포털: 앞·뒤 곡면 도어와 투명 측벽, 별도 리더.
    const circle=(zz)=>Array.from({length:33},(_,i)=>iso(x+w/2+Math.cos(i*Math.PI/16)*w*.48,y+d/2+Math.sin(i*Math.PI/16)*d*.48,z+zz));
    const bottom=circle(.04),top=circle(h-.12);
    g.appendChild(el('polygon',{points:pts(bottom),fill:'#8ca3a0',stroke:'#c9d8ca','stroke-width':.8}));
    for(let n=0;n<32;n++)g.appendChild(el('polygon',{points:pts([bottom[n],bottom[n+1],top[n+1],top[n]]),fill:'#a5d0cf',opacity:.18,stroke:'none'}));
    for(const dx of [.03,.94])box(x+w*dx,y+d*.42,z,w*.035,d*.16,h,'#a6bdb6');
    for(const yy of [y+d*.02,y+d*.98])pipe([x+w*.5,yy,z+.08],[x+w*.5,yy,z+h-.12],'#e1eadd',.8);
    g.appendChild(el('polygon',{points:pts(top),fill:'#b4c8bb',opacity:.85,stroke:'#d9e2d1','stroke-width':.9}));
    box(x+w*.87,y+d*.79,z+h*.4,w*.075,d*.06,h*.21,'#304e51');
  } else if(['door','metal_detector'].includes(kind)) {
    const height=placement?h:1.65,depth=kind==='metal_detector'?d:d*.4;
    for(const dx of [0,w-.1])box(x+dx,y,z,.1,depth,height,kind==='metal_detector'?'#c3c8bb':'#657f89');
    box(x,y,z+height-.1,w,depth,.1,'#819f9f');
    if(kind==='metal_detector'){
      for(const dx of [.025,w-.075])box(x+dx,y+depth,z+height*.22,.025,.01,height*.62,'#526f70');
      box(x+w*.35,y+depth,z+height-.085,w*.3,.012,.055,'#314d51');
    } else {const p=[[x+.12,y+depth,z+.05],[x+w-.12,y+depth,z+.05],[x+w-.12,y+depth,z+height-.12],[x+.12,y+depth,z+height-.12]];g.appendChild(el('polygon',{points:pts(p.map(a=>iso(...a))),fill:'#97c6ca',opacity:.42,stroke:'#b2d7d4','stroke-width':1}))}
  } else if(['cctv','weather'].includes(kind)) {
    if(kind==='cctv' && placement?.mount_z){
      pipe([x,y,z+h*.4],[x,y+d*.5,z+h*.4],'#c4cebd',2);
      box(x,y+d*.3,z,w,d*.7,h*.62,'#d6dbcc');
      const lens=el('g',{transform:roomFace(x,y+d,z)});lens.appendChild(el('circle',{cx:w*.5,cy:h*.3,r:w*.2,fill:'#253f4f',stroke:'#80a6a5','stroke-width':.025}));g.appendChild(lens);
    } else if(kind==='cctv'){box(x+w/2,y+d/2,z,.055,.065,1.6,'#a6b9bc');box(x+w/2-.18,y+d/2,z+1.5,.52,.2,.22,'#cad4cf');box(x+w/2+.32,y+d/2,z+1.53,.06,.18,.15,'#253f4f')}
    else {box(x+w/2,y+d/2,z,.055,.065,1.6,'#a6b9bc');for(const dx of [-.35,0,.35])pipe([x+w/2,y+d/2,z+1.65],[x+w/2+dx,y+d/2+.25,z+1.65],'#c7d5ce',1.4);box(x+w/2-.2,y+d/2-.1,z+.8,.43,.25,.4,'#d5d9ca')}
  } else if(kind==='guard_post') {
    box(x,y,z,w,d,1.3,'#b2b5a5');box(x-.07,y-.06,z+1.3,w+.14,d+.12,.1,'#6f8c87');
    faceRect(.12,.55,w-.24,.5,'#43767f');faceRect(w*.6,.06,.42,.95,'#54777a');
  } else if(kind==='immersion') {
    box(x,y,z,w,d,.55,'#9dafb3');g.appendChild(quad(x+.09,y+.09,z+.56,w-.18,d-.18,{fill:'#679c95'}));
    for(let i=0;i<4;i++)box(x+.14+i*.2,y+.18,z+.48,.09,d-.36,.26,'#344e56');
  } else if(kind==='badge_reader' && placement) {
    box(x,y,z,w,d,h,'#334d54');
    faceRect(w*.15,h*.27,w*.7,h*.5,'#a5c7c3');faceRect(w*.34,h*.12,w*.32,h*.05,'#aadd80');
  } else if(kind==='busway' && placement?.mount_z) {
    box(x,y,z,w,d,h,'#c6ba8a');
    for(const dx of [.15,w-.35]){pipe([x+dx,y+d/2,z+h],[x+dx,y+d/2,z+h+.3],'#aebfc0',.8);box(x+dx,y,z-.25,.22,d+.08,.25,'#768d8d')}
  } else if(kind==='busway') {
    for(const dx of [.1,w-.15])box(x+dx,y+.15,z,.035,.05,1.5,'#7e949e');
    box(x,y+.1,z+1.4,w,.23,.13,'#c6ba8a');
    for(let i=0;i<2;i++)box(x+.15+i*.5,y+.05,z+1.1,.22,.32,.3,'#7d9294');
  } else if(kind==='rack_mover') {
    box(x,y,z+.1,w,d,.28,'#c0a677');for(const dx of [.13,w-.18])facilityCylinder(g,x+dx,y+d,z,.09,.16,'#344950');
    box(x+.15,y+.15,z+.38,w-.3,d-.3,.12,'#7d9596');
  } else if(['switchgear','ats','ups','battery'].includes(kind)) {
    const dark=['ups','battery'].includes(kind);
    box(x,y,z,w,d,h,dark?'#627876':'#c5cabc');
    const bays=kind==='switchgear'?3:kind==='ups'?2:1;
    for(let n=0;n<bays;n++){
      const left=w*(n/bays+.035),width=w*(1/bays-.07);
      faceRect(left,h*.07,width,h*.87,dark?'#354e52':'#a7b5aa');
      faceRect(left+width*.1,h*.67,width*.72,h*.18,'#304d53');
      faceRect(left+width*.17,h*.73,width*.4,h*.06,'#81b6aa');
      faceRect(left+width*.85,h*.42,width*.035,h*.14,'#d5dac4');
      if(kind==='ups' || kind==='battery')for(let row=0;row<4;row++){
        faceRect(left+width*.08,h*(.13+row*.12),width*.7,h*.08,'#718981');
        faceRect(left+width*.12,h*(.15+row*.12),width*.035,h*.025,'#bbd5a4');
        for(let slot=0;slot<4;slot++)faceRect(left+width*(.23+slot*.12),h*(.16+row*.12),width*.06,h*.012,'#2d454b');
      } else {
        for(let slot=0;slot<4;slot++)faceRect(left+width*.12,h*(.15+slot*.045),width*.65,h*.012,'#65817d');
        faceRect(left+width*.48,h*.4,width*.025,h*.24,'#566e66');
        if(kind==='ats'){
          faceRect(left+width*.25,h*.58,width*.49,h*.023,'#d3c39d');
          for(const offset of [.24,.7])faceRect(left+width*offset,h*.56,width*.055,h*.09,'#b9ce9e');
        }
      }
    }
  } else if(kind==='disk_shredder') {
    box(x,y,z,w,d,h*.76,'#9ba99e');
    faceRect(w*.11,h*.12,w*.78,h*.51,'#536d70');
    faceRect(w*.16,h*.42,w*.66,h*.035,'#233f49');
    box(x+w*.1,y+d*.12,z+h*.76,w*.8,d*.76,h*.21,'#b8c3ad');
    g.appendChild(quad(x+w*.22,y+d*.29,z+h*.975,w*.56,d*.38,{fill:'#2c454b',stroke:'#d1d7bd','stroke-width':.6}));
    faceRect(w*.68,h*.8,w*.065,h*.065,'#cd7765');
  } else {
    box(x,y,z,w,d,h,type==='cooling'?'#8aa9b1':kind==='battery'?'#6e8684':'#98a8a4');
    faceRect(.1,h-.48,w-.2,.29,'#263e48');faceRect(.16,h-.4,w-.32,.05,accent);
    if(kind==='battery')for(let i=0;i<4;i++){faceRect(.14,.12+i*.2,w-.28,.14,'#394f4e');faceRect(.2,.16+i*.2,.09,.035,'#a6cf96')}
    else vents(h-.55);
    if(['crac','fan_coil','cdu'].includes(kind)){
      // 실내 공조 캐비닛은 전면 흡입 그릴, CDU는 배관 접속부로 구분한다.
      faceRect(w*.08,h*.05,w*.84,h*.025,'#d0d5c2');
      for(const dx of [w*.86,w*.94])pipe([x+dx,y,z+.06],[x+dx,y,z+.73],dx<w*.9?'#75c4d4':'#d0a07c',1.8);
    }
  }
  const point=iso(x+w*.5,y+d,z+.12);
  g.appendChild(el('circle',{cx:point[0],cy:point[1],r:2,fill:bad?'#f48181':'#b4d6a0',stroke:'#263e49','stroke-width':.7}));
  if(bad){const p=iso(x+w/2,y+d/2,z+h+.1);g.appendChild(warnBadge(p[0],p[1]-5))}
  tipify(g,{title:item.name||item.id,sub:item.id+' / '+(out?'옥외':item.floor),color:accent,
    rows:[['설비',facilityGuide(item).title||kind],['고장 주입',bad?'활성 이상 있음':'해당 설비 활성 고장 없음']],
    foot:'교육용 가상 시설 · 역할·설계값·상태·고장 영향 보기'});
  return g;
}
function drawOutdoor(detail) {
  const g=el('g',{'data-site':'outdoor'}),z=.13,items=physicalFacilitiesOf('SITE');
  g.appendChild(prism(0,0,0,GW,GD,z,'#64736c'));
  g.appendChild(quad(.15,.15,z+.01,GW-.3,GD-.3,{fill:'#718078'}));
  // Outdoor yard: no storey walls, open fence and separate equipment plinths.
  for(let x=0;x<=GW;x+=1.5){g.appendChild(prism(x,0,z,.035,.035,.75,'#a1b2a4'));if(x<GW)g.appendChild(roomLine([x,0,z+.55],[x+1.5,0,z+.55],'#a3b4a6',1))}
  for(const yy of [2.65,5.02])g.appendChild(roomLine([.3,yy,z+.02],[GW-.3,yy,z+.02],'#b8b79d',2));
  items.slice().sort((a,b)=>a.site_pos[0]+a.site_pos[1]-b.site_pos[0]-b.site_pos[1]).forEach(item=>{
    const [x,y]=item.site_pos;
    g.appendChild(quad(x-.1,y-.12,z+.018,1.9,1.45,{fill:'#89928a',stroke:'#c2c0a5','stroke-width':.7}));
    g.appendChild(drawRoomEquipment(item,x,y,z+.02));
    if(detail){const p=iso(x+.8,y+1.35,z);pill(p[0],p[1]+8,item.name||item.id,{size:8,anchor:'mid',gap:1,color:'#e0e5d9'})}
  });
  return g;
}

/* 지하 설비층과 1층 로비의 건축 배치. 좌표는 화면용 상대 단위이며 시공 치수·법정 이격 거리가 아니다.
 * 설비 ID는 assets.yaml을 참조한다. 방·문·점검 여유와 동선을 함께 수정한다. */
const BASEMENT_FLOORPLAN = {
  rooms: [
    {id:'electrical',name:'전기실 · UPS',rect:[.16,.16,5.49,4.1],color:'#a39c86'},
    {id:'mechanical',name:'기계실',rect:[5.8,.16,6.04,4.1],color:'#7b9290'},
    {id:'battery',name:'배터리실',rect:[.16,5.46,3.02,2.38],color:'#92978a'},
    {id:'media',name:'매체 폐기실',rect:[3.36,5.46,2.21,2.38],color:'#9a9387'},
    {id:'core',name:'계단·승강기 코어',rect:[5.78,5.46,2.2,2.38],color:'#89969b'},
    {id:'suppression',name:'소화용기실',rect:[8.16,5.46,3.68,2.38],color:'#a7978f'}
  ],
  doors: [
    {id:'electrical',name:'전기실 출입',x:3.05,y:4.3,width:1,axis:'x',height:1.25,into:-1},
    {id:'suppression',name:'소화용기실 출입',x:10.1,y:5.38,width:1.1,axis:'x',height:1.25,into:1},
    {id:'mechanical',name:'기계실 반입문',x:9,y:4.3,width:1.65,axis:'x',height:1.25,double:true,into:-1},
    {id:'battery',name:'배터리실 출입',x:2.15,y:5.38,width:.95,axis:'x',height:1.25,into:1},
    {id:'media',name:'매체 폐기실 출입',x:3.75,y:5.38,width:1.2,axis:'x',height:1.25,into:1},
    {id:'core',name:'계단·승강기 출입',x:6.15,y:5.38,width:1.6,axis:'x',height:1.25,glass:true,double:true,into:1},
    {id:'exit',name:'피난계단 연결',x:.08,y:4.32,width:1.04,axis:'y',height:1.25,double:true,into:-1}
  ],
  equipment: {
    'swgr-01': {room:'electrical',pos:[.55,.65],size:[1.38,.72,1.55],reason:'수전측 반을 전기실 뒤쪽에 두고 전면 조작·점검 공간을 비웁니다.'},
    'tr-01': {room:'electrical',pos:[2.52,.65],size:[1.22,.85,1.32],reason:'수전반 가까운 변압기 구획입니다. 실내 외함형 변압기를 표현합니다.'},
    'ats-01': {room:'electrical',pos:[.55,2.52],size:[.8,.65,1.42],reason:'UPS 앞단의 절체반입니다. 하부 급전 경로와 점검 통로를 구분합니다.'},
    'ups-01': {room:'electrical',pos:[1.63,2.52],size:[1.13,.65,1.48],reason:'배터리실과 가까운 전기실 전면에 두고, 정면 점검 여유를 남깁니다.'},
    'batt-01': {room:'battery',pos:[.5,5.78],size:[.68,.66,1.25],reason:'별도 배터리실의 캐비닛 A입니다. 앞쪽 공통 점검 공간으로 접근합니다.'},
    'batt-02': {room:'battery',pos:[1.36,5.78],size:[.68,.66,1.25],reason:'캐비닛 A와 나란히 두되 출입문과 점검 동선을 막지 않습니다.'},
    'chiller-01': {room:'mechanical',pos:[6.25,.82],size:[2.35,1.02,1.06],reason:'냉동기는 기계실의 중심 설비입니다. 옆 열교환기·펌프와 연결하고 전면 점검 공간을 확보합니다.'},
    'hx-01': {room:'mechanical',pos:[9.2,.67],size:[.62,.75,1.08],reason:'판형 열교환기를 냉동기와 옥외 냉각 배관 사이에 둡니다.'},
    'eco-01': {room:'mechanical',pos:[10.45,.67],size:[.96,.77,1.05],reason:'옥외 냉각 계통과 가까운 배관·밸브 스키드로 표현합니다.'},
    'pump-pcw-01': {room:'mechanical',pos:[6.32,2.66],size:[.8,.47,.43],reason:'냉수 주 펌프를 공통 헤더 앞의 방진 베이스에 놓습니다.'},
    'pump-pcw-02': {room:'mechanical',pos:[7.55,2.66],size:[.8,.47,.43],reason:'예비 펌프는 주 펌프와 나란히 배치합니다. 예비 설정은 운전 상태와 별개입니다.'},
    'pump-cw-01': {room:'mechanical',pos:[9.02,2.3],size:[.88,.5,.46],reason:'냉각수 펌프는 냉각탑으로 이어지는 배관측에 배치합니다.'},
    'fm200-01': {room:'suppression',pos:[8.85,5.85],size:[1.1,.65,1.28],reason:'소화용기는 독립된 용기실에서 점검하도록 분리하고 상부 헤더로 연결합니다.'},
    'vesda-01': {room:'electrical',pos:[4.72,.18],size:[.48,.14,.39],mount_z:1.03,reason:'배터리실의 샘플링 배관을 연결한 감지기를 인접 전기실 벽의 점검 가능한 위치에 둡니다.'},
    'shred-01': {room:'media',pos:[3.67,6.51],size:[.88,.78,.91],reason:'전기실·소화용기실과 분리된 매체 폐기 작업실입니다. 출입문 앞 인계·작업 공간을 남깁니다.'}
  },
  clearances:[
    {id:'switchgear-front',rect:[.5,1.53,3.28,.67]},
    {id:'ups-front',rect:[.5,3.27,2.46,.69]},
    {id:'battery-front',rect:[.42,6.64,1.72,.8]},
    {id:'chiller-front',rect:[6.16,1.99,2.48,.5]},
    {id:'mechanical-front',rect:[6.15,3.34,4.6,.65]},
    {id:'media-work',rect:[3.54,5.65,1.82,.66]}
  ],
  paths:[
    {id:'service',color:'#e4c48f',points:[[6.9,5.45],[6.9,4.83],[9.83,4.83],[9.83,3.72],[6.4,3.72]],label:'장비 반입·정비'},
    {id:'electric-access',color:'#e4c48f',points:[[3.57,4.83],[3.57,3.65],[1.18,3.65]]},
    {id:'battery-access',color:'#e4c48f',points:[[2.65,4.83],[2.65,7.1],[1.02,7.1]]},
    {id:'exit',color:'#b5cabc',points:[[7.1,4.83],[.1,4.83]],label:'비상 출구'}
  ]
};
const LOBBY_FLOORPLAN = {
  equipment: {
    'fp-01': {roomName:'안내·방재 데스크',pos:[4.1,.18],size:[.7,.16,.6],mount_z:1.03,reason:'안내 데스크 뒤 벽의 소방 수신반입니다. 출입 담당자가 바로 확인할 수 있는 위치입니다.'},
    'cctv-01': {roomName:'보안 검색 구역',pos:[10.65,3.18],size:[.4,.36,.3],mount_z:1.5,reason:'보안 경계 벽에 부착하여 검색대와 정문을 향하게 배치합니다.'},
    'mantrap-01': {roomName:'통제구역 경계',pos:[8.2,2.9],size:[1.6,1.2,1.7],reason:'검색대 다음의 인터록 포털입니다. 인증을 거쳐 계단·승강기 로비로 진입하는 경계에 둡니다.'},
    'mdet-01': {roomName:'보안 검색 구역',pos:[8.36,5.3],size:[1.28,.36,1.65],reason:'정문과 맨트랩을 연결하는 직선 동선에 놓고, 검색 전후 대기 공간을 남깁니다.'}
  },
  entrance:{id:'entrance',asset:'door-main',name:'정문',x:8,y:7.91,width:2,axis:'x',height:1.8,double:true,glass:true,into:-1}
};
function facilityPlacement(item) {
  if(item.location==='outdoor')return null;
  if(item.floor==='3F')return item.id==='door-3f'?{roomName:'AI 전산실 출입구',reason:'외벽의 출입문에서 전면 작업 통로까지 동선이 이어집니다. 문 개폐 범위에는 장비를 두지 않습니다.'}:AI_FLOORPLAN.equipment[item.id]||null;
  if(item.floor==='B1'){
    const plan=BASEMENT_FLOORPLAN.equipment[item.id];
    return plan?{...plan,roomName:BASEMENT_FLOORPLAN.rooms.find(r=>r.id===plan.room)?.name}:null;
  }
  if(item.floor==='1F'){
    if(item.id==='door-main')return {roomName:'보안 로비 · 외벽',reason:'외벽의 정문에서 검색대·맨트랩·승강기 로비까지 동선이 이어집니다.'};
    return LOBBY_FLOORPLAN.equipment[item.id]||null;
  }
  return null;
}
function planRoute(points,z,color,attributes={}) {
  const g=el('g',{'pointer-events':'none',...attributes});
  g.appendChild(el('polyline',{points:pts(points.map(p=>iso(...p,z))),fill:'none',stroke:color,'stroke-width':2.2,'stroke-linejoin':'round',opacity:.65}));
  for(let n=1;n<points.length;n++){
    const a=points[n-1],b=points[n],dx=b[0]-a[0],dy=b[1]-a[1],len=Math.hypot(dx,dy);if(len<.45)continue;
    const ux=dx/len,uy=dy/len,c=[a[0]+dx*.63,a[1]+dy*.63],back=[c[0]-ux*.19,c[1]-uy*.19];
    g.appendChild(el('polygon',{points:pts([iso(...c,z),iso(back[0]-uy*.09,back[1]+ux*.09,z),iso(back[0]+uy*.09,back[1]-ux*.09,z)]),fill:color,opacity:.9}));
  }
  return g;
}
function planDoor(door,z,asset) {
  const g=el('g',{'data-plan-door':door.id,'data-door-axis':door.axis,'data-door-opening':[door.x,door.y,door.width].join(',')});
  const p=(along,depth,height)=>door.axis==='x'?[door.x+along,door.y+depth,z+height]:[door.x+depth,door.y+along,z+height];
  const post=(along,depth,w,d,h,color)=>{const v=p(along,depth,0);g.appendChild(prism(...v,door.axis==='x'?w:d,door.axis==='x'?d:w,h,color))};
  post(-.035,-.055,.07,.13,door.height,'#c1cbc7');post(door.width-.035,-.055,.07,.13,door.height,'#c1cbc7');
  const beam=p(-.035,-.055,door.height-.085);g.appendChild(prism(...beam,door.axis==='x'?door.width+.07:.13,door.axis==='x'?.13:door.width+.07,.085,'#b3c0ba'));
  const threshold=[p(0,-.12,.02),p(door.width,-.12,.02),p(door.width,.12,.02),p(0,.12,.02)];
  g.appendChild(el('polygon',{points:pts(threshold.map(v=>iso(...v))),fill:'#bbc3b7',stroke:'#dce0cb','stroke-width':.45}));
  const leaves=door.double?2:1,span=door.width/leaves;
  for(let n=0;n<leaves;n++){
    const hinge=n?door.width:0,sign=n?-1:1,dx=sign*span*.35,depth=door.into*span*.65;
    const corners=[p(hinge,0,.05),p(hinge+dx,depth,.05),p(hinge+dx,depth,door.height-.14),p(hinge,0,door.height-.14)];
    g.appendChild(el('polygon',{points:pts(corners.map(v=>iso(...v))),fill:door.glass?'#86b9be':'#acb7af',opacity:door.glass?.34:.8,stroke:'#d2d9cc','stroke-width':.8}));
    const arc=[];for(let k=0;k<=10;k++){const angle=k*Math.PI/20;arc.push(iso(...p(hinge+sign*span*Math.cos(angle),door.into*span*Math.sin(angle),.027)))}
    g.appendChild(el('polyline',{points:pts(arc),fill:'none',stroke:'#cbd0b6','stroke-width':.55,'stroke-dasharray':'2 2',opacity:.5}));
  }
  if(['exit','entrance','loading'].includes(door.id)){
    const [sx,sy]=iso(...p(door.width/2,0,door.height+.05));
    g.appendChild(el('rect',{x:sx-12,y:sy-7,width:24,height:8,rx:1,fill:door.id==='exit'?'#437960':'#485f64'}));
    g.appendChild(el('text',{x:sx,y:sy-.9,'text-anchor':'middle','font-size':5.2,fill:'#e5efdc','font-family':'sans-serif',text:door.id==='exit'?'STAIR':door.id==='loading'?'SERVICE':'ENTRY'}));
  }
  if(asset){
    const open=e=>{e.stopPropagation();openFacility(asset)};
    g.setAttribute('data-facility',asset.id);g.setAttribute('class','hit');g.setAttribute('role','button');g.setAttribute('tabindex',0);
    g.setAttribute('aria-label',asset.name+' 상세');
    g.addEventListener('click',open);g.addEventListener('keydown',e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();open(e)}});
    tipify(g,{title:asset.name,sub:'1F / 보안 로비 외벽',rows:[['출입 경로','정문 → 검색 → 맨트랩 → 계단·승강기']],foot:'선택하면 출입 설비 상세를 엽니다'});
  }
  return g;
}
function drawFacilityFloor(detail) {
  const g=el('g',{'data-floorplan':'basement'}),z=.22,P=BASEMENT_FLOORPLAN,objects=[],wide=$('#scene').clientWidth>=560;
  const put=(x,y,node)=>objects.push({depth:x+y,node});
  g.appendChild(el('g',{filter:'url(#plateShadow)'},[prism(0,0,0,GW,GD,z,'#6c7877',{flat:true})]));
  g.appendChild(quad(0,0,z+.01,GW,GD,{fill:'#b4baae'}));
  P.rooms.forEach(room=>{
    const [x,y,w,d]=room.rect;
    g.appendChild(quad(x,y,z+.018,w,d,{fill:room.color,'data-plan-room':room.id,'data-room-bounds':room.rect.join(',')}));
    if(room.id==='lobby')for(let xx=x;xx<x+w;xx+=.4)for(let yy=y;yy<y+d;yy+=.4)
      g.appendChild(quad(xx,yy,z+.025,Math.min(.39,x+w-xx),Math.min(.39,y+d-yy),{fill:'#b5bbaf',stroke:'#929f98','stroke-width':.18}));
  });
  g.appendChild(quad(.12,4.39,z+.035,11.76,.86,{fill:'#617d77','data-corridor':'main','data-corridor-bounds':'.12,4.39,11.76,.86'}));
  for(const yy of [4.42,5.22])g.appendChild(roomLine([.2,yy,z+.041],[11.8,yy,z+.041],'#cbd5b8',.65));
  P.clearances.forEach(area=>{
    const [x,y,w,d]=area.rect;
    g.appendChild(quad(x,y,z+.04,w,d,{fill:'#d1c9a4',opacity:.19,stroke:'#e4d3a1','stroke-width':.6,'stroke-dasharray':'3 2','data-maintenance-clearance':area.id,'data-clearance-bounds':area.rect.join(',')}));
    for(let xx=x;xx<x+w;xx+=.22)g.appendChild(roomLine([xx,y,z+.041],[Math.min(xx+.16,x+w),y+Math.min(.16,d),z+.041],'#dfcf9d',.6));
  });
  P.paths.forEach(path=>g.appendChild(planRoute(path.points,z+.055,path.color,{'data-walkpath':path.id})));
  const wall=(x,y,w,d,h=.38)=>put(x+w/2,y+d/2,el('g',{'data-plan-wall':'','data-wall-bounds':[x,y,w,d].join(',')},[prism(x,y,z,w,d,h,'#b4beba')]));
  // 긴 뒤 벽을 중심점으로 깊이 정렬하면 가까운 장비 위에 그려진다.
  // 외곽 뒤 벽은 배경에 먼저 그리고, 내부 벽·설비만 깊이 정렬한다.
  g.appendChild(prism(0,0,z,12,.12,1.72,'#b4beba'));
  g.appendChild(prism(0,.12,z,.12,4.2,1.28,'#b4beba'));
  wall(0,5.36,.12,2.64,.3);
  wall(11.88,.12,.12,7.76,.22);
  wall(0,7.88,12,.12,.18);
  wall(5.68,.12,.12,4.18,.28);
  for(const x of [3.23,5.64,8.02])wall(x,5.44,.12,2.44,.22);
  for(const [a,b] of [[.12,3.01],[4.09,8.96],[10.69,11.88]])wall(a,4.27,b-a,.12,.33);
  for(const [a,b] of [[.12,2.11],[3.14,3.71],[4.99,6.11],[7.79,10.06],[11.24,11.88]])wall(a,5.32,b-a,.12,.22);
  const fac=physicalFacilitiesOf('B1');
  for(const door of P.doors)put(door.x+(door.axis==='x'?door.width/2:0),door.y+(door.axis==='y'?door.width/2:0),planDoor({...door,height:door.id==='exit'?1.25:.58},z,door.asset?fac.find(f=>f.id===door.asset):null));
  // Cooling pipework stays in the mechanical room; the electrical room has its own tray.
  const services=el('g',{'pointer-events':'none','data-plant-connections':'mechanical'});
  for(const [offset,color] of [[0,'#68b4c5'],[.17,'#d1a67f']]){
    services.appendChild(el('polyline',{points:pts([[11.8,.3+offset,.44],[6.0,.3+offset,.44],[6.0,2.4+offset,.44],[9.9,2.4+offset,.44]].map(p=>iso(p[0],p[1],z+p[2]))),fill:'none',stroke:color,'stroke-width':2.6,'stroke-linejoin':'round'}));
    for(const xx of [6.72,7.94,9.48])services.appendChild(roomLine([xx,2.4+offset,z+.44],[xx,2.8,z+.3],color,1.7));
  }
  put(8,1.2,services);
  const tray=el('g',{'pointer-events':'none'});
  tray.appendChild(prism(.45,.3,z+1.6,3.37,.19,.07,'#889186'));
  tray.appendChild(roomLine([.5,.4,z+1.69],[3.8,.4,z+1.69],'#d9b878',1.7));
  for(let xx=.5;xx<3.8;xx+=.26)tray.appendChild(roomLine([xx,.29,z+1.69],[xx,.5,z+1.69],'#c5c8b5',.5));
  put(2,.4,tray);
  // Drain grating belongs to the wet mechanical zone.
  for(let xx=6.03;xx<11.65;xx+=.16)g.appendChild(quad(xx,3.18,z+.04,.08,.08,{fill:'#42595c'}));
  for(const item of fac){
    const placement=P.equipment[item.id];if(!placement)continue;
    const [x,y]=placement.pos,ground=z+(placement.mount_z||0);
    const node=drawRoomEquipment(item,x,y,ground,true,placement);
    node.setAttribute('data-plan-equipment',item.id);node.setAttribute('data-equipment-room',placement.room);
    node.setAttribute('data-equipment-bounds',[x,y,...placement.size.slice(0,2)].join(','));
    if(placement.mount_z)node.setAttribute('data-wall-mounted','true');
    put(x+placement.size[0]/2,y+placement.size[1]/2,node);
  }
  // Sampling line runs to the detector in the battery room.
  put(1,5.42,el('g',{'pointer-events':'none'},[
    roomLine([.45,5.43,z+1.5],[2.9,5.43,z+1.5],'#d0a7a0',1.5),
    roomLine([.72,5.43,z+1.5],[.72,5.43,z+1.12],'#d0a7a0',1.2)
  ]));
  const core=el('g',{'data-architectural-feature':'stairs-lift'});
  core.appendChild(prism(5.86,6.45,z,.73,1.2,1.35,'#73898b'));
  const lift=el('g',{transform:roomFace(5.87,7.66,z)});lift.appendChild(roomRect(.06,.05,.6,1.17,'#a3b4b2'));lift.appendChild(roomRect(.35,.05,.014,1.17,'#597577'));core.appendChild(lift);
  for(let i=0;i<7;i++)core.appendChild(prism(6.88,5.98+i*.24,z,.79,.25,(i+1)*.18,'#a2afad'));
  for(const xx of [6.86,7.72]){core.appendChild(roomLine([xx,6.05,z+.5],[xx,7.55,z+1.58],'#d2d7c5',1.3));for(let i=0;i<3;i++)core.appendChild(roomLine([xx,6.13+i*.62,z+.22+i*.44],[xx,6.13+i*.62,z+.57+i*.44],'#819897',.9))}
  put(6.8,7.0,core);
  for(const worker of crewOf('B1')){
    const [x,y]=[4.8,3.5];
    put(x,y,drawRoomWorker(worker,x,y,z,detail&&wide));
  }
  objects.sort((a,b)=>a.depth-b.depth).forEach(o=>g.appendChild(o.node));
  if(detail){
    for(const room of P.rooms){
      if(!wide&&!['electrical','mechanical','battery'].includes(room.id))continue;
      const [x,y,w,d]=room.rect,p=iso(x+w/2,y<4?y+.3:y+d-.1,z+(y<4?1.85:0));
      pill(p[0],p[1]+(y<4?-2:24),room.name,{size:8.5,anchor:'mid',gap:2,color:'#dee5d4'});
    }
    if(wide){const corridor=iso(5.8,4.83,z+.05);pill(corridor[0],corridor[1]+6,'관리 복도',{size:8,anchor:'mid',gap:2,color:'#bdd3bb'})}
    const unknown=fac.filter(item=>!P.equipment[item.id] && !P.doors.some(d=>d.asset===item.id));
    if(unknown.length){const p=iso(6,8,z);pill(p[0],p[1]+42,'미배치 설비 '+unknown.length+'개 · 자산 목록에서 확인',{size:9,anchor:'mid',color:'#e3ba86'})}
  }
  return g;
}
function drawLobbyFloor(detail) {
  const g=el('g',{'data-floorplan':'lobby'}),z=.22,objects=[],P=LOBBY_FLOORPLAN,wide=$('#scene').clientWidth>=560;
  const put=(x,y,node)=>objects.push({depth:x+y,node});
  g.appendChild(prism(0,0,0,GW,GD,z,'#778984'));
  // 대기·안내 공간은 넓은 석재 타일, 통제 구역은 차분한 회색 바닥.
  g.appendChild(quad(0,0,z+.01,GW,GD,{fill:'#aebbad'}));
  for(let x=.12;x<11.88;x+=.6)for(let y=3.35;y<7.87;y+=.6)
    g.appendChild(quad(x,y,z+.018,Math.min(.585,11.88-x),Math.min(.585,7.88-y),{fill:'#c1c6b6',stroke:'#9ba99d','stroke-width':.22}));
  g.appendChild(quad(.2,.2,z+.025,11.6,2.94,{fill:'#7d9391','data-controlled-zone':'vertical-circulation'}));
  g.appendChild(quad(7.97,3.42,z+.03,2.07,4.37,{fill:'#a5b8a0',opacity:.7}));
  g.appendChild(planRoute([[9,7.8],[9,6.08],[9,2.35],[7.1,2.35]],z+.04,'#607e60',{'data-walkpath':'entry-screening-authentication'}));
  g.appendChild(planRoute([[8.75,7.36],[6.7,7.36],[6.7,5.25]],z+.04,'#8c9e89',{'data-walkpath':'visitor-reception'}));
  const wall=(x,y,w,d,h)=>put(x+w/2,y+d/2,prism(x,y,z,w,d,h,'#b8c5b9'));
  g.appendChild(prism(0,0,z,12,.12,1.85,'#b8c5b9'));
  g.appendChild(prism(0,.12,z,.12,7.76,.8,'#b8c5b9'));
  wall(11.88,.12,.12,7.76,.22);
  wall(0,7.88,7.96,.12,.18);wall(10.04,7.88,1.96,.12,.18);
  // 좌측은 벽, 우측은 유리 칸막이. 맨트랩 개구부만 통과할 수 있다.
  wall(.12,3.19,5.1,.13,.32);
  const glass=(x,w)=> {
    const node=el('g',{'data-security-partition':''});
    node.appendChild(el('polygon',{points:pts([[x,3.25,z+.08],[x+w,3.25,z+.08],[x+w,3.25,z+1.45],[x,3.25,z+1.45]].map(p=>iso(...p))),fill:'#b4d5cd',opacity:.24,stroke:'#d1dfd0','stroke-width':.8}));
    for(const dx of [0,w])node.appendChild(prism(x+dx,3.19,z,.045,.13,1.5,'#99afa6'));
    put(x+w/2,3.25,node);
  };
  glass(5.22,2.96);glass(9.82,2.02);
  // 낮게 잘라 보이는 건축 벽에서도 카메라 부착 구간은 남긴다.
  wall(10.52,3.14,.65,.12,1.83);
  const desk=el('g',{'data-architectural-feature':'reception'});
  desk.appendChild(prism(4.2,4.0,z,2.8,.82,.73,'#5c7669'));
  desk.appendChild(prism(4.14,3.95,z+.73,2.92,.93,.09,'#d4d1b7'));
  for(let dx=4.35;dx<6.85;dx+=.17)desk.appendChild(prism(dx,4.825,z+.08,.055,.03,.52,'#81977c'));
  desk.appendChild(prism(5.38,4.2,z+.82,.64,.09,.41,'#2a474a'));
  const screen=el('g',{transform:roomFace(5.4,4.3,z+.84)});screen.appendChild(roomRect(.04,.04,.5,.29,'#436f6d'));desk.appendChild(screen);
  put(5.6,4.45,desk);
  // 방문객 좌석은 출입 검색 동선에서 벗어난 왼쪽 창가에 둔다.
  for(const y of [4.17,6.53]){
    const sofa=el('g',{'data-architectural-feature':'waiting-seat'});
    sofa.appendChild(prism(1.05,y,z,2.18,.66,.3,'#526f6b'));
    sofa.appendChild(prism(1.05,y,z+.3,2.18,.17,.41,'#76978a'));
    for(const x of [1.08,3.0])sofa.appendChild(prism(x,y,z+.3,.2,.66,.23,'#8aa594'));
    for(let n=0;n<3;n++)sofa.appendChild(prism(1.31+n*.54,y+.19,z+.3,.5,.4,.08,'#a2b7a0'));
    put(2.1,y+.3,sofa);
  }
  const table=el('g',{'data-architectural-feature':'waiting-table'});
  table.appendChild(prism(1.7,5.4,z,.08,.46,.35,'#768c7f'));
  table.appendChild(prism(1.46,5.27,z+.35,1.21,.74,.08,'#d1c8a8'));put(2,5.6,table);
  // 승강기·계단은 인증 경계 뒤에서 지하와 전산층으로 이어진다.
  const core=el('g',{'data-architectural-feature':'stairs-lift'});
  core.appendChild(prism(5.65,.2,z,1.35,1.35,1.62,'#748c85'));
  const doors=el('g',{transform:roomFace(5.65,1.56,z)});
  doors.appendChild(roomRect(.13,.04,1.08,1.45,'#b8c7bc'));
  doors.appendChild(roomRect(.655,.04,.025,1.45,'#587a73'));
  doors.appendChild(roomRect(1.25,.77,.06,.17,'#d3d8bc'));core.appendChild(doors);
  for(let n=0;n<7;n++)core.appendChild(prism(10.45,.32+n*.24,z,.95,.25,(7-n)*.18,'#b3c1b2'));
  for(const xx of [10.43,11.43])core.appendChild(roomLine([xx,.39,z+1.66],[xx,1.85,z+.55],'#cbd9c6',1.4));
  put(8.5,1.1,core);
  // 별도 문 패널을 방 안에 두지 않고 정문을 외벽 개구부에 붙인다.
  const facilities=physicalFacilitiesOf('1F');
  put(9,7.91,planDoor(P.entrance,z,facilities.find(item=>item.id==='door-main')));
  for(const item of facilities){
    const plan=P.equipment[item.id];if(!plan)continue;
    const [x,y]=plan.pos,node=drawRoomEquipment(item,x,y,z+(plan.mount_z||0),false,plan);
    node.setAttribute('data-plan-equipment',item.id);
    node.setAttribute('data-equipment-bounds',[x,y,...plan.size.slice(0,2)].join(','));
    if(plan.mount_z)node.setAttribute('data-wall-mounted','true');
    put(x+plan.size[0]/2,y+plan.size[1]/2,node);
  }
  // 데스크 앞 안내 위치. 칸막이·카운터에 캐릭터와 선택 영역이 가려지지 않는다.
  for(const worker of crewOf('1F'))put(5.15,5.9,drawRoomWorker(worker,5.15,5.9,z,detail&&wide));
  // 방재 패널과 건물 이름은 뒤 벽면을 사용한다.
  const sign=el('g',{'data-architectural-feature':'lobby-sign'});
  sign.appendChild(prism(.7,.15,z+.91,3.15,.06,.52,'#344f47'));
  sign.appendChild(roomLettering(.9,.22,z+1.25,'AI DATA CENTER',.22,'#d9e7c5'));
  sign.appendChild(roomLettering(.91,.22,z+1.05,'SECURITY RECEPTION',.107,'#aabd9d'));put(2.2,.2,sign);
  objects.sort((a,b)=>a.depth-b.depth).forEach(o=>g.appendChild(o.node));
  if(detail){
    for(const [x,y,label,zz] of [[2.1,7.72,'방문객 대기',0],[5.6,5.04,'안내 · 방재',0],[9,5.29,'출입 검색',1.92],[9,3.15,'인증 · 맨트랩',2.05],[7.1,1.45,'승강기 · B1–4F',1.97],[10.7,.15,'계단',1.85]]){
      if(!wide&&!['방문객 대기','출입 검색','승강기 · B1–4F'].includes(label))continue;
      const p=iso(x,y,z+zz);pill(p[0],p[1]+(zz?0:18),label,{size:9,anchor:'mid',gap:2,color:'#e0e7d5'});
    }
  }
  return g;
}

/* 3F의 건축 배치. 상대 좌표이며 시공 도면이나 법정 이격 거리 산정이 아니다.
 * 실물 Spark/Thor는 공랭 전시 캐비닛, 액냉 설비는 분리된 비교 실습 구역이다. */
const AI_FLOORPLAN={
  rack:{pos:[1.55,3.0],size:[5.9,1.0]},
  door:{id:'entrance',asset:'door-3f',x:7.4,y:7.91,width:1.5,axis:'x',height:1.65,double:true,into:-1},
  clearances:[
    {id:'rack-rear',rect:[1.4,1.25,6.15,1.0]},
    {id:'rack-front',rect:[1.4,4.05,6.15,1.5]},
    {id:'entry-route',rect:[7.65,4.15,1.25,3.6]},
    {id:'main-route',rect:[1.0,5.6,6.65,1.0]}
  ],
  path:[[8.15,7.85],[8.15,6.1],[3.2,6.1],[3.2,5.15]],
  equipment:{
    'crac-02':{pos:[.25,4.0],size:[.95,1.0,1.7],roomName:'공랭 구역 · 측벽 공조',reason:'항온항습기를 측벽에 두고 랙 전면의 냉기 공급 구간과 구분합니다. 전면 정비 통로를 비워 둡니다.'},
    'fcu-3f-01':{pos:[7.85,2.3],size:[.7,1.7,2.2],roomName:'공랭 구역 · 랙 열 끝',reason:'인로우 쿨러은 랙 열 옆에 놓습니다. 랙 전면 작업 통로와 출입 동선을 가로막지 않습니다.'},
    'pdu-03':{pos:[.3,6.85],size:[.5,.65,1.25],roomName:'공랭 구역 · 측벽 전원',reason:'전원 분배는 측벽을 따라 상부 부스바와 연결하고 액체냉각 배관과 분리합니다. 통로 바닥을 가로지르는 전원선을 그리지 않습니다.'},
    'bus-3f-b':{pos:[1.5,.45],size:[6.05,.3,.16],mount_z:3.0,roomName:'공랭 구역 · 상부 전원',reason:'부스바는 랙 후면 상부에 설치하고 탭오프로 PDU에 연결합니다. 바닥에 독립 장비처럼 세우지 않습니다.'},
    'cdu-01':{pos:[9.5,.55],size:[1.05,.8,1.45],roomName:'액체냉각 비교 실습 구역',reason:'CDU와 침지 시험 설비는 공랭 Spark·Thor에서 분리된 실습 구역에 둡니다. 실물 장비에 액체 배관이 연결된 것처럼 표시하지 않습니다.'},
    'imm-01':{pos:[9.5,2.5],size:[2.05,1.35,.8],roomName:'액체냉각 비교 실습 구역',reason:'침지 시험 탱크는 누수 대응이 가능한 별도 실습 구역에 두고 앞쪽 정비 공간과 출입 동선을 확보합니다.'},
    'fm200-03':{pos:[10.4,6.5],size:[1.05,.55,1.35],roomName:'출입구 옆 방재 구역',reason:'소화 용기는 출입문을 막지 않는 측면 보호 구역에 둡니다. 밸브 점검 공간을 확보하고 이동 동선에서 분리합니다.'},
    'vesda-02':{pos:[.16,6.2],size:[.5,.16,.45],mount_z:1.08,roomName:'벽부 조기연기감지',reason:'감지 본체를 벽에 부착하고 샘플링 배관을 상부로 연결합니다. 통로에 센서를 세워 놓지 않습니다.'},
    'cctv-03':{pos:[11.1,.2],size:[.48,.2,.3],mount_z:1.72,roomName:'출입 동선 감시',reason:'상부 벽의 카메라가 출입구와 주요 이동 통로를 향하도록 배치합니다.'},
    'badge-3f':{pos:[9.04,7.855],size:[.23,.08,.32],mount_z:.82,roomName:'출입문 옆 카드리더',reason:'카드리더는 출입문 옆 벽에 붙이고 문 개폐 범위 밖에서 사용합니다.'}
  }
};
function drawAIFloor(detail){
  const P=AI_FLOORPLAN,z=.22,g=el('g',{'data-floorplan':'ai-compute'}),objects=[],fac=physicalFacilitiesOf('3F');
  const put=(x,y,node)=>objects.push({depth:x+y,node});
  g.appendChild(prism(0,0,0,GW,GD,z,'#617b80',{flat:true}));
  for(let x=0;x<GW;x+=.5)for(let y=0;y<GD;y+=.5)
    g.appendChild(quad(x+.008,y+.008,z+.015,.484,.484,{fill:(Math.round((x+y)*2)%2)?'#6b8489':'#728c90',stroke:'#91a5a5','stroke-width':.2}));
  g.appendChild(quad(9.15,.22,z+.025,2.62,4.8,{fill:'#738f91',stroke:'#b1d1ca','stroke-width':.7,'data-plan-room':'liquid-lab'}));
  // 배수·누수 대비 경계는 실습 구역 안에만 둔다.
  g.appendChild(prism(9.08,.2,z,.08,4.9,.13,'#adc1b7'));
  g.appendChild(prism(9.08,5.02,z,2.72,.08,.13,'#adc1b7'));
  g.appendChild(prism(0,0,z,GW,.13,1.8,'#91a7aa'));
  g.appendChild(prism(0,.13,z,.13,7.74,1.3,'#809ca1'));
  for(const x of [1.65,4,6.35,8.7])g.appendChild(roomLine([x,.15,z+1.62],[x+1.5,.15,z+1.62],'#c6e2d1',1.6));
  g.appendChild(roomLettering(9.3,.15,z+1.7,'LIQUID COOLING / TRAINING',.15,'#e4ece0'));
  P.clearances.forEach(area=>{const [x,y,w,d]=area.rect;g.appendChild(quad(x,y,z+.035,w,d,{fill:area.id==='rack-front'?'#6da9b4':'#a4ae94',opacity:.3,stroke:'#c4d2b5','stroke-width':.6,'stroke-dasharray':'3 2','data-maintenance-clearance':area.id,'data-clearance-bounds':area.rect.join(',')}))});
  g.appendChild(planRoute(P.path,z+.05,'#d3ddbc',{'data-walkpath':'ai-entry'}));
  // 전면 타공 타일 → 공랭 장비 → 후면 리턴. 실물 공랭과 액냉 비교 실습을 연결하지 않는다.
  for(let x=1.7;x<7.3;x+=.32)for(let y=4.15;y<4.6;y+=.13)
    g.appendChild(quad(x,y,z+.055,.18,.03,{fill:'#347f90'}));
  const rack=racksOf('3F').find(r=>r.style==='nvidia-ai');
  if(rack){const [x,y]=P.rack.pos,node=drawNvidiaRack(rack,x,y,z);node.setAttribute('data-equipment-bounds',[x,y,...P.rack.size].join(','));put(x+P.rack.size[0]/2,y+P.rack.size[1]/2,node)}
  // 용기 보호대와 카드리더 부착 벽은 건축 요소다.
  for(const x of [10.18,11.63])put(x,6.8,prism(x,6.36,z,.06,.84,.8,'#b5c4b6'));
  put(9.16,7.785,prism(8.98,7.72,z,.38,.13,1.27,'#91a7aa'));
  for(const item of fac){
    if(item.id===P.door.asset)continue;
    const plan=P.equipment[item.id];if(!plan)continue;
    const [x,y]=plan.pos,node=drawRoomEquipment(item,x,y,z+(plan.mount_z||0),true,plan);
    node.setAttribute('data-plan-equipment',item.id);node.setAttribute('data-equipment-bounds',[x,y,...plan.size.slice(0,2)].join(','));
    if(plan.mount_z)node.setAttribute('data-mounted',plan.mount||'wall-or-overhead');
    put(x+plan.size[0]/2,y+plan.size[1]/2,node);
  }
  const services=el('g',{'pointer-events':'none','data-ai-connections':'separated'});
  services.appendChild(roomLine([1.55,.63,z+3.02],[.3,.63,z+3.02],'#d4b67e',1.5));
  services.appendChild(roomLine([.3,.63,z+3.02],[.3,7.1,z+3.02],'#d4b67e',1.2));
  services.appendChild(roomLine([.3,7.1,z+3.02],[.55,7.1,z+1.25],'#d4b67e',1.2));
  services.appendChild(roomLine([.22,6.25,z+1.53],[.22,6.25,z+2.1],'#d6b4a6',.9));
  services.appendChild(roomLine([.22,6.25,z+2.1],[.22,.3,z+2.1],'#d6b4a6',.9));
  // 비교 실습 회로는 오른쪽 구역 안에서만 이어진다.
  for(const [offset,color] of [[0,'#6ab6c8'],[.13,'#d1a58b']]){
    services.appendChild(roomLine([9.63+offset,.98,z+.5],[9.63+offset,2.6,z+.5],color,1.3));
  }
  put(6,1,services);
  put(P.door.x+P.door.width/2,P.door.y,planDoor(P.door,z,fac.find(item=>item.id===P.door.asset)));
  for(const worker of crewOf('3F'))put(3.3,6.2,drawRoomWorker(worker,3.3,6.2,z,detail));
  objects.sort((a,b)=>a.depth-b.depth).forEach(o=>g.appendChild(o.node));
  g.appendChild(roomLine([0,GD,z],[7.38,GD,z],'#c4d6cf',1.1));
  g.appendChild(roomLine([8.95,GD,z],[GW,GD,z],'#c4d6cf',1.1));
  g.appendChild(roomLine([GW,0,z],[GW,GD,z],'#b7cfc6',1.1));
  if(detail){
    const p=iso(5,4.15,z);pill(p[0],p[1]+25,'NVIDIA · 공랭 장비',{size:9,anchor:'mid',color:'#c9df9d',gap:2});
    const q=iso(10.55,5.1,z);pill(q[0],q[1]+23,'액체냉각 · 비교 실습',{size:9,anchor:'mid',color:'#b6d8d5',gap:2});
  }
  return g;
}

/* 업무 공간은 코드로 그린다. xOC에는 실제 층 번호나 가상의 운영 수치를 넣지 않는다. */
function drawControlCenterRoom(fid,detail) {
  const lab=fid==='5F',z=.22,accent=lab?'#b6a1e2':'#7bd5c3';
  const g=el('g',{'data-control-room':fid});
  g.appendChild(prism(0,0,0,GW,GD,z,lab?'#768390':'#3c5664'));
  g.appendChild(quad(0,0,z+.005,GW,GD,{fill:lab?'#8192a0':'#405b68'}));
  for(let x=.3;x<GW;x+=.8)for(let y=.3;y<GD;y+=.8)
    g.appendChild(quad(x,y,z+.012,.78,.78,{fill:lab?'#8497a4':'#46616e',stroke:lab?'#97a7b1':'#53727e','stroke-width':.35}));
  g.appendChild(prism(0,0,z,GW,.15,1.8,lab?'#adbac2':'#546c7a'));
  g.appendChild(prism(0,0,z,.15,GD,1.35,lab?'#93a8b7':'#496477'));
  g.appendChild(roomLine([.2,.22,z+1.67],[GW-.25,.22,z+1.67],accent,2));
  // 읽을 수 있는 벽면 표식. 좌표 변환의 Y축을 양수로 두어 글자를 뒤집지 않는다.
  const sign=el('a',{href:dcURL(lab?'researchlab':'xoc'),'aria-label':lab?'AI 연구소 열기':'xOC 제한구역 관제 화면',on:{click:e=>e.stopPropagation()}});
  sign.appendChild(roomLettering(.65,.19,z+2.05,lab?'AI RESEARCH LAB  /  5F':'xOC  /  RESTRICTED',.26,accent));
  g.appendChild(sign);
  const station=(id,x,y)=>{const worker=crewOf(fid).find(w=>w.id===id);if(worker)g.appendChild(drawWorkstation(worker,x,y,z,detail))};
  if(lab) {
    // 자료 열람 벽과 시험 보드. 장식 그래프는 실시간 성능으로 표시하지 않는다.
    for(let n=0;n<3;n++) {
      const x=.6+n*1.35;
      g.appendChild(prism(x,.35,z,1.14,.35,1.48,'#435c6b'));
      for(let shelf=0;shelf<3;shelf++)for(let book=0;book<6;book++)
        g.appendChild(prism(x+.08+book*.16,.65,z+.13+shelf*.44,.11,.08,.31,['#b6a1e2','#a5c2c8','#d8c2a2'][book%3]));
    }
    g.appendChild(prism(6.4,.23,z+.6,4.6,.09,1.08,'#d0d7d4'));
    g.appendChild(roomLettering(6.65,.34,z+1.46,'RESEARCH  >  TEST  >  REVIEW',.14,'#435965'));
    for(let i=0;i<3;i++)for(let j=0;j<2;j++) {
      const f=el('g',{transform:roomFace(6.8+i*1.3,.35,z+.78+j*.25)});
      f.appendChild(roomRect(0,0,.75,.14,['#ac9ed7','#8fbcbc','#c8b68e'][i]));g.appendChild(f);
    }
    // 독립 연구·평가 자리 사이에 넓은 중앙 동선을 둔다.
    station('skill-researcher',2.05,3.45);station('skill-evaluator',7.8,3.45);
    g.appendChild(prism(4.9,5.6,z,1.9,1.05,.72,'#687d8e'));
    g.appendChild(quad(5,5.7,z+.74,1.7,.85,{fill:'#b4bdc0'}));
    g.appendChild(roomLettering(4.98,6.68,z+.58,'EXPERIMENTS',.12,'#e0e9ec'));
  } else {
    // 두 관제 직무는 별도의 콘솔·모니터 벽을 갖는다.
    for(let side=0;side<2;side++) {
      const x=.65+side*5.9;
      for(let panel=0;panel<3;panel++) {
        const f=el('g',{transform:roomFace(x+panel*1.55,.24,z+.57)});
        f.appendChild(roomRect(0,0,1.4,.94,'#152b39',{rx:.035}));
        f.appendChild(roomRect(.06,.07,1.28,.8,'#214353'));
        for(let line=0;line<5;line++)f.appendChild(roomRect(.14,.16+line*.11,.84-(line%3)*.14,.025,side?'#91b7d3':'#7fae9c'));
        g.appendChild(f);
      }
      g.appendChild(roomLettering(x,.26,z+1.75,side?'SECURITY OPERATIONS':'AI AGENT OPERATIONS',.19,side?'#b5ccde':accent));
    }
    // 4층의 과밀을 풀기 위해 담당자별 전면 작업석을 확보한다.
    station('agent-supervisor',2.15,3.7);station('soc-analyst',8,3.7);
    // 출입 인증 구역은 앞 모서리에 낮게 배치해 근무자 클릭을 가리지 않는다.
    g.appendChild(quad(.5,6.45,z+.03,2.3,1.1,{fill:'#364751',stroke:'#8fbdac','stroke-width':1}));
    g.appendChild(prism(.6,6.5,z,.28,.32,.82,'#607885'));
    g.appendChild(prism(2.4,6.5,z,.28,.32,.82,'#607885'));
    g.appendChild(roomLettering(.9,7.2,z+.08,'ACCESS CONTROL',.12,'#bdd6d2'));
  }
  g.appendChild(roomLine([0,GD,z+.02],[GW,GD,z+.02],accent,1.5));
  g.appendChild(roomLine([GW,0,z+.02],[GW,GD,z+.02],accent,1.2));
  return g;
}


 // Room headings and content faces share the same display projection.
 const contentHeight=h=>svgHost.dataset.sceneMode==='building'?Math.min(h,1.65):h;
 function contentFace(x,y,z){const [sx,sy]=iso(x,y,z);return `matrix(${XS},${YS*.48},0,${ZS},${sx},${sy})`;}
 function contentLettering(x,y,z,title,size,color){return roomLettering(x,y,z,title,size,color,{transform:contentFace(x,y,z)});}
 // Opaque in-room displays contain live catalog and owner-scoped learning data.
 function contentDisplay(x,y,z,w,h,title,accent,rows=[],footer=''){
  const overview=svgHost.dataset.sceneMode==='building';h=contentHeight(h);
  const g=el('g',{class:'dc-room-screen','data-room-display':title});
  const face=el('g',{transform:contentFace(x,y,z+h)});
  face.append(el('rect',{x:-.06,y:-.06,width:w+.12,height:h+.12,rx:.12,fill:'#11121e',stroke:'#080a12','stroke-width':.08}));
  face.append(el('rect',{width:w,height:h,rx:.075,fill:'#202137',stroke:accent,'stroke-width':.027}));
  if(overview){
   for(let i=0;i<3;i++){const xx=.18+i*(w-.3)/3;face.append(el('rect',{x:xx,y:.2,width:(w-.65)/3,height:h-.4,rx:.04,fill:i===0?'#51406b':'#313249',stroke:accent,'stroke-width':.014,opacity:.8}));face.append(el('path',{d:`M${xx+.1} ${h*.45} h${(w-.65)/3-.2} M${xx+.1} ${h*.65} h${(w-.65)/3-.3}`,stroke:accent,'stroke-width':.028,opacity:.65}));}
   g.append(face);return g;
  }
  face.append(el('path',{d:`M.18 .57 H${w-.18}`,stroke:accent,'stroke-width':.018,opacity:.6}));
  const text=(x,y,value,size=.25,color='#eee8fc')=>el('text',{x,y,text:value,'font-size':size,'font-family':'system-ui,sans-serif',fill:color,stroke:'none'});
  const wrap=(value,max,size)=>{const lines=[];let line='',length=0;for(const char of String(value)){const cw=/[\u0000-\u00ff]/.test(char)?.56:1;if(length+cw>max/size&&line){lines.push(line);line='';length=0;}line+=char;length+=cw;}if(line)lines.push(line);return lines;};
  face.append(text(.22,.37,title,.28,accent));
  const top=.74,bottom=h-.36,rowHeight=Math.min(1.03,(bottom-top)/Math.max(1,rows.length));
  rows.forEach((row,i)=>{
   const yy=top+i*rowHeight,item=el('g',{'data-screen-entry':String(i)});
   item.append(el('rect',{class:'dc-screen-card',x:.15,y:yy-.08,width:w-.3,height:rowHeight-.1,rx:.045,fill:row.route?'#302940':'#25283d',stroke:row.route?'#75618c':'#3b4156','stroke-width':.014}));
   const lines=wrap(row.title,w-.66,.27).slice(0,2);lines.forEach((line,n)=>item.append(text(.31,yy+.22+n*.3,line,.27)));
   if(row.detail)item.append(text(.31,yy+Math.min(rowHeight-.2,lines.length*.3+.2),row.detail,.2,'#c0b6d2'));
   if(row.route&&learning&&svgHost.dataset.sceneMode!=='building'){item.dataset.dcLearningRoute=row.route;item.setAttribute('role','link');item.setAttribute('tabindex','0');item.setAttribute('aria-label',row.title+' 열기');}
   face.append(item);
  });
  if(footer)face.append(text(.23,h-.12,footer,.19,'#9bded5'));
  g.append(face);return g;
 }

 // Thin optical glass: see-through faces, edge light, reflections and local HUD artwork.
 function holoDisplay(x,y,z,w,h,title,accent,kind='radar',yaw=0,details=[]){
  const g=el('g',{'data-holographic-display':kind}),[sx,sy]=iso(x,y,z+h);
  const face=el('g',{transform:`matrix(${XS*(1-yaw)},${YS*(1+yaw)},0,${ZS},${sx},${sy})`});
  const cut=.12,outline=`M${cut} 0 H${w-.28} L${w} .24 V${h-cut} L${w-cut} ${h} H.2 L0 ${h-.2} V${cut}Z`;
  face.append(el('path',{d:outline,fill:'none',stroke:accent,'stroke-width':.13,opacity:.09}));
  face.append(el('path',{d:outline,fill:kind.startsWith('cover')?'url(#holoViolet)':'url(#holoGlass)',stroke:accent,'stroke-width':.022,'stroke-opacity':.75}));
  face.append(el('path',{d:`M.12 .1 H${w*.53} L${w*.28} ${h-.12} H.12Z`,fill:'#dbfff9',opacity:.035}));
  face.append(el('path',{d:`M.04 .38 V.15 L.15 .04 H.46 M${w-.46} ${h-.04} H${w-.15} L${w-.04} ${h-.15} V${h-.38}`,fill:'none',stroke:'#d5fffa','stroke-width':.04}));
  face.append(el('text',{x:.15,y:.24,'font-size':Math.min(.15,(w-.3)/Math.max(1,[...title].length)),'font-family':'system-ui,sans-serif',fill:'#e2fff9',stroke:'none','font-weight':600,text:title}));
  face.append(el('path',{d:`M.15 .34 H${w-.15}`,stroke:accent,'stroke-width':.012,opacity:.5}));
  const line=(d,color=accent,width=.025)=>el('path',{d,fill:'none',stroke:color,'stroke-width':width});
  const label=(x,y,text,size=.11,color=accent)=>el('text',{x,y,text,'font-size':size,'font-family':'ui-monospace,monospace',fill:color,stroke:'none'});
  if(kind==='status'){details.forEach((text,i)=>face.append(label(.18,.65+i*.3,text,.17)));
  }else if(kind==='radar'){
   const cx=w*.54,cy=h*.58,r=Math.min(w*.25,h*.31);
   for(const mult of [1,.73,.4])face.append(el('circle',{cx,cy,r:r*mult,fill:'none',stroke:accent,'stroke-width':.014,'stroke-dasharray':mult===.73?'.05 .06':'none',opacity:mult===1?.9:.5}));
   face.append(line(`M${cx-r-.16} ${cy} H${cx+r+.16} M${cx} ${cy-r-.14} V${cy+r+.14}`,accent,.012));
   face.append(line(`M${cx-r*.8} ${cy+r*.3} L${cx-r*.2} ${cy-r*.5} L${cx+r*.35} ${cy-r*.1} L${cx+r*.8} ${cy-r*.7}`,'#c4a5ff',.03));
   for(const [dx,dy,color] of [[-.8,.3,accent],[-.2,-.5,'#e883bc'],[.35,-.1,accent],[.8,-.7,'#e883bc']])face.append(el('circle',{cx:cx+r*dx,cy:cy+r*dy,r:.045,fill:color,stroke:'none'}));
   for(let n=0;n<4;n++)face.append(line(`M.17 ${.6+n*.18} H${.42+(n%2)*.18}`,accent,.02));
   face.append(label(.16,h-.15,'RED  /  BLUE',.095),label(w-.86,h-.15,'TACTICAL',.095));
  }else if(kind==='level'){
   const cx=w/2,cy=h*.57,r=h*.25;
   face.append(line(`M${cx} ${cy-r} L${cx+r*.85} ${cy-r*.5} V${cy+r*.5} L${cx} ${cy+r} L${cx-r*.85} ${cy+r*.5} V${cy-r*.5}Z`,'#c5a4ff',.035));
   face.append(line(`M${cx-.23} ${cy+.04} L${cx} ${cy-.14} L${cx+.23} ${cy+.04} M${cx-.23} ${cy+.19} L${cx} ${cy+.01} L${cx+.23} ${cy+.19}`,'#d6c0ff',.055));
   face.append(label(w*.35,h-.12,'LV. —',.13));
  }else if(kind==='feedback'){
   face.append(line(`M.2 ${h*.54} H${w*.22} L${w*.3} ${h*.4} L${w*.38} ${h*.72} L${w*.48} ${h*.45} L${w*.56} ${h*.59} H${w-.2}`,'#bf9afa',.04));
   face.append(label(.2,h-.25,'EVIDENCE / REVIEW',.11));
  }else if(kind==='progress'||kind==='ranking'){
   for(let n=0;n<3;n++){
    const yy=.56+n*(h-.76)/3;
    face.append(el('circle',{cx:.22,cy:yy+.045,r:.04,fill:'none',stroke:accent,'stroke-width':.02}));
    face.append(roomRect(.4,yy,w-.8,.08,'none',{stroke:accent,'stroke-width':.012,rx:.025,opacity:.6}));
    if(kind==='ranking')face.append(label(w-.25,yy+.09,'—',.11));
   }
  }else if(kind==='modes'){
   ['SOLO','DUEL','FFA'].forEach((t,i)=>{const xx=.16+i*(w-.25)/3;face.append(roomRect(xx,.46,(w-.6)/3,h-.61,'#180f3226',{rx:.04,stroke:i===1?'#e992c5':accent,'stroke-width':.018}));face.append(label(xx+.12,h-.25,t,.17,i===1?'#f0b0d7':'#b9fff1'));});
  }else if(kind.startsWith('cover')){
   const k=Number(kind.slice(-1))||0,cx=w/2,cy=h*.54,r=w*.29;
   if(k===0)face.append(line(`M${cx} ${cy-r} L${cx+r} ${cy-r*.6} V${cy+.1} Q${cx+r} ${cy+r*.6} ${cx} ${cy+r} Q${cx-r} ${cy+r*.6} ${cx-r} ${cy+.1} V${cy-r*.6}Z`,accent,.04),line(`M${cx-.22} ${cy} L${cx-.04} ${cy+.2} L${cx+.28} ${cy-.2}`,'#eddbff',.045));
   else if(k===1)face.append(line(`M${cx-r*.7} ${cy-r*.5} L${cx-r*.2} ${cy} L${cx-r*.7} ${cy+r*.5} M${cx+.02} ${cy+r*.5} H${cx+r*.75}`,accent,.065));
   else if(k===2){face.append(roomRect(cx-r,cy-r*.7,r*2,r*1.4,'none',{stroke:accent,'stroke-width':.035,rx:.05}));face.append(line(`M${cx-r} ${cy-r*.25} H${cx+r} M${cx-r*.65} ${cy+r*.05} H${cx+r*.65} M${cx-r*.65} ${cy+r*.3} H${cx+r*.3}`,accent,.025));}
   else{face.append(line(`M${cx} ${cy-r} L${cx-r} ${cy+r*.6} H${cx+r}Z`,accent,.025));for(const [dx,dy] of [[0,-1],[-1,.6],[1,.6]])face.append(el('circle',{cx:cx+r*dx,cy:cy+r*dy,r:.11,fill:'#24203b',stroke:accent,'stroke-width':.035}));}
   face.append(label(.17,h-.29,'LECTURE / LAB',.09),line(`M.17 ${h-.15} H${w-.17}`,accent,.018));
  }else{
   for(let n=0;n<4;n++)face.append(line(`M.17 ${.55+n*.18} H${w-.17-(n%2)*.25}`,accent,.018));
  }
  g.append(face);return g;
 }
 function trainingCockpit(x,y,z){
  const g=el('g',{'data-training-cockpit':'single-seat'}),cyan='#61eee5';
  const outline=[[.3,0],[4.5,0],[4.8,.3],[4.8,3.3],[4.5,3.6],[.3,3.6],[0,3.3],[0,.3]];
  const floor=outline.map(([a,b])=>iso(x+a,y+b,z+.17));
  g.append(el('polygon',{points:pts(outline.map(([a,b])=>iso(x+a,y+b,z+.03))),fill:'#100f20',stroke:'#050713','stroke-width':5}));
  g.append(el('polygon',{points:pts(floor),fill:'#1c2838',stroke:cyan,'stroke-width':1.3}));
  g.append(quad(x+.24,y+.24,z+.18,4.32,3.12,{fill:'#192332',stroke:'#7c6bb955','stroke-width':.8}));
  // Projected rings and a swept glass HUD surround one pilot station.
  const ring=el('g',{transform:`translate(${iso(x+2.35,y+2.35,z+.19).join(' ')}) scale(1 ${YS/XS})`});
  for(const r of [27,39,46])ring.append(el('circle',{r,fill:'none',stroke:r===39?'#b09ae6':cyan,'stroke-width':r===39?1.2:.6,opacity:.55,'stroke-dasharray':r===46?'8 5':'none'}));g.append(ring);
  const hud=contentDisplay(x+.75,y+.2,z+.92,3.3,1.7,'CYBER COMBAT',cyan,[{title:'미션 준비',detail:'시나리오를 선택하세요'}]);hud.setAttribute('data-mission-panel','cockpit');g.append(hud);
  g.append(holoDisplay(x-.16,y+.72,z+.92,1.15,1.5,'RED','#ed92c7','scan',-.65));
  g.append(holoDisplay(x+3.93,y+.2,z+.92,1.25,1.5,'BLUE',cyan,'scan',.25));
  // Low consoles keep the transparent screen and pilot silhouette exposed.
  for(const side of [0,1]){
   const xx=x+.42+side*3.24,col=side?cyan:'#e68dc5';
   g.append(prism(xx,y+1.46,z+.17,.6,1.27,.45,'#293044'));
   g.append(quad(xx+.04,y+1.51,z+.64,.52,1.17,{fill:'#182237',stroke:col,'stroke-width':.7}));
   for(let n=0;n<4;n++)g.append(quad(xx+.11,y+1.64+n*.22,z+.65,.1,.07,{fill:col,opacity:.75}));
   g.append(roomLine([xx+.08,y+1.53,z+.68],[xx+.52,y+1.53,z+.68],col,1));
  }
  // The seat faces the HUD. Its opaque near-side back hides the occupant and far armrest.
  g.append(prism(x+1.77,y+1.98,z+.17,1.18,1.1,.4,'#232c40'));
  g.append(prism(x+1.83,y+2.03,z+.58,1.06,.93,.13,'#47445e'));
  g.append(drawWorkerFigure({id:'red-instructor',name:'공방전 교관',facing:'rear'},x+2.35,y+2.53,z+.43,true));
  g.append(prism(x+1.74,y+2.92,z+.45,1.24,.22,.8,'#343449'));
  g.append(prism(x+1.84,y+3.15,z+.56,1.04,.035,.57,'#292b3d'));
  for(const xx of [x+1.85,x+2.85])g.append(roomLine([xx,y+3.19,z+.61],[xx,y+3.19,z+1.15],cyan,.65));
  g.append(prism(x+2.84,y+2.12,z+.55,.16,.77,.24,'#6d6b8b'));
  g.append(prism(x+2.62,y+1.6,z+.48,.08,.08,.38,'#9cabc1'));
  g.append(roomLettering(x+.32,y+3.43,z+.2,'SOLO / MISSION POD',.14,'#a2c8d9'));
  return g;
 }
 function extensionFloor(fid){
  const z=.22,g=el('g',{'data-extension-floor':fid}),academy=fid==='6F',live=fid==='7F';
  const accent=academy?'#c2a4ff':live?'#58e9df':'#a5c4a9';
  g.append(prism(0,0,0,GW,GD,z,academy||live?'#303047':'#708391',{flat:true}));
  for(let x=0;x<GW;x+=.5)for(let y=0;y<GD;y+=.5)g.append(quad(x+.008,y+.008,z+.01,.484,.484,{fill:academy||live?((Math.round((x+y)*2)%2)?'#26273a':'#292b3e'):((Math.round((x+y)*2)%2)?'#718895':'#7b929d'),stroke:academy||live?'#72708c33':'#9babb4','stroke-width':.22}));
  if(academy||live){
   g.append(prism(0,0,z,GW,.14,.65,'#34364b'),prism(0,0,z,.14,GD,.65,'#34364b'));
   for(const off of [.12,.22])g.append(quad(off,off,z+.025,GW-off*2,GD-off*2,{fill:'none',stroke:accent,'stroke-width':off===.12?1.3:.35,opacity:.65}));
   g.append(roomLine([.15,.18,z+.67],[11.8,.18,z+.67],accent,1.6),roomLine([.18,.18,z+.67],[.18,7.8,z+.67],accent,1.2));
   for(const xx of [.8,3.4,6,8.6,11.2])g.append(quad(xx,7.5,z+.03,.5,.06,{fill:accent,opacity:.8}));
  }else{
   g.append(prism(0,0,z,GW,.14,1.75,'#96a8b2'),prism(0,0,z,.14,GD,1.25,'#889eab'));
   g.append(roomLine([.3,.2,z+1.6],[11.7,.2,z+1.6],accent,2));
  }
  const objects=[],put=(x,y,node)=>objects.push({depth:x+y,node});
  if(academy){
   g.setAttribute('data-content-catalog','thumbnails');
   g.append(contentLettering(.65,.55,z+.9+contentHeight(3.15)+.45,'xOC ACADEMY  /  KNOWLEDGE GALLERY',.23,'#d8c9fb'));
   const entries=learning?.offerings||[],status=learning?.learning_status;
   const courseRows=entries.slice(0,2).map(c=>({title:c.title,detail:c.available?'이용 가능 · Core 번들':'미설치',route:c.available?c.route:null}));
   g.append(contentDisplay(.6,.55,z+.9,5.15,3.15,'CONTENTS / 콘텐츠',accent,courseRows,entries.length+'개 콘텐츠 · 이용 가능 '+entries.filter(c=>c.available).length));
   const recent=status?.recent[0],noteRows=status?[{title:'노트 '+status.notebooks+'편 · 완료 '+status.completed_lessons+'차시',detail:'작성 중 '+status.drafts+'편',route:'#academy/history'},recent?{title:recent.title.replace(' · 실습 노트',''),detail:recent.status==='complete'?'최근 기록 · 작성 완료':'최근 기록 · 이어쓰기',route:'#academy/lesson/'+recent.course+'/'+recent.lesson}:{title:'아직 작성한 노트가 없습니다',detail:'첫 강좌에서 실습을 기록해 보세요',route:'#academy'}]:[{title:'나의 실습 노트',detail:'학습 과정과 결과 기록'}];
   g.append(contentDisplay(6.2,.55,z+.9,5.15,3.15,'MY LEARNING / 내 기록','#9ce8de',noteRows,'나의 실습 과정 · 결과 · 해석'));
   (learning?.subjects||[{id:'xoc-web-defense',title:'웹 침해 대응'},{id:'xoc-linux-defense',title:'리눅스·네트워크 침해 대응'}]).forEach((subject,i)=>{
    const x=.8+i*5.5,y=4.5,count=learning?.scenarios.filter(s=>s.category===subject.id).length;
    const island=el('g',{'data-catalog-display':''});island.append(prism(x+.3,y+.35,z,4.1,.75,.55,'#36324d'));
    island.append(contentDisplay(x,y,z+.66,4.8,1.78,'연계 공방전 · '+(i+1),'#bca6ef',[{title:subject.title,detail:count===undefined?'콘텐츠 조회':count+'개 시나리오 · Red / Blue / Purple',route:learning?'#academy/scenarios/'+subject.id:null}]));
    put(x+2,y+.8,island);
   });
  }else if(live){
   g.setAttribute('data-training-mode','pilot');
   g.append(contentLettering(.55,.5,z+.95+contentHeight(3.1)+.68,'LIVE FIRE  /  CYBER COMBAT RANGE',.23,'#c9fbf2'));
   g.append(contentLettering(.58,.5,z+.95+contentHeight(3.1)+.32,'TRAIN CYBERSECURITY LIKE A FIGHTER PILOT',.13,'#baa4e2'));
   const subjects=learning?.subjects||[],scenarios=learning?.scenarios||[],total=scenarios.reduce((n,s)=>n+s.missions,0);
   const catalog=contentDisplay(.55,.5,z+.95,5.2,3.1,'SCENARIOS / 공방전','#81e9dd',subjects.length?subjects.map(subject=>({title:subject.title,detail:scenarios.filter(s=>s.category===subject.id).length+'개 시나리오',route:'#academy/scenarios/'+subject.id})):[{title:'등록 콘텐츠 조회'}],learning?scenarios.length+'개 시나리오 · '+total+'개 미션':'');
   catalog.setAttribute('data-mission-panel','scenarios');g.append(catalog);
   const state=contentDisplay(6.2,.5,z+.95,5.2,3.1,'TRAINING / 훈련 현황','#bda5f4',[{title:'개인 훈련',detail:'Live Fire 연결 후 제공'},{title:'반별 순위',detail:'리그 기능 연결 전'}],'현재 시나리오와 미션 열람 가능');state.setAttribute('data-mission-panel','training');g.append(state);
   const cockpit=trainingCockpit(1.35,3.1,z);put(4,5,cockpit);
   const missions=contentDisplay(6.7,4.7,z+.8,4.8,3.1,'MISSION BRIEF / 미션 보기','#81e9dd',scenarios.slice(0,2).map(s=>({title:s.title,detail:s.missions+'개 미션 · '+s.total_points+'점',route:'#academy/scenario/'+s.id})),'Red 공격 → Blue 대응 → Purple 보고');missions.setAttribute('data-mission-panel','missions');put(9.1,5.1,missions);
  }else{
   g.append(roomLettering(.7,.2,z+1.98,'AGENT OFFICE',.23,'#d0e2c9'));
   const staff=crewOf('4F').filter(w=>w.id!=='ops-lead');
   staff.forEach((w,i)=>{const x=1.85+(i%2)*3.15,y=2.55+Math.floor(i/2)*2.9;put(x+.7,y+1.1,drawWorkstation(w,x,y,z,false));});
   const rack=drawRoomRack({id:'R-8F-01',floor:'8F',aisle:'C',u:24,design_kw:999},8,2,z);
   rack.setAttribute('data-company-rack','R-8F-01');put(8.8,2.8,rack);
   put(10,6.2,drawLeadOffice(crewOf('4F').find(w=>w.id==='ops-lead'),8.25,4.85,z,false));
  }
  objects.sort((a,b)=>a.depth-b.depth).forEach(o=>g.append(o.node));
  g.append(roomLine([0,GD,z+.02],[GW,GD,z+.02],accent,1.2));return g;
 }
 function prepare(host,data,building){
  learning=building?null:data.learning_snapshot;svgHost=host;svgHost.dataset.sceneMode=building?'building':'room';YS=building?8:Math.max(5,Math.min(14,((GW+GD)*XS/(host.clientWidth/Math.max(1,host.clientHeight))-125)/16));
  ST={aisles:{},power:{},plant:{}};
  const core=data.racks||[];
  LAYOUT={...REFERENCE,racks:REFERENCE.racks.map(r=>({...r,design_kw:999})),it_assets:data.assets.map(a=>({...a,id:a.service,name:a.title,container:a.service,rack:a.rack_id,zone:a.zones[0],u:['siem','indexer'].includes(a.service)?2:1}))};
  // Unlicensed AI room contains a geometric preview only, with no host identities.
  LAYOUT.it_assets.push(...Array.from({length:8},(_,i)=>({id:'preview-gpu-'+i,name:'GPU SYSTEM',rack:'R-3F-01',floor:'3F',vendor:'NVIDIA',form_factor:i<4?'dgx-spark':'jetson-thor'})));
 }
 function room(fid,keepFacilities=false){
  let node;
  if(['6F','7F','8F'].includes(fid))node=extensionFloor(fid);else node=fid==='SITE'?drawOutdoor(false):drawRoom(fid,false);
  // Cloning removes all original event listeners, including door handlers.
  node=node.cloneNode(true);
  for(const el of node.querySelectorAll('[tabindex],[role],[href]'))for(const a of ['tabindex','role','href'])el.removeAttribute(a);
  // Facility floors keep data-facility so Core can attach its own read-only selection (ADR 0010).
  if(keepFacilities)for(const n of node.querySelectorAll('[data-asset^="preview-gpu-"]'))n.setAttribute('data-facility','gpu-'+String(Number(n.getAttribute('data-asset').slice(12))+1).padStart(2,'0'));
  const strip=keepFacilities?['data-asset','data-worker']:['data-asset','data-worker','data-facility'];
  for(const el of node.querySelectorAll('[data-asset],[data-worker],[data-facility]'))for(const a of strip)el.removeAttribute(a);
  return node;
 }
 // 시설 id → 층(옥외는 SITE). 시설 화면이 설비를 층별로 묶을 때 쓴다.
 function facilityFloors(){const out={};for(const rows of Object.values(REFERENCE.facility))for(const f of rows)out[f.id]=f.location==='outdoor'?'SITE':f.floor;return out;}
 return {prepare,room,defs:sceneDefs,iso,el,facilityFloors};
})();
