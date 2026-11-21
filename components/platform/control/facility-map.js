'use strict';
/* 데이터센터 관제 지도: 아이소메트릭 장면의 설비에 실시간 상태(발광·값 배지·끊김 표시·층 경보)를 입힌다.
 * 움직이는 선은 쓰지 않는다. 설비를 고르면 그 설비의 위·아래 연결만 정적인 선으로 잠깐 보여 준다.
 * 상태는 FacilityKit 저장소(시설 모듈이 보낸 값)에서만 온다. 시뮬레이터가 없으면 아무것도 바꾸지 않는다. */
window.FacilityMap=(()=>{
 const K=()=>window.FacilityKit;
 const SVGNS='http://www.w3.org/2000/svg';
 const el=(tag,attrs={},text)=>{const n=document.createElementNS(SVGNS,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,String(v));if(text!=null)n.textContent=text;return n;};
 // 건물 전체에서 늘 값을 보여 줄 핵심 설비(그 밖에는 이상이 있을 때만)
 const KEY=['ups-01','gen-01','ct-01','ct-02','cdu-01','rack-r-2f-01','rack-r-3f-01','rack-r-4f-01'];
 function badgeText(a){
  const v=k=>K().mval(a,k),f=K().fmt;
  if(a.id==='ups-01')return 'UPS '+f(v('runtime_min'))+'분';
  if(a.id==='gen-01')return '발전기 '+v('state');
  if(/^ct-/.test(a.id))return f(v('capacity_now_kw'))+' kW';
  if(a.id==='cdu-01')return '유량 '+f(v('flow_pct'))+'%';
  if(/^rack-/.test(a.id))return f(v('it_kw'))+' kW · '+f(v('inlet_top_c'))+'°C';
  const p=K().primary(a);return p?f(p.value)+(typeof p.value==='number'&&p.unit?' '+p.unit:''):K().STATUS[a.status];
 }
 const rackId=r=>'rack-'+String(r).toLowerCase();
 function nodes(root){
  const out=[];
  for(const n of root.querySelectorAll('[data-facility]'))out.push([n,n.getAttribute('data-facility')]);
  for(const n of root.querySelectorAll('[data-rack]'))out.push([n,rackId(n.getAttribute('data-rack'))]);
  return out;
 }
 // 노드의 화면 상자를 카메라 그룹(root)의 좌표로
 function box(root,n){try{const b=n.getBBox(),m=root.getCTM().inverse().multiply(n.getCTM());
  const p=(x,y)=>[m.a*x+m.c*y+m.e,m.b*x+m.d*y+m.f],[x0,y0]=p(b.x,b.y),[x1,y1]=p(b.x+b.width,b.y+b.height);
  return {x:Math.min(x0,x1),y:Math.min(y0,y1),w:Math.abs(x1-x0),h:Math.abs(y1-y0)};}catch{return null;}}

 function decorate(host,{mode,selected}={}){
  const svg=host?.querySelector('svg.dc-world'),root=svg?.querySelector('[data-camera]');
  const d=K()?.store.data,s=d?.simulator?d.state:null;
  if(!root)return;
  root.querySelector(':scope>.fc-map-layer')?.remove();
  for(const n of root.querySelectorAll('.fc-floor-status'))n.remove();
  if(!s)return;
  const building=mode==='building',room=mode==='facility'||mode==='floor';
  const live=new Map(s.assets.map(a=>[a.id,a]));
  const k=svg.clientWidth/Math.max(1,svg.viewBox.baseVal.width);   // 사용자 단위 → 화면 px
  const found=new Map();
  for(const [n,id] of nodes(root)){
   const a=live.get(id);if(!a)continue;
   n.classList.add('fc-live');n.setAttribute('data-status',a.status);n.classList.toggle('selected',id===selected);
   if(!n.hasAttribute('data-dc-rack')){n.setAttribute('data-asset',id);n.setAttribute('data-dc-facility',id);n.setAttribute('role','button');n.setAttribute('tabindex','0');
    n.setAttribute('aria-label',(a.title||id)+' · '+K().STATUS[a.status]+' · 상태와 조치 보기');}
   if(!found.has(id))found.set(id,n);
  }
  const layer=el('g',{class:'fc-map-layer','pointer-events':'none'});
  const labels=root.querySelector(':scope>.dc-world-labels');
  root.insertBefore(layer,labels||null);
  const boxes=new Map([...found].map(([id,n])=>[id,box(root,n)]).filter(([,b])=>b));
  const pipes=K().EDGES.filter(e=>e[2]!=='air');
  // 끊긴 계통: 원인은 경보가 이름을 대는 설비만 짚는다(숨긴 장애를 따로 알려 주지 않는다).
  // 원인 위에는 작은 '끊김' 표시, 그 아래쪽(하류) 설비에는 '영향' 테두리. 움직이는 선은 쓰지 않는다.
  const named=new Set(s.alarms.map(a=>a.asset_id).filter(Boolean));
  const causes=new Set();
  for(const e of pipes)if(K().edgeState(e,s)==='broken'){if(named.has(e[0]))causes.add(e[0]);else if(named.has(e[1]))causes.add(e[1]);}
  const affected=new Set(),queue=[...causes];
  while(queue.length){const id=queue.shift();for(const e of pipes)if(e[0]===id&&!affected.has(e[1])&&!causes.has(e[1])){affected.add(e[1]);queue.push(e[1]);}}
  const marks=el('g',{class:'fc-map-marks'});layer.append(marks);
  for(const id of affected){const b=boxes.get(id);if(!b)continue;const pad=4/k;
   marks.append(el('rect',{class:'fc-map-affected',x:b.x-pad,y:b.y-pad,width:b.w+pad*2,height:b.h+pad*2,rx:6/k,'stroke-width':1.6/k,'stroke-dasharray':`${5/k} ${4/k}`}));}
  for(const id of causes){const b=boxes.get(id);if(!b)continue;const r=11;
   const g=el('g',{class:'fc-map-cut',transform:`translate(${(b.x+b.w).toFixed(2)} ${(b.y+b.h).toFixed(2)}) scale(${(1/k).toFixed(4)})`});
   g.append(el('title',{},'끊김: '+(live.get(id)?.title||id)),el('rect',{x:-r*2,y:-r,width:r*4,height:r*2,rx:r,'stroke-width':1.6}),
    el('path',{d:'M-15-4l8 8M-7-4l-8 8','stroke-width':2.2,fill:'none'}),el('text',{x:-3,y:5,'font-size':13},'끊김'));
   marks.append(g);}
  // 고른 설비: 위·아래로 바로 이어진 설비를 바닥면을 따르는 얇은 정적인 선으로(선택을 풀면 사라진다)
  if(selected&&boxes.has(selected)){
   const [ux,uy]=window.DataCenterArchitecture?.iso(1,0,0)||[28,8],links=el('g',{class:'fc-map-links'});layer.insertBefore(links,marks);
   const foot=b=>[b.x+b.w/2,b.y+b.h];
   const p0=foot(boxes.get(selected));
   const ends=[];
   for(const e of pipes){const other=e[0]===selected?e[1]:e[1]===selected?e[0]:null;if(!other||!boxes.has(other)||ends.some(x=>x[0]===other))continue;
    if(building&&K().floorOf(other)!==K().floorOf(selected))continue;ends.push([other,e[2]]);}
   for(const [other,sys] of ends){
    const p1=foot(boxes.get(other)),dx=p1[0]-p0[0],dy=p1[1]-p0[1],a=(dx/ux+dy/uy)/2,c=[p0[0]+a*ux,p0[1]+a*uy];
    links.append(el('path',{class:'fc-map-link','data-sys':sys,d:`M${p0[0].toFixed(1)} ${p0[1].toFixed(1)}L${c[0].toFixed(1)} ${c[1].toFixed(1)}L${p1[0].toFixed(1)} ${p1[1].toFixed(1)}`,'stroke-width':1.6/k}),
     el('circle',{class:'fc-map-link-end','data-sys':sys,cx:p1[0].toFixed(1),cy:p1[1].toFixed(1),r:3.5/k}));}
   links.append(el('circle',{class:'fc-map-link-end','data-sys':'self',cx:p0[0].toFixed(1),cy:p0[1].toFixed(1),r:4.5/k}));
  }
  // 값 배지: 겹치면 덜 중요한 것을 뺀다
  const badges=el('g',{class:'fc-map-badges'});layer.append(badges);
  const rank={critical:3,warning:2,off:1,normal:0};
  const want=[...found.keys()].map(id=>live.get(id)).filter(a=>room||KEY.includes(a.id)||a.status==='critical'||a.status==='warning')
   .sort((x,y)=>rank[y.status]-rank[x.status]||KEY.indexOf(y.id)-KEY.indexOf(x.id));
  const placed=[];
  for(const lab of root.querySelectorAll('.dc-world-labels>g')){       // 층·랙 이름표 자리를 먼저 비워 둔다
   const m=/translate\(([-\d.e]+) ([-\d.e]+)\)/.exec(lab.getAttribute('transform')||''),r=lab.querySelector('rect');if(!m||!r)continue;
   const w=Number(r.getAttribute('width'))+80,hh=Number(r.getAttribute('height'));placed.push({x:Number(m[1])*k-Number(r.getAttribute('width'))/2,y:Number(m[2])*k+Number(r.getAttribute('y')),w,h:hh});}
  for(const a of want){
   const b=boxes.get(a.id);if(!b)continue;
   const text=badgeText(a),sub=room?(a.title||a.id):'',fs=building?12.5:14;
   const tw=Math.max([...text].reduce((n,c)=>n+(c.charCodeAt(0)>0x2000?fs:fs*.58),0),sub?[...sub].reduce((n,c)=>n+(c.charCodeAt(0)>0x2000?fs*.82:fs*.5),0):0)+30;
   const th=sub?40:24,cx=(b.x+b.w/2)*k,cy=b.y*k-6;            // 화면 px
   const rect={x:cx-tw/2,y:cy-th,w:tw,h:th};
   if(placed.some(r=>rect.x<r.x+r.w+4&&r.x<rect.x+rect.w+4&&rect.y<r.y+r.h+3&&r.y<rect.y+rect.h+3))continue;
   placed.push(rect);
   const g=el('g',{class:'fc-map-badge','data-status':a.status,'data-asset-badge':a.id,transform:`translate(${(cx/k).toFixed(2)} ${(cy/k).toFixed(2)}) scale(${(1/k).toFixed(4)})`});
   g.append(el('rect',{x:-tw/2,y:-th,width:tw,height:th,rx:7}),el('circle',{cx:-tw/2+12,cy:-th/2-(sub?7:0),r:4.5}),
    el('text',{x:-tw/2+22,y:sub?-th+17:-7,'font-size':fs},text));
   if(sub)g.append(el('text',{x:-tw/2+22,y:-7,'font-size':fs*.82,class:'fc-map-badge-sub'},sub));
   badges.append(g);
  }
  // 층 경보: 전체 배치에서 층 이름표 옆에 붙인다
  if(building)for(const lab of root.querySelectorAll('.dc-world-labels [data-label-floor]')){
   const f=lab.getAttribute('data-label-floor'),ids=s.assets.filter(a=>K().floorOf(a.id)===f);
   const al=s.alarms.filter(x=>x.asset_id&&K().floorOf(x.asset_id)===f).length+(s.aisles.some(x=>x.floor===f&&x.status!=='normal')?1:0);
   const worst=ids.map(a=>a.status).concat(s.aisles.filter(x=>x.floor===f).map(x=>x.status)).sort((x,y)=>rank[y]-rank[x])[0];
   if(!ids.length||!['warning','critical'].includes(worst)&&!al)continue;
   const span=Number(lab.querySelector('rect')?.getAttribute('width')||80),text=(worst==='critical'?'위험':'주의')+(al?' 경보 '+al:'');
   const w=[...text].reduce((n,c)=>n+(c.charCodeAt(0)>0x2000?12:7),0)+16;
   const chip=el('g',{class:'fc-floor-status','data-status':worst,transform:`translate(${span/2+5} -11)`});
   chip.append(el('rect',{width:w,height:25,rx:12}),el('text',{x:w/2,y:17,'text-anchor':'middle','font-size':12},text));lab.append(chip);
  }
 }
 return {decorate};
})();
