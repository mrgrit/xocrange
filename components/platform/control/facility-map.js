'use strict';
/* 데이터센터 관제 지도: 아이소메트릭 장면의 설비에 실시간 상태(발광·값 배지·흐름선·층 경보)를 입힌다.
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
  // 흐름선: 두 끝이 모두 지도에 있는 고리만
  const flows=el('g',{class:'fc-map-flows'});layer.append(flows);
  const boxes=new Map([...found].map(([id,n])=>[id,box(root,n)]).filter(([,b])=>b));
  for(const e of K().EDGES){
   if(e[2]==='air')continue;
   const a=boxes.get(e[0]),b=boxes.get(e[1]);if(!a||!b)continue;
   if(building&&K().floorOf(e[0])!==K().floorOf(e[1]))continue;   // 분해도에서 층을 건너는 선은 어지럽다: 같은 층 안의 고리만
   const state=K().edgeState(e,s);
   const p0=[a.x+a.w/2,a.y+a.h*.62],p1=[b.x+b.w/2,b.y+b.h*.62],dist=Math.hypot(p1[0]-p0[0],p1[1]-p0[1]);
   const bend=Math.min(140,dist*.25),mx=(p0[0]+p1[0])/2,my=(p0[1]+p1[1])/2-bend;
   const dpath=`M${p0[0].toFixed(1)} ${p0[1].toFixed(1)}Q${mx.toFixed(1)} ${my.toFixed(1)} ${p1[0].toFixed(1)} ${p1[1].toFixed(1)}`;
   const w=(building?2.2:3)/k;
   flows.append(el('path',{d:dpath,class:'fc-map-flow-base','stroke-width':w*2.4}));
   const f=el('path',{d:dpath,class:'fc-map-flow','data-state':state,'data-sys':e[2],'stroke-width':w});f.style.strokeDasharray=state==='flow'?`${6/k} ${8/k}`:state==='broken'?'none':`${2/k} ${8/k}`;
   f.style.setProperty('--dash',(-14/k*4).toFixed(2)+'px');flows.append(f);
   if(state==='broken'){const cx=.25*p0[0]+.5*mx+.25*p1[0],cy=.25*p0[1]+.5*my+.25*p1[1],r=9/k;const x=el('g',{class:'fc-map-x',transform:`translate(${cx.toFixed(1)} ${cy.toFixed(1)})`});
    x.append(el('circle',{r,'stroke-width':2/k}),el('path',{d:`M${-r/2} ${-r/2}L${r/2} ${r/2}M${r/2} ${-r/2}L${-r/2} ${r/2}`,'stroke-width':2.4/k}));flows.append(x);}
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
