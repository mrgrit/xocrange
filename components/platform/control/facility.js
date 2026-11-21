'use strict';
// DCOC 화면(ADR 0014): 설치된 시설 모듈이 보낸 상태를 그래픽 대시보드로 보여 주고 요청을 건넨다.
// Core는 시뮬레이션하지 않고 장애 논리도 갖지 않는다. 공용 부품은 facility-kit.js(FacilityKit)에 있다.
const Facility=(()=>{
 const K=FacilityKit;
 const {ic,pill,num,fmt,bar,ring,needle,thermo,battery,donut,spark}=K;
 let data=null,sel=null,assetFilter='all',onlyIssues=false,table=false,form={fault:'',target:'',minutes:''},touched=0,unsub=null;
 let drawer=null;                         // 강사 도구 서랍(null이면 권한에 따라 기본값)
 const store=K.store;
 const reasons={not_installed:['시설 모듈이 설치되지 않았습니다','실시간 설비 상태와 장애 실습은 Live Fire의 시설 모듈이 제공합니다.'],
  absent:['시설 시뮬레이터가 아직 상태를 보내지 않았습니다','모듈이 시작되는 중일 수 있습니다. 잠시 뒤 다시 확인해 주세요.'],
  stale:['시설 시뮬레이터의 상태가 갱신되지 않고 있습니다','마지막으로 받은 값은 현재 상태가 아닐 수 있어 표시하지 않습니다.'],
  invalid:['시설 시뮬레이터가 보낸 상태를 확인할 수 없습니다','형식이 맞지 않는 값은 화면에 쓰지 않습니다.'],
  commercial_unavailable:['라이선스가 없습니다','시설 모듈은 Live Fire 이상 라이선스에서 동작합니다.'],
  entitlement_module:['라이선스에 시설 모듈이 없습니다','라이선스가 허용한 모듈만 사용할 수 있습니다.'],
  entitlement_tier:['등급이 맞지 않습니다','시설 모듈은 Live Fire 이상에서 동작합니다.']};
 const M=(s,k)=>K.metricOf(s,k);
 const V=(s,k)=>M(s,k)?.value;
 const lsGet=k=>{try{return localStorage.getItem(k);}catch{return null;}};
 const lsSet=(k,v)=>{try{localStorage.setItem(k,v);}catch{}};
 const panel=(name,title,iconName,body,{tools='',cls='',sub=''}={})=>`<section class="fc-panel ${cls}" data-panel="${name}"><header class="fc-panel-head"><h3>${ic(iconName)}${title}</h3>${sub?`<span class="fc-panel-sub">${sub}</span>`:''}<div class="fc-panel-tools">${tools}</div></header>${body}</section>`;

 /* ── 한눈 판정 ─────────────────────────────────────────── */
 function verdict(d){
  const s=d.state,crit=s.alarms.filter(a=>a.level==='critical'),warn=s.alarms.filter(a=>a.level==='warning');
  const bad=s.assets.filter(a=>a.status==='critical');
  const level=crit.length||bad.length?'critical':warn.length?'warning':'normal';
  const top=crit[0]||warn[0],target=top?.asset_id;
  const head={critical:'위험 — 지금 대응이 필요합니다',warning:'주의 — 지켜봐야 할 항목이 있습니다',normal:'정상 — 모든 설비가 정상 범위입니다'}[level];
  return `<div class="fc-verdict" data-status="${level}"><span class="fc-verdict-icon">${ic(level==='normal'?'check':level==='warning'?'alert':'octagon')}</span><div class="fc-verdict-main"><strong>${head}</strong>`+
   `<span>${top?`${K.pill(top.level)} ${esc(top.message)}`:'활성 경보가 없습니다.'}${target?` <button class="fc-link" data-asset="${esc(target)}">먼저 볼 곳: ${esc(K.assetOf(s,target)?.title||target)} ${ic('chev')}</button>`:''}</span></div>`+
   `<div class="fc-verdict-counts"><span data-status="critical"><b>${num(crit.length)}</b>위험 경보</span><span data-status="warning"><b>${num(warn.length)}</b>주의 경보</span><span><b>${num(V(s,'active_faults')??0)}</b>진행 중인 장애</span><span><b>${num((s.work||[]).length)}</b>진행 중인 작업</span></div></div>`;}
 function toolbar(d){
  const s=d.state;
  return `<div class="fc-toolbar">${verdict(d)}<div class="fc-actions"><button class="fc-btn primary" data-action="drill-open">${ic('flag')}시나리오 훈련</button>`+
   `${s.drill?.status==='running'?'':K.scaleSelect(s,d.can_operate)}${d.can_operate?`<button class="fc-btn ghost" data-action="instructor-toggle" aria-expanded="${drawerOpen(d)}">${ic('bolt')}강사 도구</button>`:''}`+
   `<a class="fc-btn ghost" href="#datacenter">${ic('map')}관제 지도</a><button class="fc-icon-btn" data-action="guide-open" aria-label="사용법" title="사용법">${ic('help')}</button></div>`+
   `<div class="fc-sync">${ic('clock')}시뮬레이터 갱신 ${esc(K.clock(s.generated_at))} · ${esc(String(s.time_scale))}배속${d.read_only?' · 라이선스 만료: 조회만 가능':''}</div></div>`;}
 function guide(){
  if(lsGet('xoc-dcoc-guide')==='closed')return '';
  return `<section class="fc-guide" data-panel="guide"><h3>${ic('help')}처음이라면 이 순서로 보세요</h3><ol>`+
   `<li><b>1</b><div><strong>문제 찾기</strong><span>맨 위 판정 줄과 경보, 계통 그림의 빨간 고리에서 이상한 설비를 찾습니다. 관제 지도에서도 설비가 색으로 빛납니다.</span></div></li>`+
   `<li><b>2</b><div><strong>설비 누르고 조치</strong><span>설비를 누르면 오른쪽에 측정값과 '할 수 있는 조치'가 나옵니다. 조치를 골라 실행합니다.</span></div></li>`+
   `<li><b>3</b><div><strong>결과 보기</strong><span>진행 막대가 끝나면 추이 그래프에서 수치가 돌아오는지 확인합니다. 모든 기록은 SIEM에서도 분석할 수 있습니다.</span></div></li>`+
   `</ol><button class="fc-btn ghost" data-action="guide-close">${ic('x')}닫기</button></section>`;}

 /* ── KPI 6개 ───────────────────────────────────────────── */
 function kpis(d){
  const s=d.state,ups=K.assetOf(s,'ups-01');
  const it=V(s,'it_load_kw')??0,load=K.mval(ups,'load_pct')??0,cap=V(s,'cooling_capacity_kw')??0,dem=V(s,'cooling_demand_kw')??0;
  const margin=cap-dem,mfrac=cap>0?dem/cap:1,mstat=margin<0?'critical':mfrac>.85?'warning':'normal';
  const rt=V(s,'ups_runtime_min')??0,chg=V(s,'ups_charge_pct')??0,onb=K.mval(ups,'mode')==='배터리 운전',rstat=onb?(rt<5?'critical':'warning'):'normal';
  const pue=V(s,'pue')??1,pstat=pue>=1.9?'critical':pue>=1.5?'warning':'normal';
  const hot=V(s,'hottest_aisle_temp_c')??0,hstat=K.tempStatus(hot),hz=String(V(s,'hottest_aisle')||'');
  const cr=s.alarms.filter(a=>a.level==='critical').length,wa=s.alarms.length-cr;
  const ustat=load>100?'critical':load>85?'warning':'normal';
  const tile=(key,status,title,visual,big,sub,target)=>`<div class="fc-kpi" data-metric="${key}" data-status="${status}" ${target?`data-asset="${esc(target)}" role="button" tabindex="0"`:''}><span class="fc-kpi-title">${title}</span><div class="fc-kpi-body">${visual}<div class="fc-kpi-value">${big}</div></div><div class="fc-kpi-sub">${sub}</div></div>`;
  return `<div class="fc-kpis facility-summary" data-panel="summary">`+
   tile('it_load_kw',ustat,esc(M(s,'it_load_kw')?.label||'IT 부하'),ring(load/100,ustat,96,11,`<text x="48" y="48" text-anchor="middle" class="fc-ring-text">${Math.round(load)}%</text><text x="48" y="68" text-anchor="middle" class="fc-tick">UPS</text>`),num(it,'kW'),`UPS 부하율 ${num(load,'%')} · ${esc(M(s,'total_power_kw')?.label||'')} ${num(V(s,'total_power_kw'),'kW')}`,'ups-01')+
   tile('cooling_capacity_kw',mstat,'냉방 여유',ring(mfrac,mstat,96,11,`<text x="48" y="48" text-anchor="middle" class="fc-ring-text">${Math.round(mfrac*100)}%</text><text x="48" y="68" text-anchor="middle" class="fc-tick">사용</text>`),num(Math.round(margin*10)/10,'kW'),`${esc(M(s,'cooling_demand_kw')?.label||'')} ${num(dem,'kW')} / ${esc(M(s,'cooling_capacity_kw')?.label||'')} ${num(cap,'kW')}<br>${ic('alert')}${esc(M(s,'cooling_limit')?.label||'')}: <b>${esc(String(V(s,'cooling_limit')??'—'))}</b>`,'chiller-01')+
   tile('ups_runtime_min',rstat,esc(M(s,'ups_runtime_min')?.label||'UPS 잔여 시간'),battery(chg,rstat,92),num(Math.min(rt,9999),'분'),`${esc(M(s,'ups_charge_pct')?.label||'')} ${num(chg,'%')}<br>${esc(M(s,'power_source')?.label||'')}: <b>${esc(String(V(s,'power_source')??'—'))}</b>`,'ups-01')+
   tile('pue',pstat,esc(M(s,'pue')?.label||'PUE'),needle(pue,1,2,[[1,1.5,'normal'],[1.5,1.9,'warning'],[1.9,2,'critical']],128),num(pue),`1.0에 가까울수록 효율이 좋습니다 · 경보 기준 1.9`,'site-efficiency')+
   tile('hottest_aisle_temp_c',hstat,esc(M(s,'hottest_aisle_temp_c')?.label||'최고 구역 온도'),thermo(hot,104),num(hot,'°C'),`${esc(M(s,'hottest_aisle')?.label||'')}: <b>${esc(hz)}</b><br>권고 상한 ${K.TEMP.advise}°C · 임계 ${K.TEMP.critical}°C`,null)+
   tile('active_alarms',cr?'critical':wa?'warning':'normal',esc(M(s,'active_alarms')?.label||'활성 경보'),donut([{value:cr,status:'critical'},{value:wa,status:'warning'}],96,`<text x="48" y="56" text-anchor="middle" class="fc-ring-text">${s.alarms.length}</text>`),num(s.alarms.length,'건'),`<span class="fc-dot-l" data-status="critical"></span>위험 ${cr} · <span class="fc-dot-l" data-status="warning"></span>주의 ${wa}`,null)+
   `</div>`;}
 // 판정 줄과 KPI에 없는 요약값도 모두 보인다(이름 그대로)
 function chips(d){const s=d.state,shown=['it_load_kw','pue','ups_runtime_min','hottest_aisle_temp_c','active_alarms','cooling_capacity_kw','cooling_demand_kw','cooling_limit','power_source','ups_charge_pct','hottest_aisle','total_power_kw','active_faults','job_state','tokens_per_s','goodput_pct','infer_p99_ms','power_cap_pct','work_in_progress'];
  const rest=s.summary.filter(m=>!shown.includes(m.key));if(!rest.length)return '';
  return `<div class="fc-chiprow">${rest.map(m=>`<span class="fc-stat" data-metric="${esc(m.key)}"><span class="fc-label">${esc(m.label)}</span>${num(m.value,m.unit)}</span>`).join('')}</div>`;}

 /* ── 계통 그림 ─────────────────────────────────────────── */
 const W=150,H=80,COL=[8,172,336,500,664];
 const POWER={w:820,h:724,nodes:[['utility-01',0,8],['sub-01',1,8],['swgr-01',2,8],['tr-01',3,8],['ats-01',4,8],['tank-fuel-01',1,116],['gen-01',2,116],
  ['batt-01',3,224],['batt-02',3,314],['ups-01',4,269],['bus-2f-a',0,420],['bus-3f-b',2,420],['pdu-04',4,420],['pdu-01',0,528],['pdu-02',1,528],['pdu-03',2,528],
  ['rack-r-2f-01',0,636],['rack-r-2f-02',1,636],['rack-r-3f-01',2,636],['rack-r-4f-01',4,636]],
  sides:{'tank-fuel-01>gen-01':'rl','gen-01>ats-01':'rb','batt-01>ups-01':'rl','batt-02>ups-01':'rl','utility-01>sub-01':'rl','sub-01>swgr-01':'rl','swgr-01>tr-01':'rl','tr-01>ats-01':'rl'},
  labels:[[664,120,'비상 전원'],[8,388,'배전(부스바·분전반)']]};
 const COOL={w:820,h:636,nodes:[['wx-01',0,8],['ct-01',1,8],['ct-02',2,8],['pump-cw-01',1.5,116],['chiller-01',1,224],['hx-01',2,224],['eco-01',3,224],
  ['tank-water-01',0,332],['pump-pcw-01',1,332],['pump-pcw-02',2,332],['crac-01',0,440],['crac-02',1,440],['fcu-3f-01',2,440],['crac-03',3,440],['cdu-01',4,440],
  ['zone:2F',0,548],['zone:3F',1.5,548],['zone:4F',3,548],['cp-dgx-01',4,548]],
  sides:{'wx-01>ct-01':'rl','wx-01>ct-02':'rl','tank-water-01>pump-pcw-01':'rl'},
  extra:[['crac-01','zone:2F'],['crac-02','zone:3F'],['fcu-3f-01','zone:3F'],['crac-03','zone:4F']],
  labels:[[500,150,'냉각수 계통 · 옥외 방열'],[500,366,'냉수 계통 · 실내 공급']]};
 const LIMIT={'냉각탑':['ct-01','ct-02'],'냉각수 펌프':['pump-cw-01'],'열교환기':['hx-01'],'냉동기':['chiller-01'],'프리쿨링 장치':['eco-01'],'냉수 펌프':['pump-pcw-01','pump-pcw-02']};
 function lines(name){const out=[];const t=String(name);if([...t].length<=8)return [t];
  const cut=[...t].map((c,i)=>c===' '||c==='('?i:-1).filter(i=>i>0),mid=[...t].length/2,i=cut.sort((a,b)=>Math.abs(a-mid)-Math.abs(b-mid))[0];
  if(i==null)return [t];out.push(t.slice(0,i).trim(),t.slice(i).trim());return out;}
 function node(s,id,x,y,bottleneck){
  if(id.startsWith('zone:')){const f=id.slice(5),a=s.aisles.find(z=>z.floor===f);if(!a)return '';const st=a.status!=='normal'?a.status:K.tempStatus(a.temp_c);
   return `<g class="fc-node" data-zone="${f}" data-status="${st}" data-key="n-${id}" transform="translate(${x} ${y})" role="button" tabindex="0" aria-label="${esc(f+' '+a.id+'열 구역')}"><rect width="${W}" height="${H}" rx="12" class="fc-node-box"/>`+
    `<svg x="10" y="10" width="22" height="22" viewBox="0 0 24 24" class="fc-node-ic"><path d="M10 4a2 2 0 0 1 4 0v10a4 4 0 1 1-4 0zM12 9v8"/></svg><text x="40" y="27" class="fc-node-name">${esc(f+' '+a.id+'열 구역')}</text>`+
    `<text x="12" y="66" class="fc-node-val">${esc(fmt(a.temp_c))}<tspan class="fc-node-unit"> °C</tspan></text></g>`;}
  const a=K.assetOf(s,id);if(!a)return '';const p=K.primary(a),ln=lines(a.title||id);
  return `<g class="fc-node ${bottleneck?'is-limit':''}" data-asset="${esc(id)}" data-status="${a.status}" data-key="n-${esc(id)}" transform="translate(${x} ${y})" role="button" tabindex="0" aria-label="${esc((a.title||id)+' · '+K.STATUS[a.status])}">`+
   `<rect width="${W}" height="${H}" rx="12" class="fc-node-box"/>${bottleneck?`<g class="fc-limit-tag" transform="translate(${W-6} -10)"><rect x="-74" width="80" height="22" rx="11"/><text x="-34" y="16" text-anchor="middle">냉방 병목</text></g>`:''}`+
   `<svg x="10" y="10" width="22" height="22" viewBox="0 0 24 24" class="fc-node-ic"><path d="${nodeIcon(id)}"/></svg>`+
   ln.map((l,i)=>`<text x="40" y="${ln.length>1?22+i*18:27}" class="fc-node-name">${esc(l)}</text>`).join('')+
   `<text x="12" y="68" class="fc-node-val">${p?esc(fmt(p.value)):''}<tspan class="fc-node-unit"> ${p&&typeof p.value!=='boolean'?esc(p.unit):''}</tspan></text>`+
   `<circle cx="${W-16}" cy="${H-16}" r="7" class="fc-node-dot"/></g>`;}
 const ICON_PATH={};
 function nodeIcon(id){const n=K.kindIcon(id);if(!ICON_PATH[n]){const m=/d="([^"]+)"/.exec(ic(n));ICON_PATH[n]=m?m[1]:'';}return ICON_PATH[n];}
 function edgePath(a,b,sides){
  const [ax,ay]=a,[bx,by]=b,cx1=ax+W/2,cx2=bx+W/2;
  if(sides==='rl'){const x1=ax+W,y1=ay+H/2,x2=bx,y2=by+H/2,mx=x1+(x2-x1)/2;return Math.abs(y1-y2)<1?`M${x1} ${y1}H${x2}`:`M${x1} ${y1}H${mx}V${y2}H${x2}`;}
  if(sides==='rb'){const x1=ax+W,y1=ay+H/2;return `M${x1} ${y1}H${cx2}V${by+H}`;}
  const y1=ay+H,y2=by,my=y2-14;return Math.abs(cx1-cx2)<1?`M${cx1} ${y1}V${y2}`:`M${cx1} ${y1}V${my}H${cx2}V${y2}`;}
 function chain(s,spec,kind){
  const pos=new Map(spec.nodes.map(([id,c,y])=>[id,[8+c*164,y]]));
  const limit=kind==='cooling'?LIMIT[String(V(s,'cooling_limit')||'')]||[]:[];
  const edges=K.EDGES.filter(e=>pos.has(e[0])&&pos.has(e[1])).map(e=>[e[0],e[1],e[2],K.edgeState(e,s)]);
  for(const [from,to] of spec.extra||[]){const a=K.assetOf(s,from);edges.push([from,to,'air',a?.status==='critical'?'broken':K.mval(a,'state')==='운전'?'flow':'dead']);}
  const order={dead:0,idle:1,flow:2,broken:3};edges.sort((x,y)=>order[x[3]]-order[y[3]]);
  const paths=edges.map(([f,t,sys,state])=>{const d=edgePath(pos.get(f),pos.get(t),spec.sides[f+'>'+t]);
   const mid=state==='broken'?(()=>{const n=d.match(/-?[\d.]+/g).map(Number);const x=(n[0]+n.at(-2))/2,y=(n[1]+n.at(-1))/2;return `<g class="fc-break" transform="translate(${x} ${y})"><circle r="11"/><path d="M-5-5 5 5M5-5-5 5"/></g>`;})():'';
   return `<g class="fc-edge" data-sys="${sys}" data-state="${state}" data-key="e-${esc(f+'>'+t)}"><path d="${d}" class="fc-edge-base"/><path d="${d}" class="fc-edge-flow"/>${mid}</g>`;}).join('');
  const labels=(spec.labels||[]).map(([x,y,t])=>`<text x="${x}" y="${y}" class="fc-chain-label">${esc(t)}</text>`).join('');
  return `<svg class="fc-chain" viewBox="0 0 ${spec.w} ${spec.h}" role="group" aria-label="${kind==='power'?'전력 계통':'냉각 계통'}">${labels}<g>${paths}</g><g>${spec.nodes.map(([id])=>node(s,id,...pos.get(id),limit.includes(id))).join('')}</g></svg>`;}
 const legend=kind=>`<div class="fc-legend"><span><i data-state="flow" data-sys="${kind}"></i>흐름</span><span><i data-state="idle"></i>대기</span><span><i data-state="broken"></i>끊김</span><span><i data-state="dead"></i>공급 없음</span></div>`;

 /* ── 추이(작은 그래프 4장, 같은 시뮬레이션 시각 축) ────────── */
 const ROWS=[['구역 온도','°C',h=>h.ai,'temp'],['IT 부하','kW',h=>h.it,'it'],['전력 사용 효율(PUE)','',h=>h.pue,'pue'],['UPS 잔여 시간','분',h=>h.ups,'ups']];
 function trendWindow(){const h=store.hist;if(h.length<2)return null;const end=h.at(-1).t,start=Math.max(h[0].t,end-60);return {start,end:Math.max(end,start+1),pts:h.filter(x=>x.t>=start)};}
 function trend(d){
  const s=d.state,win=trendWindow();
  if(!win)return `<div class="fc-trend-empty">${ic('clock')}<p>추이를 모으는 중입니다. 이 화면이나 관제 지도를 열어 두면 5초마다 값이 쌓입니다.</p></div>`;
  const Wd=1000,L=64,R=96,rowH=88,gap=44,top=30,x=t=>L+(Wd-L-R)*(t-win.start)/(win.end-win.start);
  const aisleKeys=s.aisles.map(a=>a.floor+' '+a.id);
  let g='';
  ROWS.forEach(([title,unit,get,kind],r)=>{
   const y0=top+r*(rowH+gap),y1=y0+rowH;
   let series=kind==='temp'?aisleKeys.map((k,i)=>({name:k+'열',color:K.SERIES[i%3],vals:win.pts.map(p=>p.ai?.[k])})):[{name:title,color:'#b79bff',vals:win.pts.map(get)}];
   const all=series.flatMap(x=>x.vals).filter(Number.isFinite);
   let lo=kind==='temp'?Math.max(10,Math.floor(Math.min(...all,24))-2):kind==='pue'?1:0,hi=kind==='temp'?Math.max(34,...all)+1:kind==='pue'?Math.max(2,...all):Math.max(kind==='ups'?30:10,...all)*1.15;
   const y=v=>y1-(rowH)*(v-lo)/(hi-lo);
   g+=`<text x="${L}" y="${y0-8}" class="fc-trend-title">${esc(title)}${unit?` (${unit})`:''}</text>`;
   g+=`<line x1="${L}" x2="${Wd-R}" y1="${y1}" y2="${y1}" class="fc-axis"/><line x1="${L}" x2="${Wd-R}" y1="${y0+8}" y2="${y0+8}" class="fc-grid"/>`;
   g+=`<text x="${L-8}" y="${y1+4}" class="fc-tick" text-anchor="end">${fmt(Math.round(lo*10)/10)}</text><text x="${L-8}" y="${y0+16}" class="fc-tick" text-anchor="end">${fmt(Math.round(hi*10)/10)}</text>`;
   if(kind==='temp')for(const [v,c,t] of [[K.TEMP.advise,'warning','권고 상한'],[K.TEMP.critical,'critical','임계']])if(v<hi)g+=`<line x1="${L}" x2="${Wd-R}" y1="${y(v)}" y2="${y(v)}" class="fc-limit" data-status="${c}"/><text x="${Wd-R+6}" y="${y(v)+4}" class="fc-tick">${t} ${v}°</text>`;
   if(kind==='pue')g+=`<line x1="${L}" x2="${Wd-R}" y1="${y(1.9)}" y2="${y(1.9)}" class="fc-limit" data-status="warning"/>`;
   for(const sr of series){const dpath=sr.vals.map((v,i)=>Number.isFinite(v)?`${i&&Number.isFinite(sr.vals[i-1])?'L':'M'}${x(win.pts[i].t).toFixed(1)} ${y(v).toFixed(1)}`:'').join('');
    g+=`<path d="${dpath}" class="fc-trend-line" style="stroke:${sr.color}"/>`;
    const lv=sr.vals.at(-1);if(Number.isFinite(lv)&&kind!=='temp')g+=`<text x="${Wd-R+6}" y="${y(lv)+5}" class="fc-trend-val">${fmt(lv)}</text>`;}
   if(kind==='temp')series.forEach((sr,i)=>{const lv=sr.vals.at(-1);if(Number.isFinite(lv))g+=`<circle cx="${x(win.end)}" cy="${y(lv)}" r="4" style="fill:${sr.color}"/>`;});
  });
  const yEnd=top+ROWS.length*(rowH+gap)-gap;
  for(let m=0;m<=60;m+=10){const t=win.end-m;if(t<win.start-0.01)break;g+=`<line x1="${x(t)}" x2="${x(t)}" y1="${top}" y2="${yEnd}" class="fc-grid"/><text x="${x(t)}" y="${yEnd+18}" class="fc-tick" text-anchor="middle">${m?'-'+m+'분':'지금'}</text>`;}
  for(const a of s.alarms){const t=K.simAt(a.since);if(t==null||t<win.start)continue;g+=`<g class="fc-alarm-mark" data-status="${a.level}"><line x1="${x(t)}" x2="${x(t)}" y1="${top}" y2="${yEnd}"/><title>${esc(a.message)}</title></g>`;}
  return `<div class="fc-trend-legend">${s.aisles.map((a,i)=>`<span><i style="background:${K.SERIES[i%3]}"></i>${esc(a.floor+' '+a.id)}열</span>`).join('')}<span><i class="fc-mark-l" data-status="critical"></i>경보 시작</span><span class="fc-muted">가로축: 시뮬레이션 시간(최근 ${Math.round(win.end-win.start)}분)</span></div>`+
   `<div class="fc-trend-box"><svg class="fc-trend" viewBox="0 0 ${Wd} ${yEnd+26}" data-l="${L}" data-r="${R}" data-start="${win.start}" data-end="${win.end}" role="img" aria-label="최근 시뮬레이션 시간의 구역 온도, IT 부하, PUE, UPS 잔여 시간 추이">${g}<line class="fc-cross" x1="0" x2="0" y1="${top}" y2="${yEnd}" visibility="hidden"/></svg><div class="fc-tip" hidden></div></div>`;}

 /* ── 통로 온도: 열지도 + 분포 ─────────────────────────── */
 const RACKS={'2F':['rack-r-2f-01','rack-r-2f-02'],'3F':['rack-r-3f-01'],'4F':['rack-r-4f-01']};
 function aisles(d){
  const s=d.state;
  const cards=s.aisles.map((a,i)=>{const st=a.status!=='normal'?a.status:K.tempStatus(a.temp_c),m=k=>(a.metrics||[]).find(x=>x.key===k);
   const heat=m('it_kw')?.value??0,cool=m('cooling_capacity_kw')?.value??0;
   return `<button class="fc-aisle" data-zone="${esc(a.floor)}" data-status="${st}" data-key="ai-${esc(a.id)}" style="--heat:${K.clamp((a.temp_c-18)/16,0,1).toFixed(3)}"><span class="fc-aisle-head"><i style="background:${K.SERIES[i%3]}"></i>${esc(a.floor)} · ${esc(a.id)} 통로 ${K.pill(st)}</span>`+
    `<span class="fc-aisle-temp">${num(a.temp_c,'°C')}</span>`+
    `<span class="fc-aisle-racks">${(RACKS[a.floor]||[]).map(r=>{const ra=K.assetOf(s,r),t=K.mval(ra,'inlet_top_c');return ra?`<span class="fc-rack-cell" data-status="${ra.status!=='normal'?ra.status:K.tempStatus(t??0)}" data-asset="${esc(r)}" title="${esc(ra.title)}"><b>${esc((ra.title||r).replace('랙 ',''))}</b><span>${num(t,'°C')}</span></span>`:'';}).join('')}</span>`+
    `<span class="fc-balance"><span class="fc-label">${esc(m('it_kw')?.label||'')} ${num(heat,'kW')} / ${esc(m('cooling_capacity_kw')?.label||'')} ${num(cool,'kW')}</span>${bar(cool>0?heat/cool*100:100,heat>cool?'critical':heat>cool*.85?'warning':'normal')}</span>`+
    `<span class="fc-aisle-metrics">${(a.metrics||[]).filter(x=>!['it_kw','cooling_capacity_kw'].includes(x.key)).map(x=>`<span data-metric="aisle-${esc(a.id)}.${esc(x.key)}"><span class="fc-label">${esc(x.label)}</span>${num(x.value,x.unit)}</span>`).join('')}</span></button>`;}).join('');
  // 분포: 최근 이력의 모든 구역 온도 표본
  const win=trendWindow(),vals=win?win.pts.flatMap(p=>Object.values(p.ai||{})).filter(Number.isFinite):s.aisles.map(a=>a.temp_c);
  const lo=16,hi=40,bins=Array(hi-lo).fill(0);for(const v of vals)bins[K.clamp(Math.floor(v)-lo,0,bins.length-1)]++;
  const max=Math.max(1,...bins),Wd=520,Hh=170,bw=(Wd-50)/bins.length,above=vals.length?vals.filter(v=>v>K.TEMP.advise).length/vals.length*100:0;
  const bx=v=>40+(v-lo)*bw;
  const hist=`<svg class="fc-hist" viewBox="0 0 ${Wd} ${Hh+34}" role="img" aria-label="구역 온도 분포">${bins.map((n,i)=>n?`<rect x="${(bx(lo+i)+1).toFixed(1)}" y="${(Hh-(Hh-14)*n/max).toFixed(1)}" width="${(bw-2).toFixed(1)}" height="${((Hh-14)*n/max).toFixed(1)}" rx="3" class="fc-fill" data-status="${K.tempStatus(lo+i+0.5)}"><title>${lo+i}~${lo+i+1}°C · 표본 ${n}개</title></rect>`:'').join('')}`+
   `<line x1="40" x2="${Wd-10}" y1="${Hh}" y2="${Hh}" class="fc-axis"/>${[16,20,24,28,32,36,40].map(v=>`<text x="${bx(v)}" y="${Hh+20}" class="fc-tick" text-anchor="middle">${v}°</text>`).join('')}`+
   [[K.TEMP.advise,'warning','권고 상한'],[K.TEMP.critical,'critical','임계']].map(([v,c,t])=>`<line x1="${bx(v)}" x2="${bx(v)}" y1="8" y2="${Hh}" class="fc-limit" data-status="${c}"/><text x="${bx(v)+5}" y="20" class="fc-tick">${t}</text>`).join('')+`</svg>`;
  return panel('aisles','통로 온도','therm',`<div class="facility-aisles fc-aisles">${cards}</div><div class="fc-hist-box"><div class="fc-hist-head"><strong>구역 온도 분포</strong><span>최근 ${win?Math.round(win.end-win.start):0}분 표본 ${vals.length}개 · 권고 상한(${K.TEMP.advise}°C) 초과 <b data-status="${above>0?'warning':'normal'}">${num(Math.round(above),'%')}</b></span></div>${hist}</div>`);}

 /* ── 경보 ──────────────────────────────────────────────── */
 function alarms(d){
  const s=d.state,cr=s.alarms.filter(a=>a.level==='critical').length,wa=s.alarms.length-cr,win=trendWindow();
  const tl=win?`<svg class="fc-timeline" viewBox="0 0 600 54" role="img" aria-label="경보 시작 시각">${[0,10,20,30,40,50,60].map(m=>{const x=20+560*(1-m/60);return `<line x1="${x}" x2="${x}" y1="10" y2="34" class="fc-grid"/><text x="${x}" y="50" text-anchor="middle" class="fc-tick">${m?'-'+m+'분':'지금'}</text>`;}).join('')}<line x1="20" x2="580" y1="22" y2="22" class="fc-axis"/>`+
   s.alarms.map(a=>{const t=K.simAt(a.since);if(t==null)return '';const m=Math.min(60,win.end-t);return `<circle cx="${(20+560*(1-m/60)).toFixed(1)}" cy="22" r="7" class="fc-dot" data-status="${a.level}"><title>${esc(a.message)}</title></circle>`;}).join('')+`</svg>`:'';
  return panel('alarms','경보','bell',`<div class="fc-alarm-top">${donut([{value:cr,status:'critical'},{value:wa,status:'warning'}],120,`<text x="60" y="58" text-anchor="middle" class="fc-ring-text">${s.alarms.length}</text><text x="60" y="78" text-anchor="middle" class="fc-tick">건</text>`)}`+
   `<div class="fc-alarm-legend"><span data-status="critical">${ic('octagon')}위험 <b>${cr}</b></span><span data-status="warning">${ic('alert')}주의 <b>${wa}</b></span>${tl}</div></div>${K.alarmRows(s.alarms)}`,{sub:`${s.alarms.length}건`});}

 /* ── 설비 86개: 계통별 아이콘 타일 ─────────────────────── */
 function tile(s,a){const p=K.primary(a),al=s.alarms.filter(x=>x.asset_id===a.id);
  const pct=p&&typeof p.value==='number'&&p.unit==='%';
  return `<button class="fc-tile" data-asset="${esc(a.id)}" data-status="${a.status}" data-key="t-${esc(a.id)}" title="${esc(a.title||a.id)}">${al.length?`<span class="fc-tile-alarm" data-status="${al.some(x=>x.level==='critical')?'critical':'warning'}">${ic('bell')}${al.length}</span>`:''}`+
   `<span class="fc-tile-head">${ic(K.kindIcon(a.id))}<strong>${esc(a.title||a.id)}</strong></span>`+
   `<span class="fc-tile-val">${p?`<span class="fc-label">${esc(p.label)}</span><span class="fc-tile-num">${num(p.value,p.unit)}</span>`:''}</span>${pct?bar(p.value,a.status==='normal'?'normal':a.status):''}`+
   `<span class="fc-tile-foot">${K.pill(a.status)}</span></button>`;}
 function assets(d){
  const s=d.state,groups=Object.keys(K.SYSTEMS).map(k=>[k,s.assets.filter(a=>K.systemOf(a.id)===k)]).filter(([,x])=>x.length);
  const count=(xs,st)=>xs.filter(a=>a.status===st).length;
  const chipsBar=`<div class="fc-filter">${[['all','전체',s.assets],...groups.map(([k,xs])=>[k,K.SYSTEMS[k],xs])].map(([k,t,xs])=>{const c=count(xs,'critical'),w=count(xs,'warning');
   return `<button class="fc-chip-btn" data-asset-filter="${k}" aria-pressed="${assetFilter===k}">${k==='all'?ic('grid'):ic(K.SYSTEM_ICON[k])}${esc(t)}<span class="fc-count">${xs.length}</span>${c?`<span class="fc-badge" data-status="critical">${c}</span>`:''}${w?`<span class="fc-badge" data-status="warning">${w}</span>`:''}</button>`;}).join('')}`+
   `<button class="fc-chip-btn" data-action="only-issues" aria-pressed="${onlyIssues}">${ic('alert')}문제 있는 설비만</button><button class="fc-chip-btn" data-action="assets-table" aria-pressed="${table}">${ic('grid')}자세히(표)</button></div>`;
  const pass=a=>(assetFilter==='all'||K.systemOf(a.id)===assetFilter)&&(!onlyIssues||a.status==='critical'||a.status==='warning'||s.alarms.some(x=>x.asset_id===a.id));
  let body;
  if(table){const rows=s.assets.filter(pass);
   body=`<div class="fc-table-wrap"><table class="fc-table"><thead><tr><th>설비</th><th>상태</th><th>측정값</th></tr></thead><tbody>${rows.map(a=>`<tr data-key="tr-${esc(a.id)}"><td><button class="fc-link" data-asset="${esc(a.id)}">${esc(a.title||a.id)}</button><small class="mono">${esc(a.id)}</small></td><td>${K.pill(a.status)}</td><td class="fc-metrics">${a.metrics.map(m=>`<span>${esc(m.label)} <strong>${num(m.value,m.unit)}</strong></span>`).join('')}</td></tr>`).join('')}</tbody></table></div>`;}
  else body=groups.map(([k,xs])=>{const shown=xs.filter(pass);if(!shown.length)return '';
   return `<div class="fc-group" data-key="g-${k}"><h4>${ic(K.SYSTEM_ICON[k])}${esc(K.SYSTEMS[k])}<span>${xs.length}개</span>${count(xs,'critical')?`<span class="fc-badge" data-status="critical">위험 ${count(xs,'critical')}</span>`:''}${count(xs,'warning')?`<span class="fc-badge" data-status="warning">주의 ${count(xs,'warning')}</span>`:''}</h4><div class="fc-tiles">${shown.map(a=>tile(s,a)).join('')}</div></div>`;}).join('')||'<p class="fc-empty">조건에 맞는 설비가 없습니다.</p>';
  return panel('assets','설비 상태','grid',chipsBar+body,{sub:`${s.assets.length}개`});}

 /* ── GPU 클러스터 ──────────────────────────────────────── */
 function cluster(d){
  const s=d.state,nodes=s.assets.filter(a=>/^gpu-/.test(a.id));if(!nodes.length)return '';
  const m=(a,k)=>a?.metrics.find(x=>x.key===k);
  const card=a=>{const t=K.mval(a,'gpu_temp_c')??0,clk=K.mval(a,'clock_pct')??0,sp=K.mval(a,'speed_pct')??0,xid=K.mval(a,'xid')??0;
   return `<button class="fc-gpu" data-asset="${esc(a.id)}" data-status="${a.status}" data-key="gpu-${esc(a.id)}"><span class="fc-gpu-head">${ic('chip')}<strong>${esc(a.title||a.id)}</strong>${K.pill(a.status,String(K.mval(a,'state')??''))}</span>`+
    `<span class="fc-gpu-role">${esc(m(a,'role')?.label||'')} <b>${esc(String(K.mval(a,'role')??''))}</b>${xid>0?`<span class="fc-badge" data-status="critical">XID ${esc(String(xid))}</span>`:''}</span>`+
    `<span class="fc-gpu-body">${ring(clk/100,clk<90?'warning':'normal',78,9,`<text x="39" y="44" text-anchor="middle" class="fc-ring-text small">${Math.round(clk)}%</text>`)}<span class="fc-gpu-stats">`+
    `<span><span class="fc-label">${esc(m(a,'gpu_temp_c')?.label||'')}</span>${num(t,'°C')}${bar(t,t>85?'critical':t>75?'warning':'normal',85)}</span>`+
    `<span><span class="fc-label">${esc(m(a,'speed_pct')?.label||'')}</span>${num(sp,'%')}${bar(sp,sp<80?'warning':'normal')}</span></span></span>`+
    `<span class="fc-gpu-foot"><span>${esc(m(a,'clock_pct')?.label||'')} ${num(clk,'%')}</span><span>${esc(m(a,'power_kw')?.label||'')} ${num(K.mval(a,'power_kw'),'kW')}</span><span>${esc(m(a,'gpus')?.label||'')} ${num(K.mval(a,'gpus'),'기')}</span></span></button>`;};
  const job=K.assetOf(s,'train-01'),inf=K.assetOf(s,'infer-01'),stor=K.assetOf(s,'stor-01');
  const gp=K.mval(job,'goodput_pct')??0,ck=K.mval(job,'ckpt_age_min')??0;
  const jobCard=job?`<button class="fc-svc" data-asset="train-01" data-status="${job.status}"><span class="fc-gpu-head">${ic('layers')}<strong>${esc(job.title||'train-01')}</strong>${K.pill(job.status,String(K.mval(job,'state')??''))}</span>`+
   `<span class="fc-svc-big"><span class="fc-label">${esc(m(job,'tokens_per_s')?.label||'')}</span>${num(K.mval(job,'tokens_per_s'),m(job,'tokens_per_s')?.unit)}</span>`+
   `<span class="fc-svc-rings"><span>${ring(gp/100,gp<90?'warning':'normal',84,10,`<text x="42" y="47" text-anchor="middle" class="fc-ring-text small">${Math.round(gp)}%</text>`)}<small>${esc(m(job,'goodput_pct')?.label||'')}</small></span>`+
   `<span>${ring(Math.min(ck,60)/60,ck>60?'critical':ck>45?'warning':'normal',84,10,`<text x="42" y="47" text-anchor="middle" class="fc-ring-text small">${Math.round(ck)}분</text>`)}<small>${esc(m(job,'ckpt_age_min')?.label||'')}</small></span></span>`+
   `<span class="fc-gpu-foot">${['step','step_s','lost_steps','loss','ckpt_failures'].map(k=>m(job,k)).filter(Boolean).map(x=>`<span>${esc(x.label)} ${num(x.value,x.unit)}</span>`).join('')}</span></button>`:'';
  const p99=store.hist.map(h=>h.a?.['infer-01']),sla=K.mval(inf,'sla_ms')??500,dem=K.mval(inf,'demand_rps')??0,capr=K.mval(inf,'capacity_rps')??1;
  const infCard=inf?`<button class="fc-svc" data-asset="infer-01" data-status="${inf.status}"><span class="fc-gpu-head">${ic('chip')}<strong>${esc(inf.title||'infer-01')}</strong>${K.pill(inf.status)}</span>`+
   `<span class="fc-svc-big"><span class="fc-label">${esc(m(inf,'p99_ms')?.label||'')}</span>${num(K.mval(inf,'p99_ms'),'ms')}<small class="fc-muted">${esc(m(inf,'sla_ms')?.label||'')} ${fmt(sla)}ms</small></span>`+
   spark(p99.slice(-120),{w:300,h:56,line:sla,lo:0,status:inf.status==='normal'?'normal':inf.status})+
   `<span class="fc-gpu-stats"><span><span class="fc-label">${esc(m(inf,'demand_rps')?.label||'')} / ${esc(m(inf,'capacity_rps')?.label||'')}</span>${num(dem)} / ${num(capr,'건/초')}${bar(dem/Math.max(capr,1)*100,dem>capr?'critical':dem>capr*.85?'warning':'normal')}</span>`+
   `<span><span class="fc-label">${esc(m(inf,'error_pct')?.label||'')}</span>${num(K.mval(inf,'error_pct'),'%')}</span><span><span class="fc-label">${esc(m(inf,'mem_pct')?.label||'')}</span>${num(K.mval(inf,'mem_pct'),'%')}${bar(K.mval(inf,'mem_pct'),(K.mval(inf,'mem_pct')??0)>90?'critical':'normal',90)}</span></span></button>`:'';
  const links=s.assets.filter(a=>/^link-/.test(a.id)),sw=s.assets.filter(a=>/^(leaf|spine)-/.test(a.id));
  const net=`<div class="fc-svc fc-net"><span class="fc-gpu-head">${ic('net')}<strong>네트워크</strong></span><span class="fc-net-row">${sw.map(a=>`<button class="fc-mini" data-asset="${esc(a.id)}" data-status="${a.status}">${ic('net')}${esc(a.title||a.id)}</button>`).join('')}</span>`+
   `<span class="fc-net-row">${links.map(a=>`<button class="fc-mini" data-asset="${esc(a.id)}" data-status="${a.status}" title="${esc(a.title||a.id)}">${ic('link')}${esc((a.title||a.id).replace(' 링크','').replace('GPU 노드 ',''))} <b>${esc(String(K.mval(a,'state')??''))}</b></button>`).join('')}</span>`+
   (stor?`<button class="fc-mini wide" data-asset="stor-01" data-status="${stor.status}">${ic('disk')}${esc(stor.title)} <span>${esc(m(stor,'capacity_pct')?.label||'')} ${num(K.mval(stor,'capacity_pct'),'%')}</span>${bar(K.mval(stor,'capacity_pct'),(K.mval(stor,'capacity_pct')??0)>90?'critical':'normal',90)}<span>${esc(m(stor,'inode_pct')?.label||'')} ${num(K.mval(stor,'inode_pct'),'%')}</span>${bar(K.mval(stor,'inode_pct'),(K.mval(stor,'inode_pct')??0)>95?'critical':'normal',95)}</button>`:'')+`</div>`;
  const sum=['job_state','tokens_per_s','goodput_pct','infer_p99_ms','power_cap_pct','work_in_progress'].map(k=>M(s,k)).filter(Boolean);
  return panel('cluster','GPU 클러스터','chip',`<div class="fc-chiprow">${sum.map(x=>`<span class="fc-stat" data-metric="${esc(x.key)}"><span class="fc-label">${esc(x.label)}</span>${num(x.value,x.unit)}</span>`).join('')}<button class="fc-btn ghost" data-zone="cluster">${ic('wrench')}클러스터 전체 조치</button></div>`+
   `<div class="fc-gpus">${nodes.map(card).join('')}</div><div class="fc-svcs">${jobCard}${infCard}${net}</div>`,{sub:'3F AI 전산실 · R-3F-01'});}

 /* ── 진행 중인 작업 · 전체 조치(층·부하 차단) ─────────────── */
 function work(d){const s=d.state,rows=K.workRows(s);
  return panel('work','진행 중인 작업','clock',rows?`<div class="fc-works">${rows}</div>`:`<p class="fc-empty">진행 중인 작업이 없습니다. 설비를 눌러 조치를 실행하면 여기에 진행 막대가 나옵니다.</p>`,{sub:`${(s.work||[]).length}건`});}
 function siteOps(d){
  const s=d.state,can=d.can_operate,floors=[...new Set((s.catalog.operations||[]).flatMap(o=>o.targets.map(t=>t.id)).filter(t=>/^([1-9]F|B1|SITE)$/.test(t)))].sort();
  const shed=s.catalog.shed_groups;
  return panel('operate','구역·전체 조치','wrench',`<div class="fc-zones">${floors.map(f=>`<button class="fc-zone" data-zone="${esc(f)}">${ic('layers')}<span>${esc(K.targetTitle(s,f))}</span><small>${K.opsFor(s,f).length}가지 조치</small>${ic('chev')}</button>`).join('')}</div>`+
   (shed.length?`<h4 class="fc-sub">${ic('power')}부하 차단 <small>전원이 부족할 때 어떤 부하를 내릴지 운영자가 정합니다.</small></h4><div class="fc-sheds">${shed.map(g=>`<div class="fc-shed" data-status="${g.shed?'off':'normal'}" data-key="sh-${esc(g.id)}"><div><strong>${esc(g.title)}</strong><small>${esc(g.impact)}</small></div><span class="fc-shed-kw">${num(g.load_kw,'kW')}</span>${K.pill(g.shed?'off':'normal',g.shed?'차단됨':'공급 중')}`+
    `${can?`<button class="fc-btn ${g.shed?'ghost':'danger'}" data-facility="${g.shed?'restore':'shed'}" data-group="${esc(g.id)}">${g.shed?'복구':'차단'}</button>`:''}</div>`).join('')}</div>`:'')+(can?'':K.permissionNote(d)),{cls:'',sub:''}).replace('data-panel="operate"','data-panel="operate" data-scope="site"');}

 /* ── 기록 + SIEM ───────────────────────────────────────── */
 const EV={info:'info',inject:'bolt',clear:'undo',alarm:'bell',recover:'check',action:'wrench'};
 function events(d){
  const s=d.state,list=[...s.events].reverse(),from=s.drill?.status==='running'?s.drill.started_at:s.events[0]?.at;
  const siem=session.siem_available?`<a class="fc-btn primary" data-action="siem-open" href="${esc(K.siemURL(from))}" target="_blank" rel="noopener noreferrer">${ic('search')}SIEM에서 분석 ${ic('ext')}</a>`:'';
  return panel('events','기록','list',`<p class="fc-note">${ic('info')}조치·장애·경보·훈련 기록은 SIEM에도 남습니다(규칙 그룹 facility). 장애를 넣고 되돌린 내용은 감사 기록에도 남습니다.</p>`+
   (list.length?`<ol class="fc-feed">${list.map((e,i)=>{const flag=/^훈련|강사 반 전체/.test(e.message);return `<li data-kind="${esc(e.kind)}" data-key="ev-${esc(e.at)}-${i}"><span class="fc-feed-ic">${ic(flag?'flag':EV[e.kind]||'info')}</span><time>${esc(K.clock(e.at))}</time><span>${esc(e.message)}</span></li>`;}).join('')}</ol>`:'<p class="fc-empty">기록이 없습니다.</p>'),{tools:siem});}

 /* ── 강사 도구(접이식): 기존 선택자를 그대로 둔다 ───────── */
 const drawerOpen=d=>drawer??(lsGet('xoc-dcoc-instructor')??(session.role==='admin'?'open':'closed'))==='open';
 function instructor(d){
  const s=d.state,can=d.can_operate;if(!can)return '';
  const open=drawerOpen(d),list=s.catalog.faults;
  if(!list.some(f=>f.id===form.fault))form.fault=list[0]?.id||'';
  const chosen=list.find(f=>f.id===form.fault);if(chosen&&!chosen.targets.some(t=>t.id===form.target))form.target=chosen.targets[0]?.id||'';
  const groups=Object.keys(K.SYSTEMS).map(k=>[k,list.filter(f=>f.system===k)]).filter(([,x])=>x.length);
  const visible=s.faults.filter(f=>f.fault!=='hidden'),hidden=s.faults.filter(f=>f.fault==='hidden');
  const undoAll=visible.length||s.catalog.shed_groups.some(g=>g.shed);
  const body=open?`<div class="fc-instructor-body"><div class="fc-inject"><p class="fc-note">${ic('info')}시설 상태 값만 바뀝니다. 서버·네트워크에는 영향을 주지 않습니다. 모든 장애는 정한 시간이 지나면 자동으로 복구됩니다.</p><div class="facility-form fc-form">`+
   `<label>장애<select id="facility-fault">${groups.map(([k,x])=>`<optgroup label="${esc(K.SYSTEMS[k])}">${x.map(f=>`<option value="${esc(f.id)}" ${f.id===form.fault?'selected':''}>${esc(f.title)}</option>`).join('')}</optgroup>`).join('')}</select></label>`+
   `<label>대상<select id="facility-target">${(chosen?.targets||[]).map(t=>`<option value="${esc(t.id)}" ${t.id===form.target?'selected':''}>${esc(t.title)}</option>`).join('')}</select></label>`+
   `<label>지속 시간(분)<input id="facility-minutes" type="number" min="1" max="120" value="${esc(String(form.minutes||chosen?.default_minutes||10))}"></label>`+
   `<button class="fc-btn danger" data-facility="inject" ${chosen?'':'disabled'}>${ic('bolt')}장애 넣기</button></div></div>`+
   `<div class="fc-faults"><div class="fc-faults-head"><strong>진행 중인 장애 <span class="fc-count">${s.faults.length}</span></strong>${undoAll?`<button class="fc-btn ghost" data-facility="clear_all">${ic('undo')}모두 되돌리기</button>`:''}</div>`+
   (s.faults.length?`<ul>${hidden.length?`<li class="fc-fault" data-kind="hidden">${ic('lock')}<div><strong>강사가 넣은 장애 ${hidden.length}건</strong><small>강사가 반 전체에 낸 장애입니다 · 원인은 증상으로 찾습니다 · 자동 종료까지 ${K.left(hidden.map(f=>f.expires_at).sort().at(-1))}</small></div></li>`:''}`+
    visible.map(f=>`<li class="fc-fault" data-key="f-${esc(f.handle)}">${ic('bolt')}<div><strong>${esc(f.title)}</strong><small>${esc(f.target==='*'?'전체':f.target)} · ${esc(f.requested_by)} · 자동 복구까지 ${K.left(f.expires_at)}</small></div><button class="fc-btn ghost" data-facility="clear" data-handle="${esc(f.handle)}">${ic('undo')}되돌리기</button></li>`).join('')+`</ul>`
    :'<p class="fc-empty">넣은 장애가 없습니다.</p>')+`</div></div>`:'';
  return `<section class="fc-panel fc-instructor" data-panel="instructor" data-open="${open}"><button class="fc-instructor-toggle" data-action="instructor-toggle" aria-expanded="${open}">${ic('bolt')}<span><strong>강사 도구 · 장애 넣기</strong><small>수업 중 강사가 설비 고장을 직접 내는 곳입니다. 학생 훈련은 위의 '시나리오 훈련'을 쓰세요.</small></span>${s.faults.length?`<span class="fc-badge" data-status="warning">진행 ${s.faults.length}</span>`:''}${ic('chev','fc-chev')}</button>${body}</section>`;}

 /* ── 그리기 ────────────────────────────────────────────── */
 function unavailable(d){const [title,text]=reasons[d.reason]||['시설 상태를 불러오지 못했습니다','잠시 뒤 다시 확인해 주세요.'];return '<section class="panel">'+empty(title,text)+'</section>';}
 function selection(d){if(!sel)return '';const html=K.inspector(sel);if(!html){sel=null;return '';}return `<aside class="fc-drawer" aria-label="설비 상세">${html}</aside>`;}
 function html(d){
  const s=d.state;
  return `<div class="fc-root"><div class="fc-sticky">${K.banner(d,{done:false})}</div>${K.banner(d,{live:false})}${toolbar(d)}${guide()}${kpis(d)}${chips(d)}`+
   `<div class="fc-row fc-chains">${panel('power-chain','전력 계통','bolt',chain(s,POWER,'power')+legend('power'),{sub:'한전 수전 → 변전·변압 → ATS → UPS → 부스바·분전반 → 랙'})}${panel('cooling-chain','냉각 계통','snow',chain(s,COOL,'cooling')+legend('chilled'),{sub:'냉각탑 ↔ 냉동기·열교환기 ↔ 항온항습기·CDU → 구역'})}</div>`+
   `<div class="fc-row fc-row-trend">${panel('trend','추이','wave',trend(d))}${alarms(d)}</div>`+
   `<div class="fc-row fc-row-aisles">${aisles(d)}<div class="fc-col">${work(d)}${siteOps(d)}</div></div>`+
   `${assets(d)}${cluster(d)}${events(d)}${instructor(d)}${selection(d)}</div>`;}
 function draw(){
  const node=$('system-view');if(!node||!data)return;
  if(!data.simulator||!data.state){node.innerHTML=unavailable(data);$('sync-status').textContent='시설 상태 없음';return;}
  const root=node.querySelector(':scope>.fc-root');
  if(root){const t=document.createElement('div');t.innerHTML=html(data);K.morph(root,t.firstElementChild.innerHTML);}else node.innerHTML=html(data);
  $('sync-status').textContent='시설 상태 '+date(data.state.generated_at);}
 function onData(d){if(view!=='module'||!$('system-view'))return;data=d;if(Date.now()-touched<6000&&document.activeElement?.matches?.('.fc-form select,.fc-form input'))return;draw();}
 K.onRedraw(()=>{if(view==='module'&&data)draw();});

 /* ── 조작 ──────────────────────────────────────────────── */
 const open=next=>{sel=next;draw();};
 for(const kind of ['pointerdown','focusin','input'])document.addEventListener(kind,e=>{if(e.target.closest?.('.fc-form'))touched=Date.now();});
 document.addEventListener('change',e=>{if(e.target.id==='facility-fault'){form.fault=e.target.value;form.target='';form.minutes='';draw();}else if(e.target.id==='facility-target')form.target=e.target.value;else if(e.target.id==='facility-minutes')form.minutes=e.target.value;});
 document.addEventListener('click',e=>{
  if(view!=='module'||!data?.state||!e.target.closest('.fc-root'))return;
  const z=e.target.closest('[data-zone]');if(z&&!e.target.closest('[data-asset]:not([data-zone])')){open(z.dataset.zone==='cluster'?{kind:'cluster',id:'cluster'}:{kind:'floor',id:z.dataset.zone});return;}
  const f=e.target.closest('[data-asset-filter]');if(f){assetFilter=f.dataset.assetFilter;draw();return;}
  const a=e.target.closest('[data-action]');
  if(a){const act2=a.dataset.action;
   if(act2==='inspector-close'){open(null);return;}
   if(act2==='instructor-toggle'){drawer=drawerOpen(data)?'closed':'open';lsSet('xoc-dcoc-instructor',drawer);draw();if(drawer==='open')$('system-view').querySelector('[data-panel=instructor]')?.scrollIntoView({behavior:'smooth',block:'start'});return;}
   if(act2==='guide-close'){lsSet('xoc-dcoc-guide','closed');draw();return;}
   if(act2==='guide-open'){lsSet('xoc-dcoc-guide','open');draw();window.scrollTo({top:0,behavior:'smooth'});return;}
   if(act2==='only-issues'){onlyIssues=!onlyIssues;draw();return;}
   if(act2==='assets-table'){table=!table;draw();return;}
  }
  const t=e.target.closest('[data-asset]');if(t&&!e.target.closest('.fc-insp-head')){open({kind:'asset',id:t.dataset.asset});return;}
  const b=e.target.closest('[data-facility]');if(!b)return;const kind=b.dataset.facility,s=data.state;
  if(kind==='inject'){const minutes=Number($('facility-minutes').value);if(!Number.isInteger(minutes)||minutes<1||minutes>120){notice('지속 시간은 1~120분으로 입력해 주세요.',true);return;}
   const x=s.catalog.faults.find(y=>y.id===form.fault);act(()=>K.send({action:'inject',fault:form.fault,target:form.target,minutes},'장애('+(x?.title||form.fault)+')를'));}
  else if(kind==='clear')act(()=>K.send({action:'clear',handle:b.dataset.handle},'장애 복구를'));
  else if(kind==='clear_all')act(()=>K.send({action:'clear_all'},'전체 복구를'));
  else if(kind==='shed'||kind==='restore')act(()=>K.send({action:kind,group:b.dataset.group},kind==='shed'?'부하 차단을':'부하 복구를'));
 });
 document.addEventListener('keydown',e=>{
  if(view!=='module')return;
  if(e.key==='Escape'&&sel&&!document.querySelector('dialog[open]')){open(null);return;}
  const n=e.target.closest?.('.fc-root g[role=button],.fc-root .fc-kpi[role=button]');if(n&&['Enter',' '].includes(e.key)){e.preventDefault();n.dispatchEvent(new MouseEvent('click',{bubbles:true}));}});
 // 추이 그래프: 십자선과 값 풍선
 document.addEventListener('pointermove',e=>{
  const svg=e.target.closest?.('.fc-trend');if(!svg)return;
  const box=svg.getBoundingClientRect(),vb=svg.viewBox.baseVal,x=(e.clientX-box.left)/box.width*vb.width,L=+svg.dataset.l,R=+svg.dataset.r,start=+svg.dataset.start,end=+svg.dataset.end;
  const t=start+(end-start)*K.clamp((x-L)/(vb.width-L-R),0,1),pts=store.hist.filter(p=>p.t>=start);if(!pts.length)return;
  const p=pts.reduce((a,b)=>Math.abs(b.t-t)<Math.abs(a.t-t)?b:a),cx=L+(vb.width-L-R)*(p.t-start)/(end-start);
  const cross=svg.querySelector('.fc-cross');cross.setAttribute('x1',cx);cross.setAttribute('x2',cx);cross.setAttribute('visibility','visible');
  const tip=svg.parentElement.querySelector('.fc-tip');tip.hidden=false;
  tip.innerHTML=`<strong>${(p.t-end).toFixed(1)}분 · ${esc(K.clock(p.w))}</strong>${Object.entries(p.ai||{}).map(([k,v],i)=>`<span><i style="background:${K.SERIES[i%3]}"></i>${esc(k)}열 ${fmt(v)}°C</span>`).join('')}<span>IT 부하 ${fmt(p.it)} kW</span><span>PUE ${fmt(p.pue)}</span><span>UPS 잔여 ${fmt(p.ups)}분</span>`;
  const left=cx/vb.width*box.width;tip.style.left=Math.min(box.width-230,left+14)+'px';tip.style.top='24px';});
 document.addEventListener('pointerout',e=>{const svg=e.target.closest?.('.fc-trend');if(svg&&!svg.contains(e.relatedTarget)){svg.querySelector('.fc-cross')?.setAttribute('visibility','hidden');const tip=svg.parentElement.querySelector('.fc-tip');if(tip)tip.hidden=true;}});

 return {owns(component){return (component?.requires?.capabilities||[]).includes('facility-state');},
  async view(sequence){
   document.body.classList.add('facility-view');$('eyebrow').textContent='DATA CENTER OPERATIONS';$('crumb').textContent=$('page-title').textContent;
   const d=await api('facility');if(sequence!==loadSequence)return;
   K.accept(d);data=d;draw();K.use('dcoc',true);
   unsub?.();unsub=K.subscribe(onData);
   const stop=()=>{if(view!=='module'){K.use('dcoc',false);unsub?.();unsub=null;sel=null;document.body.classList.remove('facility-view');window.removeEventListener('hashchange',stop);}};
   window.addEventListener('hashchange',stop);},
  status(live,id){const a=live?.state?.assets.find(x=>x.id===id);return a?{badge:K.pill(a.status),metrics:a.metrics.map(m=>`<div><span class="metric-label">${esc(m.label)}</span><strong>${num(m.value,m.unit)}</strong></div>`).join('')}:null;}};
})();
