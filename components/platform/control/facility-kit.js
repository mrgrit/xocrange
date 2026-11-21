'use strict';
/* 시설 화면 공용 도구: 상태 저장소(5초 폴링·짧은 이력), SVG 차트, 설비 인스펙터, 조치·훈련 요청.
 * DCOC 화면(facility.js)과 데이터센터 관제 지도(facility-map.js·datacenter.js)가 함께 쓴다.
 * Core는 모듈이 보낸 값을 보여 주고 요청을 건넬 뿐이다. 화면에 보이는 이름은 시뮬레이터가 보낸 값을 그대로 쓴다. */
window.FacilityKit=(()=>{
 const COLOR={normal:'#2fbf71',warning:'#ffb020',critical:'#ff4d6d',off:'#8a8fa3'};
 const STATUS={normal:'정상',warning:'주의',critical:'위험',off:'정지'};
 const RANK={off:0,normal:1,warning:2,critical:3};
 const SERIES=['#1fa3a0','#8f6ee6','#d0628d'];     // 통로 3개(검증한 어두운 배경용 범주 색)
 const TEMP={advise:27,critical:32};               // 구역 온도 경보 기준(권고 상한·임계)
 const reduce=()=>matchMedia('(prefers-reduced-motion: reduce)').matches;

 /* ── 아이콘(24×24 선 아이콘) ───────────────────────────── */
 const P={
  bolt:'M13 2 4 14h7l-1 8 9-12h-7z',power:'M12 3v8M6.3 6.3a8 8 0 1 0 11.4 0',
  snow:'M12 2v20M3.5 7l17 10M3.5 17l17-10M9 4l3 2 3-2M9 20l3-2 3 2',fan:'M12 12m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M12 10c0-4 1-7 4-7 2 0 2 3-1 5M14 12c4 0 7 1 7 4 0 2-3 2-5-1M12 14c0 4-1 7-4 7-2 0-2-3 1-5M10 12c-4 0-7-1-7-4 0-2 3-2 5 1',
  flame:'M12 22c4 0 7-3 7-7 0-5-4-6-4-11-3 2-5 5-5 8-1-1-2-2-2-4-2 2-3 4-3 7 0 4 3 7 7 7z',smoke:'M4 16h12a4 4 0 0 0 0-8 6 6 0 0 0-11 2A3 3 0 0 0 4 16zM6 20h8M9 12h6',
  shield:'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z',lock:'M6 11h12v10H6zM8 11V8a4 4 0 0 1 8 0v3',door:'M5 21V3h11l3 2v16M5 21h14M13 12h.01',camera:'M3 8h11l5-3v12l-5-3H3zM3 8v6',
  chip:'M7 7h10v10H7zM10 10h4v4h-4zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4',net:'M12 4v6M5 20v-4h14v4M12 10v6M9 4h6M3 20h4M17 20h4M10 20h4',
  link:'M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1',disk:'M4 6c0-2 16-2 16 0v12c0 2-16 2-16 0zM4 6c0 2 16 2 16 0M4 12c0 2 16 2 16 0',
  battery:'M3 7h15v10H3zM18 10h3v4h-3M6 10v4M9 10v4',gen:'M3 8h18v10H3zM7 8V5h4v3M8 13l2-3v6l2-3M16 11h2M16 15h2',tower:'M7 21l2-14h6l2 14M6 7h12M9 3h6v4H9zM8 14h8',
  pump:'M12 12m-6 0a6 6 0 1 0 12 0a6 6 0 1 0-12 0M12 6h9M3 18h6M12 9v6M9 12h6',drop:'M12 3c4 5 6 8 6 11a6 6 0 0 1-12 0c0-3 2-6 6-11z',exchange:'M4 8h14l-3-3M20 16H6l3 3',
  leaf:'M5 19c0-9 6-14 15-14 0 9-5 15-14 15M5 19l7-7',cloud:'M7 18h10a4 4 0 0 0 0-8 6 6 0 0 0-11.5 2A3 3 0 0 0 7 18z',sun:'M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5',
  plug:'M9 3v5M15 3v5M6 8h12v4a6 6 0 0 1-12 0zM12 18v3',bus:'M3 9h18M3 15h18M7 9v6M12 9v6M17 9v6',switch:'M4 17h4l8-8M16 17h4M14 7h6',coil:'M4 12c0-3 3-3 3 0s3 3 3 0 3-3 3 0 3 3 3 0 3-3 3 0M4 6h16M4 18h16',
  rack:'M6 3h12v18H6zM9 7h6M9 11h6M9 15h6',grid:'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',gear:'M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2',
  gauge:'M4 18a8 8 0 1 1 16 0M12 18l4-6',therm:'M10 4a2 2 0 0 1 4 0v10a4 4 0 1 1-4 0zM12 9v8',bell:'M6 16V11a6 6 0 0 1 12 0v5l2 2H4zM10 20a2 2 0 0 0 4 0',
  wrench:'M14 6a4 4 0 0 0 5 5l-9 9a2 2 0 0 1-3-3l9-9a4 4 0 0 0-2-2zM14 6l3-3',flag:'M5 21V4M5 4h11l-2 4 2 4H5',undo:'M9 14 4 9l5-5M4 9h10a6 6 0 0 1 0 12h-2',check:'M5 12l5 5 9-10',
  alert:'M12 3 2 20h20zM12 10v4M12 17h.01',octagon:'M8 3h8l5 5v8l-5 5H8l-5-5V8zM12 8v5M12 16h.01',pause:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M10 9v6M14 9v6',
  info:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 11v5M12 8h.01',clock:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7v5l3 2',play:'M7 4l13 8-13 8z',stop:'M6 6h12v12H6z',
  x:'M6 6l12 12M18 6 6 18',chev:'M9 6l6 6-6 6',search:'M10 10m-6 0a6 6 0 1 0 12 0a6 6 0 1 0-12 0M15 15l6 6',ext:'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',star:'M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1-5.4-2.9-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z',
  layers:'M12 3 2 8l10 5 10-5zM2 13l10 5 10-5',map:'M3 6l6-3 6 3 6-3v15l-6 3-6-3-6 3zM9 3v15M15 6v15',help:'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17h.01',
  scale:'M4 12h16M4 12l4-4M4 12l4 4M20 12l-4-4M20 12l-4 4',list:'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',wave:'M2 12h5l3-8 4 16 3-8h5'};
 const ic=(name,cls='')=>`<svg class="fc-ic ${cls}" viewBox="0 0 24 24" aria-hidden="true"><path d="${P[name]||P.info}"/></svg>`;
 const statusIcon={normal:'check',warning:'alert',critical:'octagon',off:'pause'};
 const esc2=v=>esc(String(v??''));
 const pill=(s,text)=>`<span class="fc-pill" data-status="${esc2(s)}">${ic(statusIcon[s]||'info')}${esc2(text||STATUS[s]||s)}</span>`;

 /* ── 설비 분류 ─────────────────────────────────────────── */
 const SYSTEMS={power:'전력',cooling:'냉방',fire:'소방',security:'출입·보안',compute:'GPU 클러스터',network:'네트워크',storage:'저장소'};
 const SYSTEM_ICON={power:'bolt',cooling:'snow',fire:'flame',security:'shield',compute:'chip',network:'net',storage:'disk'};
 const systemOf=id=>/^(gpu-|train-|infer-)/.test(id)?'compute':/^(link-|leaf-|spine-)/.test(id)?'network':/^stor-/.test(id)?'storage':
  /^(fm200|vesda|fp-)/.test(id)?'fire':/^(door|cctv|mantrap|mdet|guard|badge|robot|shred)/.test(id)?'security':
  /^(ct-|chiller|pump|hx-|eco|crac|fcu|cont-|rf-|cdu|cp-|imm|tank-water|wx)/.test(id)?'cooling':'power';
 const KIND=[[/^utility/,'power'],[/^sub-/,'bolt'],[/^swgr/,'switch'],[/^tr-/,'coil'],[/^ats/,'switch'],[/^gen/,'gen'],[/^tank-fuel/,'drop'],[/^ups/,'battery'],[/^batt/,'battery'],
  [/^pv/,'sun'],[/^bess/,'battery'],[/^fc-/,'bolt'],[/^bus/,'bus'],[/^pdu/,'plug'],[/^ct-/,'tower'],[/^chiller/,'snow'],[/^pump/,'pump'],[/^hx/,'exchange'],[/^eco/,'leaf'],
  [/^(crac|fcu)/,'fan'],[/^cont/,'door'],[/^rf-/,'grid'],[/^(cdu|cp-|imm|tank-water)/,'drop'],[/^wx/,'cloud'],[/^fm200/,'flame'],[/^vesda/,'smoke'],[/^fp-/,'bell'],
  [/^door/,'door'],[/^cctv/,'camera'],[/^(mantrap|mdet|guard|badge)/,'shield'],[/^(robot|shred)/,'gear'],[/^rack/,'rack'],[/^(gpu|train|infer)/,'chip'],[/^link/,'link'],
  [/^(leaf|spine)/,'net'],[/^stor/,'disk'],[/^site-eff/,'gauge']];
 const kindIcon=id=>(KIND.find(([r])=>r.test(id))||[0,'info'])[1];
 // 타일에 크게 보일 측정값(설비 종류별 우선순위). 라벨은 시뮬레이터 값을 그대로 쓴다.
 const PRIMARY=[[/^ups/,'runtime_min'],[/^gpu/,'gpu_temp_c'],[/^train/,'tokens_per_s'],[/^infer/,'p99_ms'],[/^tank-fuel/,'level_pct'],[/^tank-water/,'buffer_pct'],[/^stor/,'capacity_pct'],
  [/^link/,'state'],[/^(crac|fcu)/,'aisle_temp_c'],[/^ct-/,'capacity_now_kw'],[/^cdu/,'flow_pct'],[/^rack/,'inlet_top_c'],[/^batt/,'temp_c'],[/^hx/,'fouling_pct'],[/^wx/,'wetbulb_c'],[/^site-eff/,'pue'],[/^rf-/,'airflow_pct']];
 const ORDER=['load_pct','capacity_now_kw','flow_pct','temp_c','output_kw','it_kw','load_kw','supply','state','mode','signal','level','damper','energized','source','connected','free_cooling'];
 function primary(a){if(!a)return null;const want=(PRIMARY.find(([r])=>r.test(a.id))||[])[1];return a.metrics.find(m=>m.key===want)||ORDER.map(k=>a.metrics.find(m=>m.key===k)).find(Boolean)||a.metrics[0]||null;}

 /* ── 값 표시 ───────────────────────────────────────────── */
 const fmt=v=>typeof v==='boolean'?(v?'예':'아니오'):typeof v==='number'?v.toLocaleString('ko-KR',{maximumFractionDigits:Math.abs(v)>=100?0:Math.abs(v)>=10?1:2}):String(v??'—');
 const decOf=v=>Math.abs(v)>=100?0:Math.abs(v)>=10?1:2;
 const num=(v,unit='',key='')=>typeof v==='number'?`<span class="fc-num" data-num="${v}" data-dec="${decOf(v)}"${key?` data-key="${esc2(key)}"`:''}>${fmt(v)}</span>${unit?`<small class="fc-unit">${esc2(unit)}</small>`:''}`:`<span class="fc-text">${esc2(fmt(v))}</span>${unit&&typeof v!=='boolean'?`<small class="fc-unit">${esc2(unit)}</small>`:''}`;
 const metricOf=(s,key)=>s?.summary.find(m=>m.key===key);
 const assetOf=(s,id)=>s?.assets.find(a=>a.id===id);
 const mval=(a,key)=>a?.metrics.find(m=>m.key===key)?.value;
 const clamp=(v,lo,hi)=>Math.max(lo,Math.min(hi,v));
 function floorOf(id){
  const m=/^rack-r-(\d)f/.exec(id);if(m)return m[1]+'F';
  if(/^(gpu-|train-|infer-|link-|leaf-|spine-|stor-|cp-|imm-)/.test(id))return '3F';
  return (window.DataCenterArchitecture?.facilityFloors?.()||{})[id]||null;
 }
 const tempStatus=t=>t>=TEMP.critical?'critical':t>TEMP.advise?'warning':'normal';
 const ago=t=>{const s=Math.max(0,Math.round((Date.now()-new Date(t))/1000));return s<60?s+'초 전':s<3600?Math.floor(s/60)+'분 전':Math.floor(s/3600)+'시간 전';};
 const left=t=>{const s=Math.max(0,Math.round((new Date(t)-Date.now())/1000));return s>=60?Math.floor(s/60)+'분 '+(s%60)+'초':s+'초';};
 const clock=t=>new Date(t).toLocaleTimeString('ko-KR',{hour12:false});

 /* ── 저장소: 5초 폴링, 순번이 바뀐 상태만 이력에 쌓는다 ───────── */
 const HKEY='xoc-facility-history-v1',HMAX=720;
 const store={data:null,hist:[],pending:[],seq:-1,listeners:new Set(),timer:null,active:new Set()};
 try{const saved=JSON.parse(sessionStorage.getItem(HKEY)||'null');if(Array.isArray(saved))store.hist=saved.slice(-HMAX);}catch{}
 function record(s){
  const w=Date.parse(s.generated_at);if(!Number.isFinite(w))return;
  const last=store.hist.at(-1);
  if(last&&(s.sequence<last.q||w<last.w)){store.hist=[];}               // 시뮬레이터가 다시 시작했다
  else if(last&&s.sequence===last.q)return;
  const prev=store.hist.at(-1),m=k=>metricOf(s,k)?.value;
  const t=prev?prev.t+Math.max(0,w-prev.w)/60000*prev.x:0;
  const a={};for(const x of s.assets){const p=primary(x);if(p&&typeof p.value==='number')a[x.id]=p.value;}
  const sample={q:s.sequence,w,t,x:Number(s.time_scale)||1,it:m('it_load_kw'),tot:m('total_power_kw'),pue:m('pue'),ups:Math.min(m('ups_runtime_min')??0,240),
   hot:m('hottest_aisle_temp_c'),cap:m('cooling_capacity_kw'),dem:m('cooling_demand_kw'),al:s.alarms.length,cr:s.alarms.filter(x=>x.level==='critical').length,
   ai:Object.fromEntries(s.aisles.map(x=>[x.floor+' '+x.id,x.temp_c])),a};
  store.hist.push(sample);if(store.hist.length>HMAX)store.hist.splice(0,store.hist.length-HMAX);
  try{sessionStorage.setItem(HKEY,JSON.stringify(store.hist));}catch{}
 }
 // 벽시계 시각 → 시뮬레이션 분(이력 사이를 보간한다)
 function simAt(iso){const w=Date.parse(iso),h=store.hist;if(!h.length||!Number.isFinite(w))return null;if(w<=h[0].w)return w<h[0].w-1000?null:h[0].t;
  for(let i=1;i<h.length;i++)if(w<=h[i].w){const a=h[i-1],b=h[i];return a.t+(b.t-a.t)*((w-a.w)/Math.max(1,b.w-a.w));}
  const z=h.at(-1);return z.t+(w-z.w)/60000*z.x;}
 const codes={unknown_fault:'없는 장애입니다.',unknown_target:'이 대상에는 할 수 없습니다.',unknown_group:'없는 부하 묶음입니다.',unknown_handle:'이미 복구된 장애입니다.',too_many_faults:'동시에 넣을 수 있는 장애 수를 넘었습니다.',invalid_request:'요청을 처리하지 못했습니다.',
  unknown_op:'없는 조치입니다.',bad_value:'값이 허용 범위를 벗어났습니다.',node_not_drained:'먼저 노드를 작업에서 제외(drain)해야 합니다.',already_in_progress:'같은 작업이 이미 진행 중입니다.',too_much_work:'동시에 진행할 수 있는 작업 수를 넘었습니다.',already_done:'이미 그 상태입니다.',node_in_use:'그 노드는 학습 작업이 쓰고 있습니다.',job_running:'학습 작업이 이미 진행 중입니다.',job_not_running:'학습 작업이 진행 중이 아닙니다.',retripped:'차단기를 올리자마자 다시 떨어졌습니다. 부하를 먼저 줄이세요.',unknown_drill:'없는 훈련입니다.',node_unhealthy:'그 노드는 지금 쓸 수 없는 상태입니다.',last_replica:'마지막 복제본은 회수할 수 없습니다.',drill_running:'이미 훈련이 진행 중입니다.',no_drill:'진행 중인 훈련이 없습니다.',not_permitted:'강사가 넣은 장애는 강사만 끝낼 수 있습니다.'};
 function settle(s){if(!store.pending.length)return;const done=new Map(s.handled.map(h=>[h.request_id,h]));
  store.pending=store.pending.filter(p=>{const h=done.get(p.id);if(!h)return Date.now()-p.at<30000;
   if(h.status==='rejected')notice(codes[h.code]||'요청이 거절되었습니다.',true);else notice(p.label+' 적용했습니다.');return false;});}
 function accept(d){store.data=d;if(d?.state){record(d.state);settle(d.state);}for(const fn of store.listeners){try{fn(d);}catch(e){console.error(e);}}}
 async function refresh(){if(!store.active.size||document.hidden)return;try{accept(await api('facility'));}catch{}}
 function use(name,on){if(on)store.active.add(name);else store.active.delete(name);
  if(store.active.size&&!store.timer)store.timer=setInterval(refresh,5000);else if(!store.active.size&&store.timer){clearInterval(store.timer);store.timer=null;}}
 const subscribe=fn=>{store.listeners.add(fn);return ()=>store.listeners.delete(fn);};
 async function send(body,label){const r=await api('facility/requests',body);store.pending.push({id:r.request_id,label,at:Date.now()});notice(label+' 요청했습니다.');
  for(const ms of [900,2200,4500])setTimeout(refresh,ms);}

 /* ── 화면 갱신: 기존 DOM을 고쳐 써서 전환 효과·포커스·스크롤을 지킨다 ── */
 function tween(el,from,to,dec){
  if(reduce()||!Number.isFinite(from)||from===to){el.textContent=fmt(to);return;}
  const start=performance.now(),run=now=>{const k=Math.min(1,(now-start)/600),e=1-Math.pow(1-k,3),v=from+(to-from)*e;
   el.textContent=k<1?v.toLocaleString('ko-KR',{minimumFractionDigits:0,maximumFractionDigits:dec}):fmt(to);if(k<1&&el.isConnected)requestAnimationFrame(run);};
  requestAnimationFrame(run);}
 function update(a,b){
  if(a===document.activeElement&&/^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName))return;
  if(b.hasAttribute('data-num')&&a.getAttribute('data-num')!==b.getAttribute('data-num')){
   const from=Number(a.getAttribute('data-num'));for(const at of [...b.attributes])a.setAttribute(at.name,at.value);tween(a,from,Number(b.getAttribute('data-num')),Number(b.getAttribute('data-dec')||1));return;}
  for(const at of [...a.attributes])if(!b.hasAttribute(at.name))a.removeAttribute(at.name);
  for(const at of [...b.attributes])if(a.getAttribute(at.name)!==at.value)a.setAttribute(at.name,at.value);
  if(b.hasAttribute('data-num'))return;
  patch(a,b);
  if(a.tagName==='SELECT'){const o=b.querySelector('option[selected]');if(o)a.value=o.value;}
  else if(a.tagName==='INPUT'&&a.value!==b.getAttribute('value')&&b.hasAttribute('value'))a.value=b.getAttribute('value');
 }
 function patch(a,b){
  const next=[...b.childNodes];
  next.forEach((nb,i)=>{
   let na=a.childNodes[i];
   const key=nb.nodeType===1?nb.getAttribute('data-key'):null;
   if(key&&!(na?.nodeType===1&&na.getAttribute('data-key')===key)){
    const found=[...a.children].find(c=>c.getAttribute('data-key')===key);
    if(found){a.insertBefore(found,na||null);na=found;}else{a.insertBefore(nb,na||null);return;}
   }
   if(!na){a.appendChild(nb);return;}
   if(na.nodeType!==nb.nodeType||na.nodeName!==nb.nodeName){a.replaceChild(nb,na);return;}
   if(na.nodeType!==1){if(na.nodeValue!==nb.nodeValue)na.nodeValue=nb.nodeValue;return;}
   update(na,nb);
  });
  while(a.childNodes.length>next.length)a.removeChild(a.lastChild);
 }
 function morph(node,html){const t=document.createElement(node.tagName==='DIV'||node.tagName==='SECTION'||node.tagName==='ASIDE'?'div':'div');t.innerHTML=html;patch(node,t);}

 /* ── SVG 차트(외부 라이브러리 없이) ───────────────────────── */
 // 원형 게이지: 0~1 비율, 상태 색
 function ring(frac,status,size=120,stroke=12,inner=''){
  const r=(size-stroke)/2,c=2*Math.PI*r,f=clamp(Number(frac)||0,0,1);
  return `<svg class="fc-ring" viewBox="0 0 ${size} ${size}" style="width:${size}px;height:${size}px" aria-hidden="true"><circle cx="${size/2}" cy="${size/2}" r="${r}" class="fc-track" stroke-width="${stroke}"/>`+
   `<circle cx="${size/2}" cy="${size/2}" r="${r}" class="fc-arc" data-status="${status}" stroke-width="${stroke}" stroke-dasharray="${c.toFixed(2)}" style="stroke-dashoffset:${(c*(1-f)).toFixed(2)}" transform="rotate(-90 ${size/2} ${size/2})"/>${inner}</svg>`;}
 // 반원 바늘 게이지: 구간 색 띠 + 바늘
 function needle(value,lo,hi,bands,w=220){
  const h=w*0.6,cx=w/2,cy=h-8,r=w/2-16,ang=v=>Math.PI*(1-clamp((v-lo)/(hi-lo),0,1));
  const pt=(a,rr)=>[cx+rr*Math.cos(a),cy-rr*Math.sin(a)];
  const arc=(a0,a1,cls)=>{const [x0,y0]=pt(ang(a0),r),[x1,y1]=pt(ang(a1),r);return `<path d="M${x0.toFixed(1)} ${y0.toFixed(1)}A${r} ${r} 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}" class="fc-band" data-status="${cls}" stroke-width="14"/>`;};
  const deg=(1-clamp((value-lo)/(hi-lo),0,1))*180;
  const ticks=[lo,(lo+hi)/2,hi].map(v=>{const [x,y]=pt(ang(v),r-22);return `<text x="${x.toFixed(1)}" y="${(y+5).toFixed(1)}" class="fc-tick" text-anchor="middle">${fmt(v)}</text>`;}).join('');
  return `<svg class="fc-needle" viewBox="0 0 ${w} ${h}" style="width:${w}px;height:${h}px" aria-hidden="true">${bands.map(([a,b,s])=>arc(a,b,s)).join('')}${ticks}`+
   `<g class="fc-needle-hand" style="transform:rotate(${(90-deg).toFixed(1)}deg);transform-origin:${cx}px ${cy}px"><path d="M${cx-4} ${cy}L${cx} ${cy-r+6}L${cx+4} ${cy}Z"/></g><circle cx="${cx}" cy="${cy}" r="8" class="fc-hub"/></svg>`;}
 // 온도계: 15~40°C, 권고 상한·임계선
 function thermo(t,h=150){
  const lo=15,hi=40,y=v=>10+(h-40)*(1-clamp((v-lo)/(hi-lo),0,1)),s=tempStatus(t);
  return `<svg class="fc-thermo" viewBox="0 0 70 ${h}" style="width:70px;height:${h}px" aria-hidden="true"><rect x="20" y="8" width="16" height="${h-36}" rx="8" class="fc-track-fill"/>`+
   `<rect x="23" y="${y(t).toFixed(1)}" width="10" height="${(h-30-y(t)).toFixed(1)}" rx="5" class="fc-fill" data-status="${s}"/><circle cx="28" cy="${h-18}" r="13" class="fc-fill" data-status="${s}"/>`+
   [[TEMP.advise,'warning'],[TEMP.critical,'critical']].map(([v,c])=>`<line x1="14" x2="42" y1="${y(v)}" y2="${y(v)}" class="fc-limit" data-status="${c}"/><text x="46" y="${y(v)+5}" class="fc-tick">${v}°</text>`).join('')+`</svg>`;}
 // 배터리: 충전량 채움
 function battery(pct,status,w=120){const f=clamp((pct||0)/100,0,1),iw=w-26;
  return `<svg class="fc-battery" viewBox="0 0 ${w} 56" style="width:${w}px;height:56px" aria-hidden="true"><rect x="3" y="6" width="${w-18}" height="44" rx="8" class="fc-outline"/><rect x="${w-14}" y="19" width="8" height="18" rx="3" class="fc-outline-fill"/>`+
   `<rect x="9" y="12" width="${(iw*f).toFixed(1)}" height="32" rx="4" class="fc-fill" data-status="${status}" style="transition:width .6s"/></svg>`;}
 // 도넛: [{value,status,label}]
 function donut(parts,size=130,inner=''){
  const r=size/2-12,c=2*Math.PI*r,total=parts.reduce((n,p)=>n+p.value,0);let off=0;
  const segs=total?parts.filter(p=>p.value>0).map(p=>{const len=c*p.value/total,gap=parts.filter(x=>x.value>0).length>1?3:0;const s=`<circle cx="${size/2}" cy="${size/2}" r="${r}" class="fc-arc" data-status="${p.status}" stroke-width="18" stroke-dasharray="${Math.max(0,len-gap).toFixed(2)} ${(c-len+gap).toFixed(2)}" style="stroke-dashoffset:${(-off).toFixed(2)}" transform="rotate(-90 ${size/2} ${size/2})"/>`;off+=len;return s;}).join(''):'';
  return `<svg class="fc-donut" viewBox="0 0 ${size} ${size}" style="width:${size}px;height:${size}px" aria-hidden="true"><circle cx="${size/2}" cy="${size/2}" r="${r}" class="fc-track" stroke-width="18"/>${segs}${inner}</svg>`;}
 // 막대(0~100%), 선택적 기준선
 function bar(pct,status,mark){return `<span class="fc-bar"><span class="fc-bar-fill" data-status="${status}" style="width:${clamp(pct||0,0,100).toFixed(1)}%"></span>${mark!=null?`<span class="fc-bar-mark" style="left:${clamp(mark,0,100)}%"></span>`:''}</span>`;}
 // 스파크라인
 function spark(values,{w=220,h=48,line,lo,hi,status='normal'}={}){
  const v=values.filter(Number.isFinite);if(v.length<2)return `<span class="fc-spark-empty">추이를 모으는 중</span>`;
  let a=lo??Math.min(...v,line??Infinity),b=hi??Math.max(...v,line??-Infinity);if(b-a<1e-6){a-=1;b+=1;}
  const x=i=>4+(w-8)*i/(values.length-1),y=val=>h-4-(h-8)*(val-a)/(b-a);
  const d=values.map((val,i)=>Number.isFinite(val)?`${i&&Number.isFinite(values[i-1])?'L':'M'}${x(i).toFixed(1)} ${y(val).toFixed(1)}`:'').join('');
  return `<svg class="fc-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="height:${h}px" aria-hidden="true">${line!=null?`<line x1="0" x2="${w}" y1="${y(line).toFixed(1)}" y2="${y(line).toFixed(1)}" class="fc-limit" data-status="critical"/>`:''}<path d="${d}" class="fc-line" data-status="${status}"/><circle cx="${x(values.length-1).toFixed(1)}" cy="${y(v.at(-1)).toFixed(1)}" r="4" class="fc-dot" data-status="${status}"/></svg>`;}

 /* ── 조치 설명(무엇을 하는 조치인지만, 언제 써야 하는지는 쓰지 않는다) ── */
 const OP_NOTE={manual_transfer:'ATS를 손으로 다른 전원 쪽으로 넘깁니다.',start_generator:'비상 발전기를 수동으로 기동합니다.',isolate_fuel:'연료 배관 밸브를 잠가 새는 구간을 막습니다.',refuel:'연료 탱크를 다시 채웁니다.',
  isolate_battery:'배터리 스트링을 UPS에서 떼어 냅니다.',replace_battery:'UPS 배터리를 새것으로 바꿉니다.',ups_online:'바이패스 중인 UPS를 정상 운전으로 되돌립니다.',rebalance_load:'부하 일부를 다른 회로로 옮깁니다.',
  reset_breaker:'떨어진 랙 차단기를 다시 올립니다.',restore_feed:'끊긴 A계통 전원을 복구합니다.',start_standby:'대기 중인 예비 설비를 돌립니다.',stop_standby:'돌던 예비 설비를 대기로 돌립니다.',
  repair_equipment:'멈춘 설비를 현장에서 수리합니다.',replace_filter:'항온항습기 필터를 새것으로 바꿉니다.',recalibrate_sensor:'온도 센서를 기준기로 다시 맞춥니다.',clean_hx:'열교환기 판을 세척합니다.',
  release_damper:'프리쿨링 전환 밸브를 손으로 풉니다.',close_containment:'열린 열복도 차폐를 닫습니다.',clear_airflow:'타공 타일 주변을 정리해 바닥 기류를 살립니다.',install_blanking:'랙의 빈 칸에 블랭킹 패널을 끼웁니다.',
  isolate_leak:'새는 구간 앞뒤 밸브를 잠급니다.',service_humidifier:'가습·제습기를 점검합니다.',confirm_alarm:'현장을 확인한 뒤 수신반 경보를 복구합니다.',secure_door:'출입문 상태를 확인하고 잠급니다.',
  restore_cctv:'CCTV 영상 신호를 복구합니다.',power_cap:'GPU가 쓸 수 있는 전력의 상한을 정합니다.',power_smoothing:'학습 작업의 전력 급변을 완만하게 합니다.',checkpoint_now:'학습 상태를 지금 저장합니다.',
  restart_job:'학습 작업을 다시 시작합니다.',drain_node:'이 노드에 새 작업이 배정되지 않게 합니다.',undrain_node:'제외했던 노드를 다시 작업에 넣습니다.',reset_node:'노드의 GPU를 리셋합니다.',
  run_diag:'노드를 정밀 진단합니다.',replace_gpu:'GPU 모듈을 교체합니다.',replace_psu:'노드 전원 공급기를 교체합니다.',scale_out:'이 노드에 추론 복제본을 하나 더 띄웁니다.',scale_in:'이 노드의 추론 복제본을 내립니다.',
  restore_old_checkpoint:'학습을 이전 체크포인트로 되돌립니다.',restart_service:'추론 서버를 다시 시작합니다.',rollback_service:'추론 서버를 이전 버전으로 되돌립니다.',rate_limit:'추론 요청 제한을 켜거나 끕니다.',
  port_disable:'이 링크의 스위치 포트를 닫습니다.',port_enable:'닫힌 스위치 포트를 엽니다.',replace_optic:'광모듈과 케이블을 바꿉니다.',reset_nic:'노드 네트워크 카드를 리셋합니다.',rollback_config:'스위치 설정을 이전 상태로 되돌립니다.',
  replace_switch:'스위치를 예비품으로 교체합니다.',purge_checkpoints:'오래된 체크포인트 파일을 지웁니다.',cleanup_small_files:'작은 임시 파일을 정리합니다.',stagger_ckpt:'노드마다 체크포인트를 쓰는 시각을 엇갈리게 합니다.',replace_disk:'고장 디스크를 바꾸고 배열을 재구성합니다.'};
 const opsFor=(s,target)=>(s?.catalog.operations||[]).filter(o=>o.targets.some(t=>t.id===target));
 const targetTitle=(s,target)=>{for(const o of s?.catalog.operations||[]){const t=o.targets.find(x=>x.id===target);if(t)return t.title;}return target;};

 /* ── 인스펙터(설비 하나: 게이지·추이·가능한 조치·관련 경보) ── */
 const ui={op:null,value:{}};
 function readout(a,m){
  const key=a.id+'.'+m.key,v=m.value;
  let vis='';
  if(typeof v==='number'&&m.unit==='%')vis=bar(v,m.key==='fouling_pct'||m.key==='capacity_pct'||m.key==='inode_pct'||m.key==='mem_pct'||m.key==='load_pct'?(v>90?'critical':v>75?'warning':'normal'):'normal');
  else if(typeof v==='number'&&m.unit==='°C')vis=bar((v-15)/25*100,tempStatus(v),(TEMP.advise-15)/25*100);
  return `<div class="fc-readout" data-metric="${esc2(key)}" data-key="${esc2(key)}"><span class="fc-label">${esc2(m.label)}</span><strong>${num(v,m.unit)}</strong>${vis}</div>`;}
 function opCard(s,o,target,can){
  const open=ui.op&&ui.op.op===o.id&&ui.op.target===target,key=o.id+'@'+target;
  const busy=(s.work||[]).find(w=>w.op===o.id&&w.target===target);
  const val=o.value?(ui.value[key]??o.value.default):null;
  return `<div class="fc-op ${open?'open':''}" data-key="op-${esc2(key)}"><button class="fc-op-head" data-op="${esc2(o.id)}" data-target="${esc2(target)}" aria-expanded="${open}" ${can?'':'disabled'}>${ic(SYSTEM_ICON[o.system]||'wrench')}<span class="fc-op-title">${esc2(o.title)}</span><span class="fc-op-time">${ic('clock')}${o.minutes?'약 '+o.minutes+'분':'바로'}</span></button>`+
   (open?`<div class="fc-op-body"><p>${esc2(OP_NOTE[o.id]||'')}</p>${o.needs_drain?`<p class="fc-op-warn">${ic('alert')}먼저 이 노드를 작업에서 제외(drain)해야 합니다.</p>`:''}`+
    (o.value?`<label class="fc-slider">값 <output>${esc2(String(val))} ${esc2(o.value.unit)}</output><input type="range" data-op-value="${esc2(key)}" min="${o.value.min}" max="${o.value.max}" step="1" value="${esc2(String(val))}"></label>`:'')+
    `<p class="fc-op-meta">${o.minutes?`완료까지 약 ${o.minutes}분(시뮬레이션 시간). 진행 상황은 아래 '진행 중인 작업'에 나옵니다.`:'누르는 즉시 적용됩니다.'}</p>`+
    `<button class="fc-btn primary" data-action="operate" data-op="${esc2(o.id)}" data-target="${esc2(target)}" ${busy?'disabled':''}>${ic('wrench')}${busy?'진행 중':'조치 실행'}</button></div>`:'')+`</div>`;}
 function workRows(s,filter){const list=(s.work||[]).filter(filter||(()=>true));if(!list.length)return '';
  return list.map(w=>{const o=(s.catalog.operations||[]).find(x=>x.id===w.op),total=Math.max(o?.minutes||1,w.minutes_left,0.1),done=clamp(1-w.minutes_left/total,0,1);
   return `<div class="fc-work" data-key="work-${esc2(w.op+'@'+w.target)}"><div class="fc-work-head">${ic('wrench')}<strong>${esc2(w.title)}</strong><span>${esc2(w.target_title)}</span></div>${bar(done*100,'normal')}<small>남은 시간 ${num(w.minutes_left,'분')} · 시뮬레이션 시간</small></div>`;}).join('');}
 function alarmRows(list,{link=true}={}){if(!list.length)return '<p class="fc-empty">관련 경보가 없습니다.</p>';const s=store.data?.state;
  return `<ul class="fc-alarms">${list.map(a=>`<li data-key="al-${esc2(a.id)}" data-status="${a.level}">${pill(a.level)}<span class="fc-alarm-msg">${esc2(a.message)}</span>${link&&a.asset_id?`<button class="fc-link" data-asset="${esc2(a.asset_id)}">${esc2(assetOf(s,a.asset_id)?.title||a.asset_id)}</button>`:''}<time title="${esc2(date(a.since))}">${ago(a.since)}</time></li>`).join('')}</ul>`;}
 function permissionNote(d){return d.read_only?`<p class="fc-note">${ic('lock')}라이선스가 만료되어 조회만 할 수 있습니다.</p>`:`<p class="fc-note">${ic('lock')}운영자 이상의 계정으로 조치할 수 있습니다.</p>`;}
 function opsSection(d,targets){const s=d.state,can=d.can_operate,rows=targets.flatMap(t=>opsFor(s,t).map(o=>[o,t]));
  if(!rows.length)return '<p class="fc-empty">이 설비에 할 수 있는 조치가 없습니다.</p>';
  return (can?'':permissionNote(d))+`<div class="fc-ops">${rows.map(([o,t])=>opCard(s,o,t,can)).join('')}</div>`;}
 // 계통 그림에서 이 설비와 바로 이어진 설비(위쪽·아래쪽)
 function neighbours(s,id){
  const up=[],down=[];for(const e of EDGES){if(e[2]==='air')continue;if(e[1]===id&&!up.includes(e[0]))up.push(e[0]);if(e[0]===id&&!down.includes(e[1]))down.push(e[1]);}
  const chip=x=>{const a=assetOf(s,x);return a?`<button class="fc-mini" data-asset="${esc2(x)}" data-status="${a.status}">${ic(kindIcon(x))}${esc2(a.title||x)}</button>`:'';};
  if(!up.length&&!down.length)return '';
  return `<section class="fc-insp-sec"><h4>${ic('link')}연결된 설비</h4>${up.length?`<div class="fc-net-row"><span class="fc-label">받는 쪽(위)</span>${up.map(chip).join('')}</div>`:''}${down.length?`<div class="fc-net-row"><span class="fc-label">보내는 쪽(아래)</span>${down.map(chip).join('')}</div>`:''}</section>`;}
 function inspector(sel,{catalog=null,close=true}={}){
  const d=store.data,s=d?.state;if(!s||!sel)return '';
  const head=(iconName,title,status,sub)=>`<header class="fc-insp-head"><span class="fc-insp-icon" data-status="${status}">${ic(iconName)}</span><div><h3>${esc2(title)}</h3><span class="fc-insp-sub">${sub}</span></div>${close?`<button class="fc-icon-btn" data-action="inspector-close" aria-label="닫기">${ic('x')}</button>`:''}</header>`;
  let body='';
  if(sel.kind==='asset'){
   const a=assetOf(s,sel.id);if(!a)return '';
   const p=primary(a),series=store.hist.map(h=>h.a?.[a.id]);
   const alarms=s.alarms.filter(x=>x.asset_id===a.id);
   body=head(kindIcon(a.id),a.title||catalog?.name||a.id,a.status,`${pill(a.status)}<code>${esc2(a.id)}</code>${floorOf(a.id)?`<span>${esc2(floorOf(a.id))}</span>`:''}`)+
    (alarms.length?`<section class="fc-insp-sec" data-status="${alarms.some(x=>x.level==='critical')?'critical':'warning'}"><h4>${ic('bell')}경보 ${alarms.length}건</h4>${alarmRows(alarms,{link:false})}</section>`:'')+
    `<section class="fc-insp-sec"><h4>${ic('gauge')}측정값</h4><div class="fc-readouts">${a.metrics.map(m=>readout(a,m)).join('')}</div>`+
    (p&&typeof p.value==='number'?`<div class="fc-insp-trend"><span class="fc-label">${esc2(p.label)} 추이</span>${spark(series.slice(-120),{w:400,h:64,status:a.status==='off'?'off':a.status})}</div>`:'')+`</section>`+
    neighbours(s,a.id)+
    `<section class="fc-insp-sec" data-panel="work">${(s.work||[]).some(w=>w.target===a.id)?`<h4>${ic('clock')}진행 중인 작업</h4>${workRows(s,w=>w.target===a.id)}`:''}</section>`+
    `<section class="fc-insp-sec"><h4>${ic('wrench')}할 수 있는 조치</h4>${opsSection(d,[a.id])}</section>`;
  }else if(sel.kind==='floor'){
   const f=sel.id,aisles=s.aisles.filter(x=>x.floor===f),alarms=s.alarms.filter(x=>x.asset_id?floorOf(x.asset_id)===f:aisles.some(y=>x.id.endsWith('.aisle-'+y.id.toLowerCase())));
   const worst=[...aisles.map(x=>x.status),...alarms.map(x=>x.level)].sort((x,y)=>RANK[y]-RANK[x])[0]||'normal';
   body=head('layers',targetTitle(s,f),worst,`${pill(worst)}<code>${esc2(f)}</code>`)+
    aisles.map(x=>`<section class="fc-insp-sec"><h4>${ic('therm')}${esc2(x.floor)} ${esc2(x.id)}열 구역</h4><div class="fc-readouts"><div class="fc-readout" data-metric="aisle-${esc2(x.id)}.temp_c"><span class="fc-label">구역 온도</span><strong>${num(x.temp_c,'°C')}</strong>${bar((x.temp_c-15)/25*100,tempStatus(x.temp_c),(TEMP.advise-15)/25*100)}</div>${(x.metrics||[]).map(m=>readout({id:'aisle-'+x.id},m)).join('')}</div></section>`).join('')+
    `<section class="fc-insp-sec"><h4>${ic('bell')}이 층의 경보 ${alarms.length}건</h4>${alarmRows(alarms)}</section>`+
    `<section class="fc-insp-sec" data-panel="work">${(s.work||[]).some(w=>w.target===f)?`<h4>${ic('clock')}진행 중인 작업</h4>${workRows(s,w=>w.target===f)}`:''}</section>`+
    `<section class="fc-insp-sec"><h4>${ic('wrench')}층 단위 조치</h4>${opsSection(d,[f])}</section>`;
  }else if(sel.kind==='cluster'){
   const keys=['job_state','tokens_per_s','goodput_pct','infer_p99_ms','power_cap_pct','work_in_progress'];
   body=head('chip','GPU 클러스터 전체','normal','<code>cluster</code>')+`<section class="fc-insp-sec"><h4>${ic('gauge')}클러스터 요약</h4><div class="fc-readouts">${keys.map(k=>metricOf(s,k)).filter(Boolean).map(m=>readout({id:'cluster'},m)).join('')}</div></section>`+
    `<section class="fc-insp-sec"><h4>${ic('wrench')}클러스터 조치</h4>${opsSection(d,['cluster'])}</section>`;
  }
  if(catalog)body+=`<details class="fc-insp-sec fc-catalog"><summary>${ic('info')}설비 설명 · 기준값</summary><p>${esc2(catalog.role)}</p><dl><div><dt>배치</dt><dd>${esc2(catalog.placement)}</dd></div><div><dt>장애 영향</dt><dd>${esc2(catalog.impact)}</dd></div></dl>`+
   `<h5>점검 항목</h5><ul>${(catalog.checks||[]).map(c=>`<li>${esc2(c)}</li>`).join('')}</ul><h5>기준값</h5><dl>${(catalog.baseline||[]).map(b=>`<div><dt>${esc2(b.label)}</dt><dd>${esc2(String(b.value))}</dd></div>`).join('')}</dl></details>`;
  return `<div class="fc-insp" data-panel="operate" data-inspect="${esc2(sel.kind+':'+sel.id)}">${body}</div>`;
 }

 /* ── 계통 연결(지도와 계통 그림이 함께 쓴다) ─────────────────── */
 const st=(s,id,key)=>mval(assetOf(s,id),key);
 const crit=(s,id)=>assetOf(s,id)?.status==='critical';
 const running=(s,id)=>st(s,id,'state')==='운전';
 // [출발, 도착, 계통, 상태 함수] 상태: flow(흐름) · idle(대기) · broken(끊김) · dead(전기·물 없음)
 const powered=s=>!String(metricOf(s,'power_source')?.value||'').startsWith('없음');
 const EDGES=[
  ['utility-01','sub-01','power',s=>st(s,'utility-01','supply')==='정상'?'flow':'broken'],
  ['sub-01','swgr-01','power',s=>st(s,'sub-01','state')==='정상'?'flow':crit(s,'sub-01')?'broken':'dead'],
  ['swgr-01','tr-01','power',s=>st(s,'swgr-01','energized')===true?'flow':'dead'],
  ['tr-01','ats-01','power',s=>st(s,'tr-01','state')==='정상'?'flow':crit(s,'tr-01')?'broken':'dead'],
  ['tank-fuel-01','gen-01','power',s=>running(s,'gen-01')?'flow':'idle'],
  ['gen-01','ats-01','power',s=>running(s,'gen-01')?'flow':crit(s,'gen-01')?'broken':'idle'],
  ['ats-01','ups-01','power',s=>st(s,'ats-01','source')!=='없음'?'flow':crit(s,'ats-01')?'broken':'dead'],
  ['batt-01','ups-01','power',s=>st(s,'batt-01','connected')===false?'broken':st(s,'ups-01','mode')==='배터리 운전'?'flow':'idle'],
  ['batt-02','ups-01','power',s=>st(s,'batt-02','connected')===false?'broken':st(s,'ups-01','mode')==='배터리 운전'?'flow':'idle'],
  ['ups-01','bus-2f-a','power',s=>powered(s)?'flow':'broken'],['ups-01','bus-3f-b','power',s=>powered(s)?'flow':'broken'],['ups-01','pdu-04','power',s=>powered(s)?'flow':'broken'],
  ['bus-2f-a','pdu-01','power',s=>powered(s)?'flow':'dead'],['bus-2f-a','pdu-02','power',s=>powered(s)?'flow':'dead'],['bus-3f-b','pdu-03','power',s=>powered(s)?'flow':'dead'],
  ...[['pdu-01','rack-r-2f-01'],['pdu-02','rack-r-2f-02'],['pdu-03','rack-r-3f-01'],['pdu-04','rack-r-4f-01']].map(([p,r])=>[p,r,'power',s=>st(s,p,'breaker')!=='투입'?'broken':st(s,r,'powered')===false?'broken':powered(s)?'flow':'dead']),
  ['wx-01','ct-01','air',()=>'idle'],['wx-01','ct-02','air',()=>'idle'],
  ['ct-01','pump-cw-01','condenser',s=>crit(s,'ct-01')?'broken':running(s,'ct-01')?'flow':'dead'],['ct-02','pump-cw-01','condenser',s=>crit(s,'ct-02')?'broken':running(s,'ct-02')?'flow':'dead'],
  ...['chiller-01','hx-01','eco-01'].map(id=>['pump-cw-01',id,'condenser',s=>crit(s,'pump-cw-01')?'broken':!running(s,'pump-cw-01')?'dead':id==='chiller-01'?(crit(s,id)?'broken':running(s,id)?'flow':'idle'):id==='eco-01'?(st(s,'eco-01','free_cooling')?'flow':'idle'):'flow']),
  ...['chiller-01','hx-01','eco-01'].flatMap(id=>['pump-pcw-01','pump-pcw-02'].map(p=>[id,p,'chilled',s=>crit(s,p)?'broken':running(s,p)?(id==='chiller-01'&&!running(s,id)?'idle':id==='eco-01'&&!st(s,'eco-01','free_cooling')?'idle':'flow'):'idle'])),
  ['tank-water-01','pump-pcw-01','chilled',s=>(st(s,'tank-water-01','buffer_pct')??100)<99?'flow':'idle'],
  ...['crac-01','crac-02','fcu-3f-01','crac-03','cdu-01'].flatMap(id=>['pump-pcw-01','pump-pcw-02'].map(p=>[p,id,'chilled',s=>crit(s,p)?'broken':running(s,p)?(crit(s,id)?'broken':'flow'):'idle'])),
  ['cdu-01','cp-dgx-01','chilled',s=>(st(s,'cdu-01','flow_pct')??100)<50?'broken':'flow']];
 const edgeState=(e,s)=>{try{return e[3](s)||'dead';}catch{return 'dead';}};

 /* ── 훈련 배너·갤러리 ──────────────────────────────────── */
 const COURSES={fac:['시설 운영','layers'],ai:['GPU 클러스터 운영','chip']};
 const stars=n=>`<span class="fc-stars" aria-label="난이도 ${n}/5">${[1,2,3,4,5].map(i=>`<svg class="fc-ic ${i<=n?'on':''}" viewBox="0 0 24 24"><path d="${P.star}"/></svg>`).join('')}</span>`;
 const scales=[1,2,3,5,10,30,60,120];
 function scaleSelect(s,can){if(!can)return `<span class="fc-chip">${ic('scale')}${esc2(String(s.time_scale))}배속</span>`;const v=Number(s.time_scale);
  return `<label class="fc-scale">${ic('scale')}<span>시간 배속</span><select id="facility-scale" data-action="time-scale">${scales.map(x=>`<option value="${x}" ${v===x?'selected':''}>${x}배</option>`).join('')}${scales.includes(v)?'':`<option selected value="${esc2(String(v))}">${esc2(String(v))}배</option>`}</select></label>`;}
 function classDrill(s){const hidden=s.faults.filter(f=>f.fault==='hidden');if(!hidden.length)return null;
  return {until:hidden.map(f=>f.expires_at).sort().at(-1),by:hidden[0].requested_by};}
 function banner(d,{scale=true,full=true,live=true,done=true}={}){
  const s=d.state,dr=s.drill,cd=live?classDrill(s):null;let out='';
  if(cd)out+=`<div class="fc-banner" data-kind="class" data-panel="drill" data-drill-kind="class">${ic('flag')}<div class="fc-banner-main"><span class="fc-banner-kicker">강사 진행 훈련 · 반 전체</span><strong>강사가 반 전체에 장애를 냈습니다</strong><span>원인은 공개되지 않습니다. 경보와 계통 그림에서 증상을 찾아 대응하세요. 자동 종료까지 ${left(cd.until)}</span></div></div>`;
  if(live&&dr&&dr.status==='running'){const pct=clamp((dr.elapsed_min||0)/dr.minutes*100,0,100);
   out+=`<div class="fc-banner" data-kind="drill" data-panel="drill" data-drill-kind="scenario" data-drill="${esc2(dr.id)}">${ic('flag')}<div class="fc-banner-main"><span class="fc-banner-kicker">시나리오 훈련 진행 중</span><strong>${esc2(dr.title)}</strong>`+
    `<div class="fc-progress">${bar(pct,'normal')}<span>${num(dr.elapsed_min??0)} / ${dr.minutes}분 <small>시뮬레이션 시간</small></span></div></div>`+
    `<div class="fc-banner-tools">${full?`<button class="fc-btn ghost" data-action="drill-brief" data-drill="${esc2(dr.id)}">${ic('info')}브리핑</button>`:''}${scale?scaleSelect(s,d.can_operate):''}${d.can_operate?`<button class="fc-btn danger" data-action="drill-stop" data-facility="drill_stop">${ic('stop')}${Date.now()-(ui.stopArm||0)<5000?'한 번 더 눌러 중지':'훈련 중지'}</button>`:''}</div></div>`;}
  else if(done&&dr&&dr.status!=='running'&&full&&!ui.dismissed?.[dr.started_at])out+=`<div class="fc-banner" data-kind="done" data-panel="drill" data-drill-kind="scenario">${ic('check')}<div class="fc-banner-main"><span class="fc-banner-kicker">지난 시나리오 훈련</span><strong>${esc2(dr.title)}</strong><span>${dr.status==='finished'?'시간 종료':'중지'}${dr.ended_at?' · '+esc2(date(dr.ended_at)):''} · 해결하지 못한 장애 ${esc2(String(dr.open_faults))}건</span></div><button class="fc-icon-btn" data-action="drill-dismiss" data-started="${esc2(dr.started_at)}" aria-label="닫기">${ic('x')}</button></div>`;
  return out;}
 function gallery(d){
  const s=d.state,list=s.catalog.drills||[],g=ui.gallery||(ui.gallery={course:'fac',level:0,pick:null});
  const running=s.drill?.status==='running';
  const courses=[...new Set(list.map(x=>COURSES[x.course]?x.course:'etc'))];if(!courses.includes(g.course))g.course=courses[0];
  const pick=list.find(x=>x.id===g.pick);
  if(pick){const [cname,cicon]=COURSES[pick.course]||['기타','flag'];
   return `<div class="fc-brief" data-drill="${esc2(pick.id)}"><button class="fc-link" data-action="gallery-back">← 훈련 목록</button><span class="fc-brief-course">${ic(cicon)}${esc2(cname)}</span><h2>${esc2(pick.title)}</h2>`+
    `<div class="fc-brief-meta">${stars(pick.level)}<span>${ic('clock')}${pick.minutes}분 <small>시뮬레이션 시간</small></span><span>${ic('scale')}${esc2(String(pick.time_scale))}배속으로 진행</span></div>`+
    `<section><h4>상황</h4><p class="fc-brief-text">${esc2(pick.brief||'—')}</p></section>`+
    `<section><h4>이렇게 진행됩니다</h4><ol class="fc-steps"><li><b>1</b><span>시작하면 시뮬레이터가 시나리오 시간표대로 장애를 냅니다. 어떤 장애인지는 화면에 나오지 않습니다.</span></li><li><b>2</b><span>경보, 계통 그림, 관제 지도에서 증상을 찾고 설비를 눌러 상태를 확인합니다.</span></li><li><b>3</b><span>설비에서 조치를 실행하고, 수치가 정상으로 돌아오는지 추이 그래프로 확인합니다.</span></li></ol></section>`+
    `<footer>${!d.can_operate?permissionNote(d):running?`<p class="fc-note">${ic('info')}이미 진행 중인 훈련이 있습니다. 끝내거나 중지한 뒤 시작할 수 있습니다.</p>`:''}<button class="fc-btn primary big" data-action="drill-start" data-facility="drill_start" data-drill="${esc2(pick.id)}" ${d.can_operate&&!running?'':'disabled'}>${ic('play')}훈련 시작</button></footer></div>`;}
  const shown=list.filter(x=>(COURSES[x.course]?x.course:'etc')===g.course&&(!g.level||x.level===g.level));
  return `<div class="fc-gallery-tools"><div class="fc-tabs" role="tablist">${courses.map(c=>`<button role="tab" data-action="gallery-course" data-course="${c}" aria-selected="${g.course===c}">${ic((COURSES[c]||['','flag'])[1])}${esc2((COURSES[c]||['기타'])[0])}<span class="fc-count">${list.filter(x=>(COURSES[x.course]?x.course:'etc')===c).length}</span></button>`).join('')}</div>`+
   `<div class="fc-chips">${[0,1,2,3,4,5].map(n=>`<button class="fc-chip-btn" data-action="gallery-level" data-level="${n}" aria-pressed="${g.level===n}">${n?'난이도 '+n:'전체 난이도'}</button>`).join('')}</div></div>`+
   `<div class="fc-cards">${shown.map(x=>`<button class="fc-card" data-drill="${esc2(x.id)}" data-action="gallery-pick" data-key="dr-${esc2(x.id)}">${running&&s.drill.id===x.id?'<span class="fc-card-live">진행 중</span>':''}<span class="fc-card-top">${ic((COURSES[x.course]||['','flag'])[1])}${stars(x.level)}</span><strong>${esc2(x.title)}</strong><p>${esc2(x.brief)}</p><span class="fc-card-meta">${ic('clock')}${x.minutes}분 · ${esc2(String(x.time_scale))}배속</span></button>`).join('')||'<p class="fc-empty">조건에 맞는 훈련이 없습니다.</p>'}</div>`;}
 function openGallery(pick){
  let dlg=$('fc-gallery');
  if(!dlg){dlg=document.createElement('dialog');dlg.id='fc-gallery';dlg.className='fc-dialog';dlg.setAttribute('data-panel','drill');dlg.setAttribute('aria-label','시나리오 훈련');
   dlg.innerHTML=`<header class="fc-dialog-head"><div><span class="fc-kicker">SCENARIO TRAINING</span><h2>${ic('flag')}시나리오 훈련</h2><p>훈련을 고르면 상황 설명을 보고 시작할 수 있습니다. 시작하면 장애 이름은 보이지 않고 증상만 나타납니다.</p></div><button class="fc-icon-btn" data-action="gallery-close" aria-label="닫기">${ic('x')}</button></header><div class="fc-dialog-body" id="fc-gallery-body"></div>`;
   document.body.append(dlg);dlg.addEventListener('close',()=>{if(ui.gallery)ui.gallery.pick=null;});}
  (ui.gallery||(ui.gallery={course:'fac',level:0,pick:null})).pick=pick||null;
  const p=(store.data?.state?.catalog.drills||[]).find(x=>x.id===pick);if(p)ui.gallery.course=COURSES[p.course]?p.course:'etc';
  drawGallery();if(!dlg.open)dlg.showModal();}
 function drawGallery(){const body=$('fc-gallery-body');if(body&&store.data?.state)morph(body,gallery(store.data));}

 /* ── SIEM 연결: 시설 사건(C1 xoc-facility, 규칙 그룹 facility)을 Discover로 ── */
 function siemURL(from){const t=new Date(from||Date.now()-3600e3).toISOString();
  return `/siem/app/data-explorer/discover#?_a=(discover:(columns:!(rule.description,data.facility.kind,data.facility.message),isDirty:!f,sort:!()),metadata:(indexPattern:'wazuh-alerts-*',view:discover))`+
   `&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'${t}',to:now))&_q=(filters:!(),query:(language:kuery,query:'rule.groups:facility'))`;}

 /* ── 공용 클릭·변경 처리 ───────────────────────────────── */
 const rerender=new Set();const redraw=()=>{for(const fn of rerender)fn();drawGallery();};
 document.addEventListener('click',e=>{
  const t=e.target.closest('[data-action],[data-op]');if(!t||!store.data?.state)return;
  const s=store.data.state,a=t.dataset.action;
  if(t.matches('.fc-op-head')){const k={op:t.dataset.op,target:t.dataset.target};ui.op=ui.op&&ui.op.op===k.op&&ui.op.target===k.target?null:k;redraw();return;}
  if(a==='operate'){const o=(s.catalog.operations||[]).find(x=>x.id===t.dataset.op);if(!o)return;const body={action:'operate',op:o.id,target:t.dataset.target};
   if(o.value){const v=Number(ui.value[o.id+'@'+t.dataset.target]??o.value.default);if(!(v>=o.value.min&&v<=o.value.max)){notice(`값은 ${o.value.min}~${o.value.max} 사이로 정해 주세요.`,true);return;}body.value=v;}
   ui.op=null;act(()=>send(body,'조치('+o.title+')를'));redraw();return;}
  if(a==='drill-open'){openGallery(null);return;}
  if(a==='drill-brief'){openGallery(t.dataset.drill);return;}
  if(a==='gallery-close'){$('fc-gallery')?.close();return;}
  if(a==='gallery-back'){ui.gallery.pick=null;drawGallery();return;}
  if(a==='gallery-pick'){ui.gallery.pick=t.dataset.drill;drawGallery();$('fc-gallery-body').scrollTop=0;return;}
  if(a==='gallery-course'){ui.gallery.course=t.dataset.course;ui.gallery.level=0;drawGallery();return;}
  if(a==='gallery-level'){ui.gallery.level=Number(t.dataset.level);drawGallery();return;}
  if(a==='drill-start'){const x=(s.catalog.drills||[]).find(y=>y.id===t.dataset.drill);if(x){$('fc-gallery')?.close();act(()=>send({action:'drill_start',drill:x.id},'훈련('+x.title+') 시작을'));}return;}
  if(a==='drill-stop'){   // 한 번 더 눌러야 중지한다(잘못 누름 방지, 브라우저 확인 창은 쓰지 않는다)
   if(Date.now()-(ui.stopArm||0)<5000){ui.stopArm=0;act(()=>send({action:'drill_stop'},'훈련 중지를'));}
   else{ui.stopArm=Date.now();notice('한 번 더 누르면 훈련을 중지합니다. 훈련이 낸 장애도 함께 정리됩니다.');setTimeout(redraw,5100);}
   redraw();return;}
  if(a==='drill-dismiss'){(ui.dismissed||(ui.dismissed={}))[t.dataset.started]=true;redraw();return;}
 });
 document.addEventListener('input',e=>{const r=e.target.closest('[data-op-value]');if(r){ui.value[r.dataset.opValue]=Number(r.value);const o=r.closest('.fc-slider')?.querySelector('output');if(o)o.textContent=r.value+' '+(o.textContent.split(' ').slice(1).join(' '));}});
 document.addEventListener('change',e=>{if(e.target.id==='facility-scale'&&store.data?.state)act(()=>send({action:'time_scale',value:Number(e.target.value)},'시간 배속 변경을'));});
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&ui.op){ui.op=null;redraw();}});

 return {store,use,subscribe,refresh,accept,send,morph,ic,pill,num,fmt,bar,ring,needle,thermo,battery,donut,spark,primary,kindIcon,systemOf,floorOf,SYSTEMS,SYSTEM_ICON,
  STATUS,COLOR,RANK,SERIES,TEMP,tempStatus,metricOf,assetOf,mval,inspector,alarmRows,workRows,banner,openGallery,scaleSelect,classDrill,EDGES,edgeState,siemURL,simAt,
  ago,left,clock,clamp,ui,onRedraw:fn=>rerender.add(fn),targetTitle,opsFor,permissionNote};
})();
