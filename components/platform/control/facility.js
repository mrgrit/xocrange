'use strict';
// DCOC screen for the installed facility module (ADR 0014). Core shows the state the module
// reports and hands it requests; it does not simulate and holds no fault logic.
const Facility=(()=>{
 let data=null,timer=null,form={fault:'',target:'',minutes:''},pending=[],touched=0;
 const systems={power:'전력',cooling:'냉방',fire:'소방',security:'출입·보안'};
 const statusNames={normal:'정상',warning:'주의',critical:'위험',off:'정지'};
 const statusClass={normal:'allow',warning:'detect',critical:'deny',off:'off'};
 const reasons={not_installed:['시설 모듈이 설치되지 않았습니다','실시간 설비 상태와 장애 실습은 Live Fire의 시설 모듈이 제공합니다.'],
  absent:['시설 시뮬레이터가 아직 상태를 보내지 않았습니다','모듈이 시작되는 중일 수 있습니다. 잠시 뒤 다시 확인해 주세요.'],
  stale:['시설 시뮬레이터의 상태가 갱신되지 않고 있습니다','마지막으로 받은 값은 현재 상태가 아닐 수 있어 표시하지 않습니다.'],
  invalid:['시설 시뮬레이터가 보낸 상태를 확인할 수 없습니다','형식이 맞지 않는 값은 화면에 쓰지 않습니다.'],
  commercial_unavailable:['라이선스가 없습니다','시설 모듈은 Live Fire 이상 라이선스에서 동작합니다.'],
  entitlement_module:['라이선스에 시설 모듈이 없습니다','라이선스가 허용한 모듈만 사용할 수 있습니다.'],
  entitlement_tier:['등급이 맞지 않습니다','시설 모듈은 Live Fire 이상에서 동작합니다.']};
 const value=m=>typeof m.value==='boolean'?(m.value?'예':'아니오'):typeof m.value==='number'?Number(m.value.toFixed(2)).toLocaleString('ko-KR'):m.value;
 const metric=m=>`${esc(String(value(m)))}${m.unit?' <small>'+esc(m.unit)+'</small>':''}`;
 const badge=s=>`<span class="badge ${statusClass[s]||'off'}">${esc(statusNames[s]||s)}</span>`;
 const left=t=>{const s=Math.max(0,Math.round((new Date(t)-Date.now())/1000));return s>=60?Math.floor(s/60)+'분 '+(s%60)+'초':s+'초';};
 function unavailable(d){const [title,text]=reasons[d.reason]||['시설 상태를 불러오지 못했습니다','잠시 뒤 다시 확인해 주세요.'];return '<section class="panel">'+empty(title,text)+'</section>';}
 function summary(s){return `<div class="summary-strip facility-summary">${s.summary.slice(0,8).map(m=>`<div class="metric"><span class="metric-label">${esc(m.label)}</span><div class="metric-value small">${metric(m)}</div></div>`).join('')}</div>`;}
 function alarms(s){return `<section class="panel"><div class="toolbar"><div class="toolbar-title">경보 <span class="tag">${s.alarms.length}건</span></div><span class="check-label">시뮬레이터 시간 ${esc(String(s.time_scale))}배속 · 갱신 ${date(s.generated_at)}</span></div>${s.alarms.length?`<div class="table-wrap"><table><thead><tr><th>수준</th><th>내용</th><th>설비</th><th>발생</th></tr></thead><tbody>${s.alarms.map(a=>`<tr><td>${badge(a.level)}</td><td>${esc(a.message)}</td><td class="mono">${esc(a.asset_id||'—')}</td><td>${date(a.since)}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty-compact">현재 경보가 없습니다.</div>'}</section>`;}
 function faults(s,can){return `<section class="panel"><div class="toolbar"><div class="toolbar-title">진행 중인 장애 <span class="tag">${s.faults.length}건</span></div>${can&&(s.faults.length||s.catalog.shed_groups.some(g=>g.shed))?'<button class="secondary" data-facility="clear_all">모두 되돌리기</button>':''}</div>${s.faults.length?`<div class="table-wrap"><table><thead><tr><th>장애</th><th>대상</th><th>넣은 사람</th><th>자동 복구까지</th><th></th></tr></thead><tbody>${s.faults.map(f=>`<tr><td><strong>${esc(f.title)}</strong>${f.fault==='hidden'?'<small>원인을 찾는 훈련입니다</small>':`<small class="mono">${esc(f.fault)}</small>`}</td><td class="mono">${esc(f.fault==='hidden'?'—':f.target==='*'?'전체':f.target)}</td><td>${esc(f.requested_by)}</td><td>${left(f.expires_at)}</td><td>${can&&f.fault!=='hidden'?`<button class="quiet" data-facility="clear" data-handle="${esc(f.handle)}">되돌리기</button>`:''}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty-compact">넣은 장애가 없습니다. 모든 장애는 정한 시간이 지나면 자동으로 복구됩니다.</div>'}</section>`;}
 function injector(s,can,readOnly){
  if(!can)return `<section class="panel"><div class="toolbar"><div class="toolbar-title">장애 넣기</div></div><div class="empty-compact">${readOnly?'라이선스가 만료되어 조회만 할 수 있습니다.':'운영자 이상의 계정으로 장애를 넣을 수 있습니다.'}</div></section>`;
  const list=s.catalog.faults;if(!list.some(f=>f.id===form.fault))form.fault=list[0]?.id||'';
  const chosen=list.find(f=>f.id===form.fault);if(chosen&&!chosen.targets.some(t=>t.id===form.target))form.target=chosen.targets[0]?.id||'';
  const groups=Object.keys(systems).map(k=>[k,list.filter(f=>f.system===k)]).filter(([,x])=>x.length);
  return `<section class="panel"><div class="toolbar"><div class="toolbar-title">장애 넣기</div><span class="check-label">시설 상태 값만 바뀝니다. 서버·네트워크에는 영향을 주지 않습니다.</span></div><div class="panel-body facility-form">
   <label>장애<select id="facility-fault">${groups.map(([k,x])=>`<optgroup label="${esc(systems[k])}">${x.map(f=>`<option value="${esc(f.id)}" ${f.id===form.fault?'selected':''}>${esc(f.title)}</option>`).join('')}</optgroup>`).join('')}</select></label>
   <label>대상<select id="facility-target">${(chosen?.targets||[]).map(t=>`<option value="${esc(t.id)}" ${t.id===form.target?'selected':''}>${esc(t.title)}</option>`).join('')}</select></label>
   <label>지속 시간(분)<input id="facility-minutes" type="number" min="1" max="120" value="${esc(String(form.minutes||chosen?.default_minutes||10))}"></label>
   <button class="primary" data-facility="inject" ${chosen?'':'disabled'}>장애 넣기</button>
   <label class="facility-scale">시간 배속<select id="facility-scale">${[1,5,10,30,60,120].map(v=>`<option value="${v}" ${Number(s.time_scale)===v?'selected':''}>${v}배</option>`).join('')}${[1,5,10,30,60,120].includes(Number(s.time_scale))?'':`<option selected value="${esc(String(s.time_scale))}">${esc(String(s.time_scale))}배</option>`}</select></label>
  </div></section>`;}
 function shed(s,can){const g=s.catalog.shed_groups;if(!g.length)return '';return `<section class="panel"><div class="toolbar"><div class="toolbar-title">부하 차단</div><span class="check-label">전원이 부족할 때 어떤 부하를 내릴지 운영자가 정합니다.</span></div><div class="table-wrap"><table><thead><tr><th>부하 묶음</th><th>차단 시 영향</th><th>부하</th><th>상태</th><th></th></tr></thead><tbody>${g.map(x=>`<tr><td><strong>${esc(x.title)}</strong></td><td>${esc(x.impact)}</td><td class="mono">${esc(Number(x.load_kw.toFixed(1)).toLocaleString('ko-KR'))} kW</td><td>${x.shed?'<span class="badge deny">차단됨</span>':'<span class="badge allow">공급 중</span>'}</td><td>${can?`<button class="quiet" data-facility="${x.shed?'restore':'shed'}" data-group="${esc(x.id)}">${x.shed?'복구':'차단'}</button>`:''}</td></tr>`).join('')}</tbody></table></div></section>`;}
 function assets(s){const order={critical:0,warning:1,off:2,normal:3};const rows=[...s.assets].sort((a,b)=>order[a.status]-order[b.status]||a.id.localeCompare(b.id));
  return `<section class="panel"><div class="toolbar"><div class="toolbar-title">통로 온도</div></div><div class="facility-aisles">${s.aisles.map(a=>`<div class="metric"><span class="metric-label">${esc(a.floor)} · ${esc(a.id)} 통로</span><div class="metric-value small">${esc(Number(a.temp_c.toFixed(1)).toLocaleString('ko-KR'))} <small>°C</small></div>${badge(a.status)}</div>`).join('')||'<div class="empty-compact">통로 정보가 없습니다.</div>'}</div></section>
  <section class="panel"><div class="toolbar"><div class="toolbar-title">설비 상태 <span class="tag">${rows.length}개</span></div><a class="workspace-link" href="#datacenter">데이터센터에서 보기 ${icon('arrow')}</a></div><div class="table-wrap"><table><thead><tr><th>설비</th><th>상태</th><th>측정값</th></tr></thead><tbody>${rows.map(a=>`<tr><td>${a.title?`<strong>${esc(a.title)}</strong><br>`:''}<small class="mono">${esc(a.id)}</small></td><td>${badge(a.status)}</td><td class="facility-metrics">${a.metrics.map(m=>`<span>${esc(m.label)} <strong>${metric(m)}</strong></span>`).join('')||'—'}</td></tr>`).join('')}</tbody></table></div></section>`;}
 function events(s){return `<section class="panel"><div class="toolbar"><div class="toolbar-title">기록</div><span class="check-label">장애를 넣고 되돌린 내용은 감사 기록에도 남습니다.</span></div>${s.events.length?`<div class="table-wrap"><table><tbody>${[...s.events].reverse().map(e=>`<tr><td class="facility-time">${date(e.at)}</td><td>${esc(e.message)}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty-compact">기록이 없습니다.</div>'}</section>`;}
 function settle(s){if(!pending.length)return;const done=new Map(s.handled.map(h=>[h.request_id,h]));
  const codes={unknown_fault:'없는 장애입니다.',unknown_target:'이 장애를 넣을 수 없는 대상입니다.',unknown_group:'없는 부하 묶음입니다.',unknown_handle:'이미 복구된 장애입니다.',too_many_faults:'동시에 넣을 수 있는 장애 수를 넘었습니다.',invalid_request:'요청을 처리하지 못했습니다.',not_permitted:'강사가 넣은 장애는 강사만 끝낼 수 있습니다.'};
  pending=pending.filter(p=>{const h=done.get(p.id);if(!h)return Date.now()-p.at<30000;if(h.status==='rejected')notice(codes[h.code]||'요청이 거절되었습니다.',true);else notice(p.label+' 적용했습니다.');return false;});}
 function draw(){const d=data,node=$('system-view');if(!node||!d)return;
  if(!d.simulator||!d.state){node.innerHTML=unavailable(d);$('sync-status').textContent='시설 상태 없음';return;}
  const s=d.state,can=d.can_operate,active=document.activeElement?.id;settle(s);
  node.innerHTML=summary(s)+alarms(s)+faults(s,can)+injector(s,can,d.read_only)+shed(s,can)+assets(s)+events(s);
  if(active&&$(active))$(active).focus({preventScroll:true});
  $('sync-status').textContent='시설 상태 '+date(s.generated_at);}
 async function send(body,label){touched=0;const r=await api('facility/requests',body);pending.push({id:r.request_id,label,at:Date.now()});notice(label+' 요청했습니다.');setTimeout(refresh,1500);}
 async function refresh(){if(view!=='module'||document.hidden)return;if(Date.now()-touched<8000)return;   // do not redraw under an open list or while typing
  try{data=await api('facility');draw();}catch(e){}}
 for(const kind of ['pointerdown','focusin','input'])document.addEventListener(kind,e=>{if(e.target.closest?.('.facility-form'))touched=Date.now();});
 document.addEventListener('change',e=>{if(e.target.id==='facility-fault'){form.fault=e.target.value;form.target='';form.minutes='';draw();}else if(e.target.id==='facility-target')form.target=e.target.value;else if(e.target.id==='facility-minutes')form.minutes=e.target.value;
  else if(e.target.id==='facility-scale')act(()=>send({action:'time_scale',value:Number(e.target.value)},'시간 배속 변경을'));});
 document.addEventListener('click',e=>{const b=e.target.closest('[data-facility]');if(!b||!data?.state)return;const a=b.dataset.facility;
  if(a==='inject'){const minutes=Number($('facility-minutes').value);if(!Number.isInteger(minutes)||minutes<1||minutes>120){notice('지속 시간은 1~120분으로 입력해 주세요.',true);return;}
   const f=data.state.catalog.faults.find(x=>x.id===form.fault);act(()=>send({action:'inject',fault:form.fault,target:form.target,minutes},'장애('+(f?.title||form.fault)+')를'));}
  else if(a==='clear')act(()=>send({action:'clear',handle:b.dataset.handle},'장애 복구를'));
  else if(a==='clear_all')act(()=>send({action:'clear_all'},'전체 복구를'));
  else if(a==='shed'||a==='restore')act(()=>send({action:a,group:b.dataset.group},a==='shed'?'부하 차단을':'부하 복구를'));});
 return {owns(component){return (component?.requires?.capabilities||[]).includes('facility-state');},
  async view(sequence){const d=await api('facility');if(sequence!==loadSequence)return;data=d;draw();clearInterval(timer);timer=setInterval(()=>{if(view==='module'&&$('system-view')?.querySelector('.facility-summary,.facility-form'))refresh();else if(view!=='module'){clearInterval(timer);timer=null;}},5000);},
  status(live,id){const a=live?.state?.assets.find(x=>x.id===id);return a?{badge:badge(a.status),metrics:a.metrics.map(m=>`<div><span class="metric-label">${esc(m.label)}</span><strong>${metric(m)}</strong></div>`).join('')}:null;}};
})();
