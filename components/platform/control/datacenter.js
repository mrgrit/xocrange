'use strict';
window.DataCenter=(()=>{
 let data=null,mode='building',selectedRack=null,selection=null,selectedFacility=null,zoom=1,drag=null,pan={x:0,y:0},camera=null,box=null;
 let floorRequest=0,loading=false,resize=null,resizeFrame=0,sshUser=null,sshPort=22,designFloor=null,designScreen='space';
 const enabled=f=>Boolean(f?.enabled&&data.allowed_floors.includes(f.id));
 const preview=id=>(data?.preview_floors||[]).includes(id);
 function hostCommand(){const h=data?.host_access?.host;if(!/^[a-z_][a-z0-9_-]{0,31}$/.test(sshUser||'')||!Number.isInteger(sshPort)||sshPort<1||sshPort>65535||!/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(h||''))return '';return 'ssh '+(sshPort===22?'':'-p '+sshPort+' ')+sshUser+'@'+h;}
 function sshFields(){const cmd=hostCommand();if($('dc-ssh-command'))$('dc-ssh-command').value=cmd||'Linux 계정을 입력하면 SSH 명령이 표시됩니다.';const b=document.querySelector('[data-dc-copy=ssh]');if(b)b.disabled=!cmd;}
 const SEG={ext:'외부망',pipe:'중계망',dmz:'DMZ',int:'내부망',office:'업무망'};
 function table(head,rows){if(!rows.length)return '<p class="dc-note">수집된 항목이 없습니다.</p>';return `<div class="dc-table-wrap"><table class="dc-table"><thead><tr>${head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${esc(c??'-')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;}
 function num(n){return Number.isInteger(n)?n.toLocaleString('ko-KR'):'-';}
 function titleOf(service){return data.assets.find(x=>x.service===service)?.title||service;}
 function switchPanel(a){
  const s=a.segment,ports=s.ports||[];if(!ports.length)return '<p class="dc-note">포트 정보를 아직 수집하지 못했습니다.</p>';
  const W=300,top=48,pitch=40,H=top+pitch*ports.length+8;
  let g=`<svg class="dc-switch-panel" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(a.title)} 포트 연결도">`;
  g+=`<rect x="6" y="4" width="${W-12}" height="30" rx="5" class="dc-sw-uplink"/><text x="16" y="17" class="dc-topo-small">업링크 · 호스트 게이트웨이</text><text x="16" y="29" class="dc-topo-label">${esc(s.gateway||'-')} · ${esc(s.bridge||'')}</text>`;
  g+=`<rect x="8" y="${top-6}" width="58" height="${pitch*ports.length+4}" rx="6" class="dc-sw-chassis"/>`;
  ports.forEach((p,i)=>{const y=top+i*pitch,up=p.state==='up',peer=p.peer;
   g+=`<rect x="18" y="${y+6}" width="26" height="18" rx="2" class="${up?'dc-sw-port-up':'dc-sw-port-down'}"/><rect x="22" y="${y+9}" width="18" height="6" class="dc-sw-port-jack"/><text x="56" y="${y+19}" text-anchor="end" class="dc-topo-small">${p.port}</text>`;
   g+=`<line x1="44" y1="${y+15}" x2="96" y2="${y+15}" class="${up?'dc-sw-cable':'dc-sw-cable-down'}"/>`;
   g+=`<rect x="96" y="${y+1}" width="${W-102}" height="${pitch-6}" rx="4" class="dc-sw-card"/>`;
   g+=`<text x="104" y="${y+15}" class="dc-topo-label">${esc(peer?titleOf(peer.service):'연결 정보 없음')}${peer?' · '+esc(peer.ifname):''}</text>`;
   g+=`<text x="104" y="${y+28}" class="dc-topo-small">${esc(peer&&peer.ip||'-')} · RX ${num(p.rx_packets)} · TX ${num(p.tx_packets)}</text>`;
  });
  return g+'</svg>';
 }
 function networkDetail(a){
  if(a.kind==='switch'&&a.segment){const s=a.segment,c=s.counters||{};
   return `<section class="dc-net"><h4>스위치 정보</h4><dl class="dc-facts"><div><dt>대역 · 게이트웨이(호스트)</dt><dd>${esc(s.subnet||'-')} · ${esc(s.gateway||'-')}</dd></div><div><dt>브리지 · 상태 · MTU</dt><dd>${esc(s.bridge||'-')} · ${esc(s.state)} · ${esc(s.mtu??'-')}</dd></div><div><dt>수신 / 송신 패킷</dt><dd>${num(c.rx_packets)} / ${num(c.tx_packets)}</dd></div>${s.internal?'<div><dt>인터넷 직접 연결</dt><dd>없음 — 진입점과 구간 라우터를 거쳐서만 통신</dd></div>':''}</dl>
   <h4>포트 연결도 <small>${(s.ports||[]).length}개 포트 사용</small></h4>${switchPanel(a)}<p class="dc-note">포트 번호는 브리지에 연결된 순서입니다. RX·TX는 스위치 포트 기준 수신·송신 패킷 수입니다.</p>
   <h4>연결된 장비</h4>${table(['장비','IP','MAC'],(s.endpoints||[]).map(e=>[titleOf(e.service),e.ip?e.ip+'/'+(e.prefix??''):'-',e.mac]))}
   <h4>MAC 주소 표 <small>최근 학습한 항목</small></h4>${table(['MAC','포트','장비'],(s.mac_table||[]).map(m=>[m.mac,m.port,m.owner?titleOf(m.owner):'외부·호스트']))}</section>`;}
  if(a.network){const n=a.network;
   return `<section class="dc-net"><h4>인터페이스</h4>${table(['이름','구간','주소','MAC'],(n.interfaces||[]).map(i=>[i.name,i.segment?SEG[i.segment]||i.segment:'관리망',(i.addresses||[]).join(', '),i.mac]))}
   <h4>라우팅 표 <small>show ip route</small></h4>${table(['목적지','다음 홉','인터페이스'],(n.routes||[]).map(r=>[r.dst,r.via||'직접 연결',r.dev]))}
   <h4>ARP 표 <small>show arp</small></h4>${table(['IP','MAC','인터페이스','장비'],(n.neighbors||[]).map(x=>[x.ip,x.mac,x.dev,x.owner?titleOf(x.owner):'-']))}</section>`;}
  return '';
 }
 function topology(){
  const sw=data.assets.filter(a=>a.kind==='switch'&&a.segment);if(!sw.length)return '<p class="dc-note">실습망 정보를 아직 수집하지 못했습니다. 잠시 후 다시 확인하세요.</p>';
  const W=300,rowH=62,y0=18,hop={ext:'fw',pipe:'ips',dmz:'web'},HOP={fw:'방화벽',ips:'IPS',web:'웹 방화벽'};
  let svg=`<svg class="dc-topology" viewBox="0 0 ${W} ${y0+rowH*sw.length}" role="img" aria-label="실습망 토폴로지">`;
  sw.forEach((a,i)=>{const s=a.segment,y=y0+i*rowH,members=(s.endpoints||[]).map(e=>e.service).filter(x=>!Object.values(hop).includes(x)||x===hop[s.id]);
   svg+=`<rect x="8" y="${y}" width="${W-16}" height="24" rx="5" class="dc-topo-switch"/><text x="16" y="${y+16}" class="dc-topo-label">${esc(SEG[s.id])} ${esc(s.subnet||'')}</text>`;
   svg+=`<text x="${W-14}" y="${y+16}" text-anchor="end" class="dc-topo-small">연결 장비 ${(s.endpoints||[]).length}대</text>`;
   if(s.id==='office')svg+=`<text x="${W/2}" y="${y-6}" text-anchor="middle" class="dc-topo-small">IPS의 세 번째 인터페이스에 연결</text>`;
   if(hop[s.id]&&i<sw.length-1){svg+=`<line x1="${W/2}" y1="${y+24}" x2="${W/2}" y2="${y+rowH}" class="dc-topo-link"/><rect x="${W/2-34}" y="${y+31}" width="68" height="20" rx="10" class="dc-topo-router"/><text x="${W/2}" y="${y+45}" text-anchor="middle" class="dc-topo-label">${esc(HOP[hop[s.id]])}</text>`;}
  });
  return svg+'</svg><p class="dc-note">요청 경로: 외부 → HTTPS 진입점 → 방화벽 → IPS → 웹 방화벽(WAF) → 내부 타깃. 업무망은 IPS에서 갈라지며, 업무망의 PC는 웹 방화벽과 SIEM 에이전트 포트로만 나갑니다. 스위치를 선택하면 포트 연결도와 MAC 주소 표를, 방화벽·IPS·웹 방화벽을 선택하면 라우팅 표와 ARP 표를 볼 수 있습니다.</p>';
 }
 function facilityInspector(node){
  const list=data.facilities||[],f=list.find(x=>x.id===selectedFacility),floor=data.floors.find(x=>x.id===designFloor);
  node.hidden=false;$('dc-stage')?.classList.add('has-selection');
  const head=`<div class="dc-inspector-heading"><span class="dc-kicker">${f?'FACILITY DETAILS':'FACILITY INVENTORY'}</span>${f?'<button class="dc-icon-button" data-dc-facility-close aria-label="시설 상세 닫기">×</button>':''}</div>`;
  const baseline='<span class="badge" title="시설 시뮬레이터(M4)가 없어 대장의 정격·설정값을 보여 줍니다">기준값 · 시뮬레이터 없음</span>';
  if(!f){
   const groups={};list.forEach(x=>(groups[x.system_title||'기타']=groups[x.system_title||'기타']||[]).push(x));
   node.innerHTML=head+`<h3>${esc(designFloor+' · '+(floor?.title||''))}</h3><p class="dc-note">시설을 선택하면 역할·배치·장애 영향·점검 항목과 기준값을 볼 수 있습니다. ${baseline}</p>`+
    Object.entries(groups).map(([g,xs])=>`<h4 class="dc-facility-group">${esc(g)}</h4><div class="dc-rack-list">${xs.map(x=>`<button data-dc-facility-pick="${esc(x.id)}"><span><strong>${esc(x.name)}</strong><small>${esc(x.title)}</small></span><span class="dc-row-arrow">›</span></button>`).join('')}</div>`).join('');
   return;
  }
  const chain=(data.facility_systems||{})[f.system]?.chain;
  node.innerHTML=head+`<button class="dc-back" data-dc-facility-back>← ${esc(designFloor)} 시설 목록</button><h3>${esc(f.name)}</h3><span class="dc-service-name">${esc(f.title)} · ${esc(f.system_title)}</span>${baseline}
   <p class="dc-device-description">${esc(f.role)}</p>
   <dl class="dc-facts"><div><dt>배치</dt><dd>${esc(f.placement)}</dd></div><div><dt>장애 영향</dt><dd>${esc(f.impact)}</dd></div>${chain?`<div><dt>${esc(f.system_title)} 계통</dt><dd>${esc(chain)}</dd></div>`:''}</dl>
   <section class="dc-net"><h4>점검 항목</h4><ul class="dc-checks">${(f.checks||[]).map(c=>`<li>${esc(c)}</li>`).join('')}</ul>
   <h4>기준값 <small>대장의 정격·설정값</small></h4>${table(['항목','값'],(f.baseline||[]).map(b=>[b.label,String(b.value)]))}</section>
   <p class="dc-note">${esc(data.facility_note||'')} 실시간 상태와 장애 주입은 Live Fire의 시설 모듈에서 제공합니다.</p>`;
 }
 function inspector(){
  const node=$('dc-inspector');if(!node||!data)return;
  if(mode==='facility'){facilityInspector(node);return;}
  const rack=data.racks.find(r=>r.id===selectedRack),a=data.assets.find(a=>a.asset_id===selection);
  node.hidden=!rack;$('dc-stage')?.classList.toggle('has-selection',Boolean(rack));if(!rack){node.replaceChildren();return;}
  const list=data.assets.filter(a=>a.rack_id===rack.id);
  const head=`<div class="dc-inspector-heading"><span class="dc-kicker">${a?'DEVICE DETAILS':'RACK INVENTORY'}</span><button class="dc-icon-button" data-dc-close aria-label="장비 패널 닫기">×</button></div>`;
  if(!a){
   node.innerHTML=head+`<h3>${esc(rack.id)}</h3><p class="dc-rack-title">${esc(rack.title)}</p><div class="dc-rack-spec"><span>2F · ${esc(rack.aisle)} 아일</span><span>${list.length}개 장비</span></div>${rack.id==='R-2F-03'?topology():''}<p class="dc-note">장비를 선택하면 상태·설명·접속 방법을 확인할 수 있습니다.</p><div class="dc-rack-list">${list.map(a=>`<button data-dc-asset="${esc(a.asset_id)}"><span><strong>${esc(a.title)}</strong><small>${esc(a.service)}</small></span>${stateBadge(a.health.state)}<span class="dc-row-arrow">›</span></button>`).join('')||'<p class="dc-note">이 랙에 선택 설치된 장비가 없습니다.</p>'}</div>`;
  }else{
   node.innerHTML=head+`<button class="dc-back" data-dc-back>← ${esc(rack.id)} 장비 목록</button><h3>${esc(a.title)}</h3><span class="dc-service-name">${esc(a.service)}</span>${stateBadge(a.health.state)}<p class="dc-device-description">${esc(a.description)}</p><dl class="dc-facts"><div><dt>배치 · 네트워크 존</dt><dd>${esc(rack.id)} · ${a.zones.map(esc).join(' / ')}</dd></div><div><dt>마지막 상태 확인</dt><dd>${esc(date(a.kind==='switch'?data.network_observation?.observed_at:data.observation.observed_at))}</dd></div></dl>${networkDetail(a)}${a.web_console?`<a class="workspace-link dc-console-link" href="${esc(a.web_console)}" ${a.web_console==='/siem/'?'target="_blank" rel="noopener noreferrer"':''}>웹 콘솔 열기 ${icon('arrow')}</a>`:'<p class="dc-note">이 장비에는 별도 웹 콘솔이 없습니다.</p>'}<section class="dc-access-section"><h4>SSH · 장비 셸 접속</h4><p class="dc-note">호스트에 SSH로 접속한 뒤 장비 셸 명령을 실행하세요.</p><div class="dc-ssh-inputs"><label>Linux 계정<input id="dc-ssh-user" value="${esc(sshUser||'')}" placeholder="예: ccc" maxlength="32" autocomplete="off" spellcheck="false"></label><label>SSH 포트<input id="dc-ssh-port" type="number" min="1" max="65535" value="${sshPort}"></label></div><div class="dc-command-head"><span>1. 호스트 SSH</span><button data-dc-copy="ssh">복사</button></div><textarea id="dc-ssh-command" readonly rows="2" aria-label="호스트 SSH 접속 명령"></textarea><div class="dc-command-head"><span>2. ${a.kind==='switch'?esc(a.title)+' 상태 확인(호스트, 읽기 전용)':esc(a.service)+' 장비 셸'}</span><button data-dc-copy="shell">복사</button></div><textarea id="dc-shell-command" readonly rows="4" aria-label="장비 컨테이너 셸 명령">${esc(a.access.shell_command)}</textarea><p class="dc-note">Core 계정과 Linux 계정은 별도입니다. 호스트의 SSH 접속·sudo 권한이 필요합니다.</p></section><details class="dc-id"><summary>자산 식별자</summary><code>${esc(a.asset_id)}</code></details>`;
   $('dc-ssh-user').oninput=e=>{sshUser=e.target.value;sshFields();};$('dc-ssh-port').oninput=e=>{sshPort=Number(e.target.value);sshFields();};sshFields();
  }
 }
 function updateCamera(){if(!camera||!box)return;const cx=box.x+box.width/2,cy=box.y+box.height/2;camera.setAttribute('transform',`translate(${pan.x} ${pan.y}) translate(${cx} ${cy}) scale(${zoom}) translate(${-cx} ${-cy})`);if($('dc-zoom-value'))$('dc-zoom-value').textContent=Math.round(zoom*100)+'%';}
 function scene(){const host=$('dc-scene');if(!host||!host.isConnected||['design','learning'].includes(mode)&&designScreen==='workspace')return;const active=document.activeElement?.closest('[data-dc-rack],[data-dc-learning-route]'),focused=active&&(active.dataset.dcLearningRoute?['data-dc-learning-route',active.dataset.dcLearningRoute]:['data-dc-rack',active.dataset.dcRack]);const value=DataCenterScene.render(host,data,mode,mode==='facility'?selectedFacility:selectedRack,designFloor);camera=value.world;box=value.box;updateCamera();if(focused)Array.from(host.querySelectorAll('['+focused[0]+']')).find(n=>n.getAttribute(focused[0])===focused[1])?.focus({preventScroll:true});}
 function render(){
  const focused=document.activeElement,focus=focused?.closest('[data-dc-asset],[data-dc-enter],[data-dc-mode],[data-dc-zoom],[data-dc-rack]');
  const restore=focus?['data-dc-asset','data-dc-enter','data-dc-mode','data-dc-zoom','data-dc-rack'].map(k=>[k,focus.getAttribute(k)]).find(([,v])=>v!==null):null;
  const scroll=$('dc-inspector')?.scrollTop||0;resize?.disconnect();cancelAnimationFrame(resizeFrame);
  let stage=$('dc-stage');if(!stage){$('system-view').innerHTML='<section id="dc-stage" class="dc-stage" aria-label="데이터센터 시각화"></section>';stage=$('dc-stage');}
  const design=mode==='design',learning=mode==='learning',facilityView=mode==='facility',room=design||learning||facilityView,floor=data.floors.find(f=>f.id===designFloor),workspace=room&&designScreen==='workspace';
  stage.dataset.mode=mode;stage.dataset.floor=room?designFloor:mode==='floor'?'2F':'';stage.classList.toggle('dc-workspace-design',workspace);stage.classList.toggle('has-selection',Boolean(selectedRack));
  stage.innerHTML=`<header class="dc-header"><div class="dc-heading"><span class="dc-kicker">xOC RANGE / FACILITY EXPLORER</span><h2>${room?esc(designFloor+' · '+floor.title):mode==='building'?'데이터센터 전체 배치':'2F · 일반 전산실'}<span>${facilityView?'FACILITIES':learning?'CONTENT LIBRARY':design?'DESIGN PREVIEW':mode==='building'?'SPATIAL OPERATIONS':'RACKS & DEVICES'}</span></h2></div><div class="dc-header-right">${design?'<span class="dc-preview-badge">관리자 · 디자인 보기</span>':''}${mode!=='floor'?'':`<div class="dc-header-metric"><strong>${data.racks.length}</strong><span>랙</span></div><div class="dc-header-metric"><strong>${data.assets.length}</strong><span>설치 장비</span></div><div class="dc-header-metric"><strong>${data.assets.filter(a=>a.health.state==='running').length}</strong><span>실행 중</span></div>`}<span class="dc-edition" data-state="${esc((data.edition||{}).state||'none')}"><span></span> ${esc(((data.edition||{}).label||'Community').toUpperCase())}${(data.edition||{}).state==='expired'?' · 만료':''}</span></div></header>
  <div class="dc-layout">
  <div class="dc-viewport"><div class="dc-view-tools"><div class="dc-view-switch" role="group" aria-label="공간 보기"><button data-dc-mode="building" aria-pressed="${mode==='building'}">전체 배치</button>${mode==='floor'?'<button data-dc-mode="floor" aria-pressed="true">2층 내부</button>':''}${facilityView?`<button aria-pressed="true">${esc(designFloor)} 시설</button>`:''}${room&&!facilityView?`<button data-dc-design="space" aria-pressed="${!workspace}">${learning?'공간 보기':'공간 디자인'}</button>${['6F','7F'].includes(designFloor)?`<button data-dc-design="workspace" aria-pressed="${workspace}">${learning?'콘텐츠 카탈로그':'시나리오 목록'}</button>`:''}`:''}</div><button class="dc-icon-button" data-dc-fullscreen aria-label="전체 화면">⛶</button></div><div id="dc-scene" class="dc-scene ${mode!=='building'?'dc-interior':''}"></div><div class="dc-camera-tools" ${workspace?'hidden':''} role="group" aria-label="시점 조절"><button data-dc-zoom="out" aria-label="축소">−</button><span id="dc-zoom-value"></span><button data-dc-zoom="in" aria-label="확대">+</button><button data-dc-zoom="reset" aria-label="시점 초기화">맞춤</button></div><span class="dc-scene-hint" ${workspace?'hidden':''}>${facilityView?'시설을 선택하면 설명과 기준값을 볼 수 있습니다':room&&['6F','7F'].includes(designFloor)?'화면의 콘텐츠를 선택해 열기':design?'관리자 디자인 보기':mode==='building'?'층 선택 → 공간 · 콘텐츠':'랙을 선택해 탑재 장비와 접속 정보를 확인하세요'}<small>드래그 이동 · 확대·축소</small></span></div><aside id="dc-inspector" class="dc-inspector" aria-label="랙 및 장비 정보"></aside></div>
  ${mode==='floor'?`<div class="dc-service-dock" aria-label="랙 선택">${data.racks.map(r=>`<button data-dc-rack="${esc(r.id)}" class="dc-service-chip ${selectedRack===r.id?'selected':''}"><strong>${esc(r.id)}</strong> ${esc(r.title)} <span>${r.asset_ids.length}개 장비</span></button>`).join('')}</div>`:''}
  ${mode==='building'?'':`<footer class="dc-status"><span class="dc-observation ${data.observation.fresh?'':'dc-stale'}"><span></span>${data.observation.fresh?'모니터링 연결 · '+esc(date(data.observation.observed_at)):'모니터링 지연 · 상태 미확인'}</span><span>컨테이너 상태 · 15초 갱신</span><span class="dc-status-right">xOC RANGE / FACILITY EXPLORER</span></footer>`}`;
  inspector();if(workspace){$('dc-scene').innerHTML=DataCenterWorkspaces.render(designFloor);act(()=>DataCenterWorkspaces.hydrate(designFloor));}else scene();$('dc-inspector').scrollTop=scroll;
  if(restore)Array.from(stage.querySelectorAll('['+restore[0]+']')).find(n=>n.getAttribute(restore[0])===restore[1])?.focus({preventScroll:true});
  const host=$('dc-scene');let w=host.clientWidth,h=host.clientHeight;
  resize=new ResizeObserver(()=>{if(!host.isConnected||view!=='datacenter'||(host.clientWidth===w&&host.clientHeight===h))return;w=host.clientWidth;h=host.clientHeight;cancelAnimationFrame(resizeFrame);resizeFrame=requestAnimationFrame(scene);});resize.observe(host);
  $('sync-status').textContent='화면 갱신 '+date(data.served_at);
 }
 async function enter(id){
  if(loading||view!=='datacenter')return;
  if(!enabled(data?.floors.find(f=>f.id===id))){if(preview(id))await enterDesign(id);return;}
  const request=++floorRequest;loading=true;const sequence=loadSequence;
  try{const fresh=await api('datacenter/floors/'+encodeURIComponent(id));if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence)return;if(id==='6F'&&fresh.catalog_only&&fresh.entry_route==='/core/#academy'){const content=await DataCenterWorkspaces.snapshot();if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence)return;data.learning_snapshot=content;mode='learning';designFloor='6F';designScreen='workspace';selectedRack=null;selection=null;reset();render();return;}if(!fresh.allowed_floors.includes(id)||!fresh.floors.find(f=>f.id===id)?.enabled)return;
   if(fresh.facility_view){const same=mode==='facility'&&designFloor===id;data=fresh;mode='facility';designFloor=id;designScreen='space';selection=null;selectedRack=null;if(!same){selectedFacility=null;zoom=1;pan={x:0,y:0};}else if(!(fresh.facilities||[]).some(f=>f.id===selectedFacility))selectedFacility=null;render();return;}
   data=fresh;mode='floor';selection=null;selectedRack=null;zoom=1;pan={x:0,y:0};render();
  }finally{loading=false;}
 }
 async function enterDesign(id){
  const request=++floorRequest,sequence=loadSequence;loading=true;
  try{const result=await api('datacenter/design/'+encodeURIComponent(id));
   if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence||result.floor?.id!==id||result.preview_only!==true)return;
   if(['6F','7F'].includes(id)&&session.navigation?.some(n=>n.id==='academy')){const content=await DataCenterWorkspaces.snapshot();if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence)return;data.learning_snapshot=content;}
   mode='design';designFloor=id;designScreen='space';selectedRack=null;selection=null;reset();render();
  }finally{loading=false;}
 }
 function home(){floorRequest++;loading=false;mode='building';designFloor=null;designScreen='space';selection=null;selectedRack=null;selectedFacility=null;reset();}
 function reset(){zoom=1;pan={x:0,y:0};updateCamera();}
 async function copy(which){const n=$(which==='ssh'?'dc-ssh-command':'dc-shell-command');if(!n||which==='ssh'&&!hostCommand())return;try{await navigator.clipboard.writeText(n.value);notice('접속 명령을 복사했습니다.');}catch{n.focus();n.select();if(document.execCommand('copy'))notice('접속 명령을 복사했습니다.');else notice('명령을 선택했습니다. Ctrl+C로 복사하세요.');}}
 document.addEventListener('click',e=>{
  if(e.target.closest('[data-nav=datacenter]')){home();if(data&&view==='datacenter')render();return;}
  if(view!=='datacenter'||!data||!e.target.closest('#dc-stage'))return;
  const design=e.target.closest('[data-dc-design]');if(design&&(mode==='design'&&preview(designFloor)||mode==='learning'&&enabled(data.floors.find(f=>f.id===designFloor)))){designScreen=design.dataset.dcDesign==='workspace'?'workspace':'space';render();return;}
  const content=e.target.closest('[data-dc-learning-route]');if(content&&['design','learning'].includes(mode)){location.hash=content.dataset.dcLearningRoute;return;}
  const floor=e.target.closest('[data-dc-enter],[data-dc-floor]');if(floor){act(()=>enter(floor.dataset.dcEnter||floor.dataset.dcFloor));return;}
  if(mode==='facility'){
   const pick=e.target.closest('[data-dc-facility],[data-dc-facility-pick]');
   if(pick){const id=pick.getAttribute('data-dc-facility')||pick.getAttribute('data-dc-facility-pick');if((data.facilities||[]).some(f=>f.id===id)){selectedFacility=id;inspector();scene();$('dc-inspector').scrollTop=0;}return;}
   if(e.target.closest('[data-dc-facility-back],[data-dc-facility-close]')){selectedFacility=null;inspector();scene();return;}
  }
  const rack=e.target.closest('[data-dc-rack]');if(rack){if(data.racks.some(r=>r.id===rack.dataset.dcRack)){selectedRack=rack.dataset.dcRack;selection=null;inspector();scene();document.querySelectorAll('.dc-service-chip').forEach(n=>n.classList.toggle('selected',n.dataset.dcRack===selectedRack));$('dc-inspector').scrollIntoView({block:'nearest',behavior:'instant'});}return;}
  const asset=e.target.closest('[data-dc-asset]');if(asset){if(data.assets.some(a=>a.asset_id===asset.dataset.dcAsset&&a.rack_id===selectedRack)){selection=asset.dataset.dcAsset;inspector();$('dc-inspector').scrollTop=0;}return;}
  if(e.target.closest('[data-dc-back]')){selection=null;inspector();return;}
  const change=e.target.closest('[data-dc-mode]');if(change){if(change.dataset.dcMode==='floor')act(()=>enter('2F'));else{floorRequest++;mode='building';selection=null;selectedRack=null;reset();render();}return;}
  const z=e.target.closest('[data-dc-zoom]');if(z){if(z.dataset.dcZoom==='reset')reset();else{zoom=Math.max(.7,Math.min(3.5,zoom+(z.dataset.dcZoom==='in'?.15:-.15)));updateCamera();}return;}
  if(e.target.closest('[data-dc-close]')){selection=null;selectedRack=null;inspector();scene();}
  const c=e.target.closest('[data-dc-copy]');if(c)act(()=>copy(c.dataset.dcCopy));
  if(e.target.closest('[data-dc-fullscreen]'))act(async()=>{if(document.fullscreenElement)await document.exitFullscreen();else await $('dc-stage').requestFullscreen();});
 });
 document.addEventListener('keydown',e=>{if(view!=='datacenter')return;const n=e.target.closest('g[data-dc-floor],g[data-dc-rack],g[data-dc-facility],[data-dc-learning-route]');if(n&&['Enter',' '].includes(e.key)&&n.getAttribute('aria-disabled')!=='true'){e.preventDefault();n.dispatchEvent(new MouseEvent('click',{bubbles:true}));}});
 document.addEventListener('pointerdown',e=>{const host=e.target.closest('#dc-scene');if(!host||e.button!==0||e.target.closest('.commercial-workspace')||e.target.closest('[data-dc-rack],[data-dc-facility],[data-dc-learning-route],.dc-level-active,.dc-level-preview'))return;drag={x:e.clientX,y:e.clientY,px:pan.x,py:pan.y,host,id:e.pointerId};host.setPointerCapture(e.pointerId);host.classList.add('dc-dragging');});
 document.addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId||!box)return;const factor=box.width/drag.host.clientWidth;pan={x:Math.max(-box.width,Math.min(box.width,drag.px+(e.clientX-drag.x)*factor)),y:Math.max(-box.height,Math.min(box.height,drag.py+(e.clientY-drag.y)*factor))};updateCamera();});
 const end=()=>{if(drag){drag.host.classList.remove('dc-dragging');drag=null;}};document.addEventListener('pointerup',end);document.addEventListener('pointercancel',end);window.addEventListener('blur',end);
 return {clear(){home();data=null;camera=null;box=null;sshUser=null;resize?.disconnect();cancelAnimationFrame(resizeFrame);},get interacting(){return Boolean(drag)||loading||view==='datacenter'&&['design','learning','facility'].includes(mode);},async load(sequence){
  if(!session.navigation?.some(p=>p.id==='datacenter')){$('system-view').innerHTML='<div class="panel">'+empty('설치되지 않은 기능','NOC 구성요소를 선택 설치하면 데이터센터를 볼 수 있습니다.')+'</div>';return;}
  const fresh=await api('datacenter');if(sequence!==loadSequence)return;let content;if(['design','learning'].includes(mode)&&['6F','7F'].includes(designFloor)&&session.navigation?.some(n=>n.id==='academy'))content=await DataCenterWorkspaces.snapshot();if(sequence!==loadSequence)return;data=fresh;if(content)data.learning_snapshot=content;if(sshUser===null)sshUser=data.host_access.username_hint||'';
  if(mode==='facility'&&enabled(data.floors.find(f=>f.id===designFloor))){act(()=>enter(designFloor));return;}
  if(!data.allowed_floors.includes('2F')||mode==='design'&&!preview(designFloor)||mode==='learning'&&!enabled(data.floors.find(f=>f.id===designFloor))||mode==='facility')mode='building';if(!data.assets.some(a=>a.asset_id===selection))selection=null;if(!data.racks.some(r=>r.id===selectedRack))selectedRack=null;render();
 }};
})();
async function datacenterView(sequence){await DataCenter.load(sequence);}
