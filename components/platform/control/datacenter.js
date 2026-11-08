'use strict';
window.DataCenter=(()=>{
 let data=null,mode='building',selectedRack=null,selection=null,zoom=1,drag=null,pan={x:0,y:0},camera=null,box=null;
 let floorRequest=0,loading=false,resize=null,resizeFrame=0,sshUser=null,sshPort=22,designFloor=null,designScreen='space';
 const enabled=f=>Boolean(f?.enabled&&data.allowed_floors.includes(f.id));
 const preview=id=>(data?.preview_floors||[]).includes(id);
 function hostCommand(){const h=data?.host_access?.host;if(!/^[a-z_][a-z0-9_-]{0,31}$/.test(sshUser||'')||!Number.isInteger(sshPort)||sshPort<1||sshPort>65535||!/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(h||''))return '';return 'ssh '+(sshPort===22?'':'-p '+sshPort+' ')+sshUser+'@'+h;}
 function sshFields(){const cmd=hostCommand();if($('dc-ssh-command'))$('dc-ssh-command').value=cmd||'Linux 계정을 입력하면 SSH 명령이 표시됩니다.';const b=document.querySelector('[data-dc-copy=ssh]');if(b)b.disabled=!cmd;}
 function inspector(){
  const node=$('dc-inspector');if(!node||!data)return;
  const rack=data.racks.find(r=>r.id===selectedRack),a=data.assets.find(a=>a.asset_id===selection);
  node.hidden=!rack;$('dc-stage')?.classList.toggle('has-selection',Boolean(rack));if(!rack){node.replaceChildren();return;}
  const list=data.assets.filter(a=>a.rack_id===rack.id);
  const head=`<div class="dc-inspector-heading"><span class="dc-kicker">${a?'DEVICE DETAILS':'RACK INVENTORY'}</span><button class="dc-icon-button" data-dc-close aria-label="장비 패널 닫기">×</button></div>`;
  if(!a){
   node.innerHTML=head+`<h3>${esc(rack.id)}</h3><p class="dc-rack-title">${esc(rack.title)}</p><div class="dc-rack-spec"><span>2F · ${esc(rack.aisle)} 아일</span><span>${list.length}개 장비</span></div><p class="dc-note">장비를 선택하면 상태·설명·접속 방법을 확인할 수 있습니다.</p><div class="dc-rack-list">${list.map(a=>`<button data-dc-asset="${esc(a.asset_id)}"><span><strong>${esc(a.title)}</strong><small>${esc(a.service)}</small></span>${stateBadge(a.health.state)}<span class="dc-row-arrow">›</span></button>`).join('')||'<p class="dc-note">이 랙에 선택 설치된 장비가 없습니다.</p>'}</div>`;
  }else{
   node.innerHTML=head+`<button class="dc-back" data-dc-back>← ${esc(rack.id)} 장비 목록</button><h3>${esc(a.title)}</h3><span class="dc-service-name">${esc(a.service)}</span>${stateBadge(a.health.state)}<p class="dc-device-description">${esc(a.description)}</p><dl class="dc-facts"><div><dt>배치 · 네트워크 존</dt><dd>${esc(rack.id)} · ${a.zones.map(esc).join(' / ')}</dd></div><div><dt>마지막 상태 관측</dt><dd>${esc(date(data.observation.observed_at))}</dd></div></dl>${a.web_console?`<a class="workspace-link dc-console-link" href="${esc(a.web_console)}" ${a.web_console==='/siem/'?'target="_blank" rel="noopener noreferrer"':''}>웹 콘솔 열기 ${icon('arrow')}</a>`:'<p class="dc-note">이 장비에는 별도 웹 콘솔이 없습니다.</p>'}<section class="dc-access-section"><h4>SSH · 장비 셸 접속</h4><p class="dc-note">호스트에 SSH로 접속한 뒤 장비 셸 명령을 실행하세요.</p><div class="dc-ssh-inputs"><label>Linux 계정<input id="dc-ssh-user" value="${esc(sshUser||'')}" placeholder="예: ccc" maxlength="32" autocomplete="off" spellcheck="false"></label><label>SSH 포트<input id="dc-ssh-port" type="number" min="1" max="65535" value="${sshPort}"></label></div><div class="dc-command-head"><span>1. 호스트 SSH</span><button data-dc-copy="ssh">복사</button></div><textarea id="dc-ssh-command" readonly rows="2" aria-label="호스트 SSH 접속 명령"></textarea><div class="dc-command-head"><span>2. ${esc(a.service)} 장비 셸</span><button data-dc-copy="shell">복사</button></div><textarea id="dc-shell-command" readonly rows="4" aria-label="장비 컨테이너 셸 명령">${esc(a.access.shell_command)}</textarea><p class="dc-note">Core 계정과 Linux 계정은 별도입니다. 호스트의 SSH 접속·sudo 권한이 필요합니다.</p></section><details class="dc-id"><summary>자산 식별자</summary><code>${esc(a.asset_id)}</code></details>`;
   $('dc-ssh-user').oninput=e=>{sshUser=e.target.value;sshFields();};$('dc-ssh-port').oninput=e=>{sshPort=Number(e.target.value);sshFields();};sshFields();
  }
 }
 function updateCamera(){if(!camera||!box)return;const cx=box.x+box.width/2,cy=box.y+box.height/2;camera.setAttribute('transform',`translate(${pan.x} ${pan.y}) translate(${cx} ${cy}) scale(${zoom}) translate(${-cx} ${-cy})`);if($('dc-zoom-value'))$('dc-zoom-value').textContent=Math.round(zoom*100)+'%';}
 function scene(){const host=$('dc-scene');if(!host||!host.isConnected||mode==='design'&&designScreen==='workspace')return;const focused=document.activeElement?.closest('[data-dc-rack]')?.dataset.dcRack;const value=DataCenterScene.render(host,data,mode,selectedRack,designFloor);camera=value.world;box=value.box;updateCamera();if(focused)Array.from(host.querySelectorAll('[data-dc-rack]')).find(n=>n.dataset.dcRack===focused)?.focus({preventScroll:true});}
 function render(){
  const focused=document.activeElement,focus=focused?.closest('[data-dc-asset],[data-dc-enter],[data-dc-mode],[data-dc-zoom],[data-dc-rack]');
  const restore=focus?['data-dc-asset','data-dc-enter','data-dc-mode','data-dc-zoom','data-dc-rack'].map(k=>[k,focus.getAttribute(k)]).find(([,v])=>v!==null):null;
  const scroll=$('dc-inspector')?.scrollTop||0;resize?.disconnect();cancelAnimationFrame(resizeFrame);
  let stage=$('dc-stage');if(!stage){$('system-view').innerHTML='<section id="dc-stage" class="dc-stage" aria-label="데이터센터 시각화"></section>';stage=$('dc-stage');}
  const design=mode==='design',floor=data.floors.find(f=>f.id===designFloor),workspace=design&&designScreen==='workspace';
  stage.dataset.mode=mode;stage.dataset.floor=design?designFloor:mode==='floor'?'2F':'';stage.classList.toggle('dc-workspace-design',workspace);stage.classList.toggle('has-selection',Boolean(selectedRack));
  stage.innerHTML=`<header class="dc-header"><div class="dc-heading"><span class="dc-kicker">xOC RANGE / FACILITY EXPLORER</span><h2>${design?esc(designFloor+' · '+floor.title):mode==='building'?'데이터센터 전체 배치':'2F · 일반 전산실'}<span>${design?'DESIGN PREVIEW':mode==='building'?'SPATIAL OPERATIONS':'RACKS & DEVICES'}</span></h2></div><div class="dc-header-right">${design?'<span class="dc-preview-badge">관리자 · 디자인 보기</span>':''}<div class="dc-header-metric"><strong>${data.racks.length}</strong><span>랙</span></div><div class="dc-header-metric"><strong>${data.assets.length}</strong><span>설치 장비</span></div><div class="dc-header-metric"><strong>${data.assets.filter(a=>a.health.state==='running').length}</strong><span>실행 중</span></div><span class="dc-edition"><span></span> COMMUNITY</span></div></header>
  <div class="dc-layout">
  <div class="dc-viewport"><div class="dc-view-tools"><div class="dc-view-switch" role="group" aria-label="공간 보기"><button data-dc-mode="building" aria-pressed="${mode==='building'}">전체 배치</button><button data-dc-mode="floor" aria-pressed="${mode==='floor'}">2층 내부</button>${design?`<button data-dc-design="space" aria-pressed="${!workspace}">공간 디자인</button>${['6F','7F'].includes(designFloor)?`<button data-dc-design="workspace" aria-pressed="${workspace}">화면 구성</button>`:''}`:''}</div><button class="dc-icon-button" data-dc-fullscreen aria-label="전체 화면">⛶</button></div><div id="dc-scene" class="dc-scene ${mode!=='building'?'dc-interior':''}"></div><div class="dc-camera-tools" ${workspace?'hidden':''} role="group" aria-label="시점 조절"><button data-dc-zoom="out" aria-label="축소">−</button><span id="dc-zoom-value"></span><button data-dc-zoom="in" aria-label="확대">+</button><button data-dc-zoom="reset" aria-label="시점 초기화">맞춤</button></div><span class="dc-scene-hint" ${workspace?'hidden':''}>${design?'관리자 디자인 보기':mode==='building'?'2층 선택 → 랙 → 장비':'랙을 선택해 탑재 장비와 접속 정보를 확인하세요'}<small>드래그 이동 · 확대·축소</small></span></div><aside id="dc-inspector" class="dc-inspector" aria-label="랙 및 장비 정보"></aside></div>
  ${mode==='floor'?`<div class="dc-service-dock" aria-label="랙 선택">${data.racks.map(r=>`<button data-dc-rack="${esc(r.id)}" class="dc-service-chip ${selectedRack===r.id?'selected':''}"><strong>${esc(r.id)}</strong> ${esc(r.title)} <span>${r.asset_ids.length}개 장비</span></button>`).join('')}</div>`:''}
  <footer class="dc-status"><span class="dc-observation ${data.observation.fresh?'':'dc-stale'}"><span></span>${data.observation.fresh?'관측 연결 · '+esc(date(data.observation.observed_at)):'관측 지연 · 상태 미확인'}</span><span>컨테이너 상태 · 15초 갱신</span><span class="dc-status-right">xOC RANGE / FACILITY EXPLORER</span></footer>`;
  inspector();if(workspace){$('dc-scene').innerHTML=DataCenterWorkspaces.render(designFloor);}else scene();$('dc-inspector').scrollTop=scroll;
  if(restore)Array.from(stage.querySelectorAll('['+restore[0]+']')).find(n=>n.getAttribute(restore[0])===restore[1])?.focus({preventScroll:true});
  const host=$('dc-scene');let w=host.clientWidth,h=host.clientHeight;
  resize=new ResizeObserver(()=>{if(!host.isConnected||view!=='datacenter'||(host.clientWidth===w&&host.clientHeight===h))return;w=host.clientWidth;h=host.clientHeight;cancelAnimationFrame(resizeFrame);resizeFrame=requestAnimationFrame(scene);});resize.observe(host);
  $('sync-status').textContent='화면 갱신 '+date(data.served_at);
 }
 async function enter(id){
  if(loading||view!=='datacenter')return;
  if(!enabled(data?.floors.find(f=>f.id===id))){if(preview(id))await enterDesign(id);return;}
  const request=++floorRequest;loading=true;const sequence=loadSequence;
  try{const fresh=await api('datacenter/floors/'+encodeURIComponent(id));if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence)return;if(!fresh.allowed_floors.includes(id)||!fresh.floors.find(f=>f.id===id)?.enabled)return;
   data=fresh;mode='floor';selection=null;selectedRack=null;zoom=1;pan={x:0,y:0};render();
  }finally{loading=false;}
 }
 async function enterDesign(id){
  const request=++floorRequest,sequence=loadSequence;loading=true;
  try{const result=await api('datacenter/design/'+encodeURIComponent(id));
   if(view!=='datacenter'||request!==floorRequest||sequence!==loadSequence||result.floor?.id!==id||result.preview_only!==true)return;
   mode='design';designFloor=id;designScreen='space';selectedRack=null;selection=null;reset();render();
  }finally{loading=false;}
 }
 function reset(){zoom=1;pan={x:0,y:0};updateCamera();}
 async function copy(which){const n=$(which==='ssh'?'dc-ssh-command':'dc-shell-command');if(!n||which==='ssh'&&!hostCommand())return;try{await navigator.clipboard.writeText(n.value);notice('접속 명령을 복사했습니다.');}catch{n.focus();n.select();if(document.execCommand('copy'))notice('접속 명령을 복사했습니다.');else notice('명령을 선택했습니다. Ctrl+C로 복사하세요.');}}
 document.addEventListener('click',e=>{
  if(view!=='datacenter'||!data||!e.target.closest('#dc-stage'))return;
  const design=e.target.closest('[data-dc-design]');if(design&&mode==='design'&&preview(designFloor)){designScreen=design.dataset.dcDesign==='workspace'?'workspace':'space';render();return;}
  const floor=e.target.closest('[data-dc-enter],[data-dc-floor]');if(floor){act(()=>enter(floor.dataset.dcEnter||floor.dataset.dcFloor));return;}
  const rack=e.target.closest('[data-dc-rack]');if(rack){if(data.racks.some(r=>r.id===rack.dataset.dcRack)){selectedRack=rack.dataset.dcRack;selection=null;inspector();scene();document.querySelectorAll('.dc-service-chip').forEach(n=>n.classList.toggle('selected',n.dataset.dcRack===selectedRack));$('dc-inspector').scrollIntoView({block:'nearest',behavior:'instant'});}return;}
  const asset=e.target.closest('[data-dc-asset]');if(asset){if(data.assets.some(a=>a.asset_id===asset.dataset.dcAsset&&a.rack_id===selectedRack)){selection=asset.dataset.dcAsset;inspector();$('dc-inspector').scrollTop=0;}return;}
  if(e.target.closest('[data-dc-back]')){selection=null;inspector();return;}
  const change=e.target.closest('[data-dc-mode]');if(change){if(change.dataset.dcMode==='floor')act(()=>enter('2F'));else{floorRequest++;mode='building';selection=null;selectedRack=null;reset();render();}return;}
  const z=e.target.closest('[data-dc-zoom]');if(z){if(z.dataset.dcZoom==='reset')reset();else{zoom=Math.max(.7,Math.min(3.5,zoom+(z.dataset.dcZoom==='in'?.15:-.15)));updateCamera();}return;}
  if(e.target.closest('[data-dc-close]')){selection=null;selectedRack=null;inspector();scene();}
  const c=e.target.closest('[data-dc-copy]');if(c)act(()=>copy(c.dataset.dcCopy));
  if(e.target.closest('[data-dc-fullscreen]'))act(async()=>{if(document.fullscreenElement)await document.exitFullscreen();else await $('dc-stage').requestFullscreen();});
 });
 document.addEventListener('keydown',e=>{if(view!=='datacenter')return;const n=e.target.closest('g[data-dc-floor],g[data-dc-rack]');if(n&&['Enter',' '].includes(e.key)&&n.getAttribute('aria-disabled')!=='true'){e.preventDefault();n.dispatchEvent(new MouseEvent('click',{bubbles:true}));}});
 document.addEventListener('pointerdown',e=>{const host=e.target.closest('#dc-scene');if(!host||e.button!==0||e.target.closest('.commercial-workspace')||e.target.closest('[data-dc-rack],.dc-level-active,.dc-level-preview'))return;drag={x:e.clientX,y:e.clientY,px:pan.x,py:pan.y,host,id:e.pointerId};host.setPointerCapture(e.pointerId);host.classList.add('dc-dragging');});
 document.addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId||!box)return;const factor=box.width/drag.host.clientWidth;pan={x:Math.max(-box.width,Math.min(box.width,drag.px+(e.clientX-drag.x)*factor)),y:Math.max(-box.height,Math.min(box.height,drag.py+(e.clientY-drag.y)*factor))};updateCamera();});
 const end=()=>{if(drag){drag.host.classList.remove('dc-dragging');drag=null;}};document.addEventListener('pointerup',end);document.addEventListener('pointercancel',end);window.addEventListener('blur',end);
 return {get interacting(){return Boolean(drag)||loading||view==='datacenter'&&mode==='design';},async load(sequence){
  if(!session.navigation?.some(p=>p.id==='datacenter')){$('system-view').innerHTML='<div class="panel">'+empty('설치되지 않은 기능','NOC 구성요소를 선택 설치하면 데이터센터를 볼 수 있습니다.')+'</div>';return;}
  const fresh=await api('datacenter');if(sequence!==loadSequence)return;data=fresh;if(sshUser===null)sshUser=data.host_access.username_hint||'';
  if(!data.allowed_floors.includes('2F')||mode==='design'&&!preview(designFloor))mode='building';if(!data.assets.some(a=>a.asset_id===selection))selection=null;if(!data.racks.some(r=>r.id===selectedRack))selectedRack=null;render();
 }};
})();
async function datacenterView(sequence){await DataCenter.load(sequence);}
