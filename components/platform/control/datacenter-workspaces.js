/* Connected free catalog and read-only commercial content previews. */
'use strict';
window.DataCenterWorkspaces=(()=>{
 let generation=0;
 function render(floor){return `<div class="commercial-workspace" data-workspace-floor="${floor}"><div class="cw-heading"><div><span class="cw-eyebrow">${floor==='6F'?'ACADEMY / CONTENT LIBRARY':'LIVE FIRE / CYBER COMBAT RANGE'}</span><h2>${floor==='6F'?'교재에서 실습으로':'Red · Blue · Purple 공방전'}</h2><p>${floor==='6F'?'강좌를 읽고 연결된 미션과 공방전을 엽니다.':'웹 8개 · 리눅스와 네트워크 7개 · 미션마다 제출 하나'}</p></div></div><div id="cw-connected-catalog" class="cw-catalog">콘텐츠를 불러오는 중…</div></div>`;}
 async function hydrate(floor){const sequence=++generation,host=document.getElementById('cw-connected-catalog');if(!host)return;
  if(!session.navigation?.some(n=>n.id==='academy')){host.textContent='아카데미 모듈을 선택 설치하면 콘텐츠를 볼 수 있습니다.';return;}
  const d=await api('academy');if(sequence!==generation||!host.isConnected)return;
  if(floor==='6F'){host.innerHTML=d.courses.map(c=>`<a class="cw-content-card cw-real-card" href="#academy/course/${c.id}"><div class="cw-card-copy"><span>CORE / ${c.public_pages}p · ${c.lessons}개 차시</span><h3>${esc(c.title)}</h3><p>${esc(c.description)}</p><footer><span>교재 + 미션</span><strong>강좌 열기 ↗</strong></footer></div></a>`).join('')+`<a class="cw-content-card cw-real-card" href="#academy/scenarios"><div class="cw-card-copy"><span>LIVE FIRE</span><h3>연계 공방전 15개</h3><p>2개 과목 · Red 공격, Blue 대응, Purple 분석·보고</p><footer><strong>시나리오 보기 ↗</strong></footer></div></a>`;}
  else host.innerHTML=d.scenarios.map(s=>`<a class="cw-content-card cw-real-card" href="#academy/scenario/${s.id}"><div class="cw-card-copy"><span>${s.category==='xoc-web-defense'?'웹 침해 대응':'리눅스·네트워크 침해 대응'}</span><h3>${esc(s.title)}</h3><p>Red 35 · Blue 45 · Purple 20</p><footer><span>7개 미션 · 100점</span><strong>미션 보기 ↗</strong></footer></div></a>`).join('');
 }
 async function snapshot(){return api('academy');}
 return {render,hydrate,snapshot};
})();
