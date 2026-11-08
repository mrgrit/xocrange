/* Free content library and read-only commercial scenario catalog. */
'use strict';
window.DataCenterWorkspaces=(()=>{
 let generation=0;
 function catalog(d){
  const items=d.offerings||[],categories=[...new Set(items.map(c=>c.category))];
  return `<section class="academy-library" aria-label="아카데미 콘텐츠 카탈로그"><header class="al-header"><div><span class="cw-eyebrow">6F / ACADEMY CONTENT LIBRARY</span><h2>콘텐츠 카탈로그</h2><p>관심 있는 콘텐츠를 선택하세요.</p></div><a href="#academy/history" class="al-history">내 학습 기록 ↗</a></header><div class="al-controls"><label class="al-search"><span>검색</span><input data-al-search type="search" placeholder="콘텐츠 이름으로 검색" aria-label="콘텐츠 검색"></label><select data-al-category aria-label="콘텐츠 분야"><option value="">전체 분야</option>${categories.map(c=>`<option>${esc(c)}</option>`).join('')}</select><button data-al-available aria-pressed="false">이용 가능한 콘텐츠</button><span class="al-count"><b data-al-count>${items.length}</b>개 콘텐츠 · 이용 가능 ${items.filter(c=>c.available).length}</span></div><div class="al-grid">${items.map((c,i)=>{
   const tag=c.available?'a':'article',attrs=c.available?`href="${esc(c.route)}"`:'aria-disabled="true"';
   return `<${tag} ${attrs} class="al-card ${c.available?'is-available':'is-unavailable'}" data-al-title="${esc(c.title.toLowerCase())}" data-al-category-value="${esc(c.category)}" data-al-enabled="${c.available}" data-al-id="${esc(c.id)}"><div class="al-cover al-palette-${categories.indexOf(c.category)%5}"><div class="al-cover-grid"></div><span class="al-mark">${esc(c.mark)}</span><img src="/assets/xoc-range-logo.png" alt="" loading="lazy"><span class="al-category">${esc(c.category)}</span></div><div class="al-copy"><div class="al-card-meta"><span>${c.available?esc(c.source):'ACADEMY'}</span><span class="al-availability">${c.available?'이용 가능':'미설치'}</span></div><h3>${esc(c.title)}</h3><footer>${c.available?'콘텐츠 열기 ↗':'—'}</footer></div></${tag}>`;
  }).join('')}</div><p class="al-empty" hidden>검색 조건에 맞는 콘텐츠가 없습니다.</p></section>`;
 }
 function bindCatalog(host=document){
  const library=host.querySelector('.academy-library');if(!library)return;
  const query=library.querySelector('[data-al-search]'),category=library.querySelector('[data-al-category]'),available=library.querySelector('[data-al-available]');
  const filter=()=>{let count=0;for(const card of library.querySelectorAll('.al-card')){const shown=card.dataset.alTitle.includes(query.value.trim().toLowerCase())&&(!category.value||card.dataset.alCategoryValue===category.value)&&(available.getAttribute('aria-pressed')!=='true'||card.dataset.alEnabled==='true');card.hidden=!shown;if(shown)count++;}library.querySelector('[data-al-count]').textContent=count;library.querySelector('.al-empty').hidden=count!==0;};
  query.oninput=filter;category.onchange=filter;available.onclick=()=>{available.setAttribute('aria-pressed',String(available.getAttribute('aria-pressed')!=='true'));filter();};
 }
 function render(floor){return `<div class="commercial-workspace ${floor==='6F'?'cw-academy-display':''}" data-workspace-floor="${floor}">${floor==='6F'?'':`<div class="cw-heading"><div><span class="cw-eyebrow">LIVE FIRE / CYBER COMBAT RANGE</span><h2>공방전 시나리오</h2><p>Red 공격 · Blue 대응 · Purple 분석과 보고</p></div></div>`}<div id="cw-connected-catalog" class="${floor==='6F'?'cw-library-host':'cw-catalog'}">콘텐츠를 불러오는 중…</div></div>`;}
 async function hydrate(floor){
  const sequence=++generation,host=document.getElementById('cw-connected-catalog');if(!host)return;
  if(!session.navigation?.some(n=>n.id==='academy')){host.textContent='아카데미 모듈을 선택 설치하면 콘텐츠를 볼 수 있습니다.';return;}
  const d=await api('academy');if(sequence!==generation||!host.isConnected)return;
  if(floor==='6F'){host.innerHTML=catalog(d);bindCatalog(host);}
  else host.innerHTML=d.scenarios.map(s=>`<a class="cw-content-card cw-real-card" href="#academy/scenario/${s.id}"><div class="cw-card-copy"><span>${s.category==='xoc-web-defense'?'웹 침해 대응':'리눅스·네트워크 침해 대응'}</span><h3>${esc(s.title)}</h3><p>Red 35 · Blue 45 · Purple 20</p><footer><span>${s.missions}개 미션 · ${s.total_points}점</span><strong>미션 보기 ↗</strong></footer></div></a>`).join('');
 }
 async function snapshot(){return api('academy');}
 return {render,hydrate,snapshot,catalog,bindCatalog};
})();
