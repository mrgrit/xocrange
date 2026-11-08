/* Administrator design surfaces. Interaction stays local; no mission execution or paid data. */
'use strict';
window.DataCenterWorkspaces=(()=>{
 const courses=[
  ['보안 운영','SOC & DEFENSE','방어·관제','방화벽 · IPS · WAF · SIEM','shield'],
  ['위협 헌팅','THREAT HUNTING','방어·관제','이벤트 분석 · 탐지 · 대응','radar'],
  ['웹 애플리케이션 보안','WEB SECURITY','웹·인프라','취약점 이해 · 검증 · 방어','web'],
  ['공격과 방어','RED / BLUE','공격·대응','공격 경로 · 탐지 근거 · 방어 정책','target'],
  ['클라우드 · 컨테이너','CLOUD SECURITY','웹·인프라','워크로드 · 구성 · 런타임','cloud'],
  ['AI 에이전트 보안','AI SECURITY','AI·보안','에이전트 · 도구 · 가드레일','nodes']
 ];
 const scenarios=[['경계 침입 대응','네트워크 · 탐지 · 차단','침입 흔적 분석','차단 정책 수립','정상 서비스 검증'],['웹 서비스 방어','웹 공격 · WAF · 로그','공격 요청 분석','웹 방어 정책 수립','차단 근거 검증'],['통합 보안 관제','SIEM · 상관분석 · 대응','경보 분류','공격 경로 추적','대응 결과 검증']];
 let filter='전체',query='',selected=null,scenario=0,mission=0,mode='SOLO',role='BLUE',board='전체';
 const paths={shield:'M32 7 52 15V30C52 43 43 52 32 57 21 52 12 43 12 30V15Z M22 31 29 38 43 24',radar:'M32 8A24 24 0 1 0 56 32 M32 19A13 13 0 1 0 45 32 M32 32 52 12 M32 5V12 M5 32H12 M32 52V59 M52 32H59',web:'M9 13H55V51H9Z M9 24H55 M18 18H19 M25 18H26 M26 33 20 39 26 45 M38 33 44 39 38 45',target:'M32 8A24 24 0 1 0 32 56A24 24 0 1 0 32 8 M32 20A12 12 0 1 0 32 44A12 12 0 1 0 32 20 M32 2V15 M32 49V62 M2 32H15 M49 32H62',cloud:'M17 43C2 43 3 24 17 24 20 7 46 9 48 26 62 25 62 43 48 43Z M23 51V58 M32 43V59 M41 51V58',nodes:'M32 15 13 44H51Z M32 7A8 8 0 1 0 32 23A8 8 0 1 0 32 7 M13 36A8 8 0 1 0 13 52A8 8 0 1 0 13 36 M51 36A8 8 0 1 0 51 52A8 8 0 1 0 51 36'};
 const art=(kind,label)=>`<div class="cw-cover cw-${kind}"><span>${esc(label)}</span><svg viewBox="0 0 64 64" aria-hidden="true"><path d="${paths[kind]}"/></svg><i></i><b>xOC ACADEMY</b></div>`;
 function academy(){
  if(selected!==null){const c=courses[selected];return `<div class="cw-heading"><div><span class="cw-eyebrow">CONTENT DETAIL</span><h2>${esc(c[0])}</h2><p>${esc(c[3])}</p></div><button data-cw-back>← 카탈로그</button></div><div class="cw-content-detail">${art(c[4],c[1])}<section class="cw-panel"><h3>콘텐츠 구성</h3><p class="cw-muted">학습 목표와 수록 자료를 확인하고 원하는 단원을 선택합니다.</p><div class="cw-tabs">${['강의','실습','워크북'].map((t,i)=>`<button data-cw-unit="${t}" aria-pressed="${i===0}">${t}</button>`).join('')}</div><div class="cw-unit"><span class="cw-eyebrow">LEARNING CONTENT</span><h3 id="cw-unit-title">강의</h3><dl><dt>학습 목표</dt><dd>${esc(c[3])}</dd><dt>구성</dt><dd>단원 목록 · 콘텐츠 뷰어 · 학습 진척도</dd><dt>이용 범위</dt><dd>기관에서 구매한 콘텐츠</dd></dl></div></section></div>`;}
  return `<div class="cw-heading"><div><span class="cw-eyebrow">ACADEMY / CONTENT LIBRARY</span><h2>콘텐츠 카탈로그</h2><p>기관 콘텐츠 · 강의, 실습, 워크북을 한곳에서</p></div><label class="cw-search">콘텐츠 검색<input id="cw-search" type="search" placeholder="제목·주제 검색" value="${esc(query)}"></label></div><div class="cw-tabs">${['전체','방어·관제','공격·대응','웹·인프라','AI·보안'].map(f=>`<button data-cw-filter="${esc(f)}" aria-pressed="${filter===f}">${f}</button>`).join('')}</div><div id="cw-catalog" class="cw-catalog">${cards()}</div>`;
 }
 function cards(){return courses.map((c,i)=>({c,i})).filter(({c})=>(filter==='전체'||filter===c[2])&&c.join(' ').toLowerCase().includes(query.toLowerCase())).map(({c,i})=>`<button class="cw-content-card" data-cw-content="${i}">${art(c[4],c[1])}<div class="cw-card-copy"><span>${esc(c[2])}</span><h3>${esc(c[0])}</h3><p>${esc(c[3])}</p><footer><span>강의 · 실습 · 워크북</span><strong>콘텐츠 열기 ↗</strong></footer></div></button>`).join('')||'<p class="cw-empty">검색 결과가 없습니다.</p>';}
 function live(){const s=scenarios[scenario];return `<div class="cw-heading"><div><span class="cw-eyebrow">LIVE FIRE / CYBER COMBAT RANGE</span><h2>사이버보안을 전투기 조종사처럼 훈련한다</h2><p>시나리오 선택 → 미션 수행 → 근거 확인 → AI 피드백</p></div><div class="cw-mode">${['SOLO','DUEL','FFA'].map(m=>`<button data-cw-mode="${m}" aria-pressed="${mode===m}">${m}</button>`).join('')}</div></div>
  <div class="cw-flight-grid"><section class="cw-panel cw-scenarios"><span class="cw-eyebrow">01 / BRIEFING</span><h3>시나리오 선택</h3>${scenarios.map((s,i)=>`<button data-cw-scenario="${i}" class="cw-scenario ${i===scenario?'selected':''}"><span>0${i+1}</span><div><strong>${s[0]}</strong><small>${s[1]}</small></div></button>`).join('')}<div class="cw-role">${['RED','BLUE'].map(r=>`<button data-cw-role="${r}" aria-pressed="${role===r}">${r==='RED'?'RED · 공격':'BLUE · 방어'}</button>`).join('')}</div><p class="cw-muted">${mode==='SOLO'?'1인 훈련 · Red / Blue 전환':mode==='DUEL'?'1:1 공방전 · 상대 역할 매칭':'자율 공방전 · 참가자별 미션'}</p></section>
  <section class="cw-panel cw-mission"><span class="cw-eyebrow">02 / MISSION CONTROL</span><div class="cw-mission-title"><h3>${s[0]}</h3><span class="cw-role-label">${role}</span></div><div class="cw-mission-steps">${s.slice(2).map((t,i)=>`<button data-cw-mission="${i}" aria-pressed="${mission===i}"><span>0${i+1}</span>${t}</button>`).join('')}</div><div class="cw-objective"><span class="cw-eyebrow">MISSION 0${mission+1}</span><h3>${s[mission+2]}</h3><dl><dt>목표</dt><dd>미션 지시문과 대상 환경 확인</dd><dt>성공 조건</dt><dd>검증 항목 · 배점 · 제출 근거</dd><dt>수행 공간</dt><dd>터미널 · 보안 장비 · 이벤트 타임라인</dd></dl></div><div class="cw-mission-actions"><button disabled>훈련 시작</button><button disabled>근거 제출</button><button disabled>힌트</button></div></section>
  <aside class="cw-pilot"><section class="cw-panel"><span class="cw-eyebrow">OPERATOR PROFILE</span><h3>나의 레벨</h3><div class="cw-level"><strong>Lv. —</strong><span>경험치 — / —</span></div><div class="cw-progress-track"></div><p class="cw-muted">미션 완료와 검증된 성과를 반영</p></section><section class="cw-panel"><span class="cw-eyebrow">TRAINING PROGRESS</span><h3>과정별 진척도</h3>${['보안 운영','웹 서비스 방어','통합 보안 관제'].map(t=>`<div class="cw-course-progress"><span>${t}</span><small>— / —</small><div class="cw-progress-track"></div></div>`).join('')}</section></aside>
  <section class="cw-panel cw-leaderboard"><span class="cw-eyebrow">AFTER ACTION / RANKING</span><h3>전체 리더보드</h3><div class="cw-tabs">${['전체','과정별','배틀별'].map(t=>`<button data-cw-board="${t}" aria-pressed="${board===t}">${t}</button>`).join('')}</div><table><thead><tr><th>순위</th><th>훈련생</th><th>RED</th><th>BLUE</th><th>총점</th></tr></thead><tbody><tr><td colspan="5">훈련 기록을 기다리고 있습니다.</td></tr></tbody></table></section>
  <section class="cw-panel cw-feedback"><span class="cw-eyebrow">03 / AI DEBRIEF</span><h3>AI 피드백</h3><div class="cw-feedback-grid">${['수행 근거','잘한 점','개선할 점','다음 훈련'].map(t=>`<div><strong>${t}</strong><p>—</p></div>`).join('')}</div><p class="cw-muted">활동 타임라인 · 채점 근거 · 과정별 진척도</p></section></div>`;}
 function render(floor){return `<div class="commercial-workspace" data-workspace-floor="${floor}"><div class="cw-design-label">상용 화면 구성 · 디자인 샘플${floor==='6F'&&session.navigation?.some(n=>n.id==='academy')?'<a class="cw-core-bundle" href="#academy">Core 번들 · 시스템 침투와 SIEM 분석 열기 ↗</a>':''}</div>${floor==='6F'?academy():live()}</div>`;}
 function repaint(){const host=document.querySelector('.commercial-workspace');if(host)host.outerHTML=render(host.dataset.workspaceFloor);}
 document.addEventListener('input',e=>{if(e.target.id==='cw-search'){query=e.target.value;document.getElementById('cw-catalog').innerHTML=cards();}});
 document.addEventListener('click',e=>{const b=e.target.closest('.commercial-workspace button');if(!b)return;
  if(b.hasAttribute('data-cw-content'))selected=Number(b.dataset.cwContent);
  else if(b.hasAttribute('data-cw-back'))selected=null;
  else if(b.hasAttribute('data-cw-filter'))filter=b.dataset.cwFilter;
  else if(b.hasAttribute('data-cw-scenario')){scenario=Number(b.dataset.cwScenario);mission=0;}
  else if(b.hasAttribute('data-cw-mission'))mission=Number(b.dataset.cwMission);
  else if(b.hasAttribute('data-cw-mode'))mode=b.dataset.cwMode;
  else if(b.hasAttribute('data-cw-role'))role=b.dataset.cwRole;
  else if(b.hasAttribute('data-cw-board'))board=b.dataset.cwBoard;
  else if(b.hasAttribute('data-cw-unit')){document.querySelectorAll('[data-cw-unit]').forEach(n=>n.setAttribute('aria-pressed',String(n===b)));document.getElementById('cw-unit-title').textContent=b.dataset.cwUnit;return;}
  else return;const focus=[...b.attributes].find(a=>a.name.startsWith('data-cw-'));repaint();if(focus){const target=Array.from(document.querySelectorAll('.commercial-workspace button')).find(n=>n.getAttribute(focus.name)===focus.value);(target||document.querySelector('.commercial-workspace button'))?.focus({preventScroll:true});}
 });
 return {render};
})();
