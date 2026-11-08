'use strict';
const Academy=(()=>{
 let owner='',course=null,lesson=null,page=0,recordDetail=null;
 function clear(){AcademyNotebook.clear();owner='';course=null;lesson=null;recordDetail=null;}
 function link(cid,lid){return '#academy/lesson/'+cid+'/'+lid;}
 function progress(done,total){return `<progress value="${done}" max="${total}" aria-label="완료 미션 ${done}/${total}"></progress><small>${done} / ${total} 미션</small>`;}
 function artwork(){return `<div class="ac-art" aria-hidden="true"><div class="ac-art-grid"></div><img src="/assets/xoc-range-logo.png" alt=""><span class="ac-art-label">THREAT HUNTING</span><div class="ac-terminal"><span>WAZUH · DISCOVER</span><code><b>rule.level</b> : &gt;=7<br><b>event.outcome</b> : blocked<br><i>▍</i> evidence → insight</code></div><span class="ac-art-mark">01 — 30</span></div>`;}
 function stats(c){return `<div class="ac-stats"><span><b>${c.public_pages}</b> 교재 페이지</span><span><b>${c.lessons}</b> 차시</span><span><b>${c.missions}</b> 실습 항목</span></div>`;}
 function heading(title,extra=''){return `<div class="ac-heading"><div><a class="ac-back" href="#academy">6F / ACADEMY</a><h2>${esc(title)}</h2></div>${extra}</div>`;}
 async function viewPage(sequence){
  if(owner!==session.username){clear();owner=session.username;}
  const parts=location.hash.slice(1).split('/');
  if(parts[1]&&!['course','lesson','history','record','scenarios','scenario'].includes(parts[1])){await libraryView(sequence);return;}
  if(parts[1]==='scenarios'||parts[1]==='scenario'){course=await api('academy/courses/wazuh-threat-hunting');if(sequence!==loadSequence)return;renderTraining(parts[1]==='scenario'?parts[2]:null);return;}
  if(parts[1]==='record'){await recordPage(parts[2],sequence);return;}
  if(parts[1]==='history'){await historyPage(Number(parts[2])||1,sequence);return;}
  if(parts[1]==='lesson'){
   const [c,l]=await Promise.all([api('academy/courses/'+encodeURIComponent(parts[2])),api('academy/lessons/'+encodeURIComponent(parts[2])+'/'+encodeURIComponent(parts[3]))]);
   if(sequence!==loadSequence)return;
   const changed=!lesson||lesson.id!==l.id||lesson.course_id!==l.course_id;course=c;lesson=l;
   if(changed)page=0;
   AcademyNotebook.select(lesson);renderLesson();return;
  }
  if(parts[1]==='course'){
   const c=await api('academy/courses/'+encodeURIComponent(parts[2]));if(sequence!==loadSequence)return;course=c;renderCourse();return;
  }
  const [d,guides]=await Promise.all([api('academy'),api('library')]);if(sequence!==loadSequence)return;
  $('system-view').innerHTML=`<div class="ac-home ac-library-home">${DataCenterWorkspaces.catalog(d)}<details class="ac-guides"><summary>Core 운영 가이드</summary><div class="ac-guide-grid">${guides.articles.map(g=>`<a class="panel" href="#academy/${g.id}"><h4>${esc(g.title)}</h4><p>${esc(g.summary)}</p></a>`).join('')}</div></details></div>`;
  DataCenterWorkspaces.bindCatalog($('system-view'));
  $('sync-status').textContent='아카데미 · 개인 학습 기록';
 }
 function renderCourse(){
  const sections=[...new Set(course.lessons.map(l=>l.section))];const count=course.lessons.reduce((n,l)=>n+l.missions,0),done=course.lessons.reduce((n,l)=>n+l.completed,0);
  $('system-view').innerHTML=`${heading(course.title,`<a class="secondary ac-button" href="#academy/history">나의 실습 기록 ↗</a>`)}<div class="ac-course-banner"><div>${artwork()}</div><div><span class="ac-kicker">CORE BUNDLE / WAZUH</span><h3>${esc(course.subtitle)}</h3><p>${esc(course.description)}</p>${stats({...course,lessons:course.lessons.length,missions:count})}${progress(done,count)}<div class="ac-chip-row"><span class="ac-chip">공개 범위 1–${course.public_pages}p</span><span class="ac-muted">교재 정합성 검토 예정</span></div></div></div>${trainingLinks(course.livefire?.subjects||[],course.livefire?.scenarios||[])}${sections.map(section=>`<section class="ac-course-section"><h3>${esc(section)}</h3><div class="ac-lesson-grid">${course.lessons.filter(l=>l.section===section).map(l=>`<a class="ac-lesson-card" href="${link(course.id,l.id)}"><span class="ac-lesson-symbol">${l.completed===l.missions?'✓':l.id.startsWith('case-')?l.id.slice(-2):'◈'}</span><div><h4>${esc(l.title)}</h4><p>${l.source_pages[0]}–${l.source_pages[1]}p · 설명 · 실습</p>${progress(l.completed,l.missions)}</div><span>↗</span></a>`).join('')}</div></section>`).join('')}`;
  $('sync-status').textContent='번들 v'+course.version+' · 1–339페이지';
 }
 function outline(){return `<aside class="ac-outline"><a class="ac-back" href="#academy/course/${course.id}">← 강좌 전체</a><h3>${esc(course.title)}</h3><nav aria-label="차시 목록">${course.lessons.map((l,i)=>`${i===0||l.section!==course.lessons[i-1].section?'<h4>'+esc(l.section)+'</h4>':''}<a href="${link(course.id,l.id)}" ${l.id===lesson.id?'aria-current="page"':''}><span>${l.completed===l.missions?'✓':String(i+1).padStart(2,'0')}</span><div>${esc(l.title)}<small>${l.source_pages[0]}–${l.source_pages[1]}p</small></div></a>`).join('')}</nav></aside>`;}
 function assetURL(name){return '/core/api/academy/assets/'+lesson.course_id+'/'+name;}
 function slideBlocks(blocks){
  const visible=blocks.filter(b=>b.type!=='text'||!b.text.startsWith('Wazuh 위협 탐지 DQL 예시집'));
  const output=[];
  for(let i=0;i<visible.length;i++){
   const b=visible[i];
   if(b.type==='text'&&(b.text.trim()==='•'||/^\d{1,2}$/.test(b.text.trim()))&&visible[i+1]?.type==='text'){
    const style=b.text.trim()==='•'?'bullet':'number';
    if(output.at(-1)?.type!=='list'||output.at(-1)?.style!==style)output.push({type:'list',style,start:style==='number'?Number(b.text):1,items:[]});
    output.at(-1).items.push(visible[++i].text);
   }else output.push(b);
  }
  const category=output[0]?.type==='text'&&/^(개념 —|웹 위협 ·|리눅스 위협 ·)/.test(output[0].text);
  const title=category?output.splice(1,1)[0]:output.shift();
  return (title?.type==='text'?'<h3 class="ac-slide-title">'+AcademyMarkup.inline(title.text)+'</h3>':textBlocks(title?[title]:[]))+textBlocks(output);
 }
 function textBlocks(blocks){const inline=AcademyMarkup.inline;return blocks.map(b=>{
  if(b.type==='image')return b.asset?`<figure class="ac-figure"><a href="${assetURL(b.asset)}" target="_blank" rel="noopener"><img loading="eager" src="${assetURL(b.asset)}" alt="${esc(b.alt||b.caption||'교재 화면')}"></a>${b.caption?'<figcaption>'+inline(b.caption)+'</figcaption>':''}</figure>`:'';
  if(b.type==='table')return `<div class="ac-table-scroll"><table>${b.head?'<thead><tr>'+b.head.map(h=>'<th>'+inline(h)+'</th>').join('')+'</tr></thead>':''}<tbody>${(b.rows||[]).map(r=>'<tr>'+r.map(v=>'<td>'+inline(v)+'</td>').join('')+'</tr>').join('')}</tbody></table></div>`;
  if(b.type==='list'){const tag=b.style==='number'?'ol':'ul';return '<'+tag+(tag==='ol'&&b.start?' start="'+b.start+'"':'')+'>'+(b.items||[]).map(x=>'<li>'+inline(x)+'</li>').join('')+'</'+tag+'>';}
  if(['code','command','query'].includes(b.type))return `<section class="ac-command">${b.where?'<header><span>'+esc(b.id||'')+'</span><strong>'+inline(b.where)+'</strong></header>':''}${b.purpose?'<p>'+inline(b.purpose)+'</p>':''}<pre class="ac-code"><code>${esc(b.text)}</code></pre>${b.syntax||b.result?'<dl>'+[['syntax','명령 · 검색식 읽기'],['result','예상 결과 · 확인할 점']].filter(([k])=>b[k]).map(([k,t])=>'<dt>'+t+'</dt><dd>'+inline(b[k])+'</dd>').join('')+'</dl>':''}</section>`;
  if(b.type==='h')return '<h4>'+inline(b.text)+'</h4>';
  if(b.type==='box')return '<aside class="ac-callout">'+(b.title?'<strong>'+inline(b.title)+'</strong>':'')+(Array.isArray(b.text)?b.text:[b.text]).map(t=>AcademyMarkup.render(t)).join('')+'</aside>';
  return AcademyMarkup.render(b.text||'');
 }).join('');}
 function renderLesson(){
  const related=lesson.livefire_scenarios||[];
  $('system-view').innerHTML=`<div class="ac-learning ac-unified ac-focus"><section class="ac-workbench"><header class="ac-compact-head"><button class="secondary" data-ac-outline aria-haspopup="dialog">☰ 목차</button><h2>${esc(lesson.title)}</h2><span class="ac-page-range">${lesson.source_pages[0]}–${lesson.source_pages[1]}p</span><div class="ac-compact-links">${related.map(s=>`<a href="#academy/scenario/${s.id}" title="${esc(s.title)}">연계 공방전 ↗</a>`).join('')}<a href="#academy/history">나의 기록</a></div></header><div id="ac-work-area" class="ac-study-grid">${reading()}${AcademyNotebook.render()}</div></section><dialog id="ac-outline-dialog"><header><strong>강좌 목차</strong><button data-ac-outline-close aria-label="목차 닫기">닫기 ×</button></header>${outline()}</dialog></div>`;
  $('sync-status').textContent='교재와 실습 노트';bindForm();AcademyNotebook.bind();
 }
 function reading(){const s=lesson.slides[page];return `<section class="ac-reader"><div class="ac-page-controls"><strong>교재 ${s.page}p</strong><div><button data-ac-page="-1" ${page===0?'disabled':''} aria-label="이전 페이지">←</button><select id="ac-page-select" aria-label="교재 페이지">${lesson.slides.map((s,i)=>`<option value="${i}" ${i===page?'selected':''}>${s.page}p · ${esc(s.title).slice(0,60)}</option>`).join('')}</select><button data-ac-page="1" ${page===lesson.slides.length-1?'disabled':''} aria-label="다음 페이지">→</button></div></div><article class="ac-slide-page">${slideBlocks(s.blocks)}</article><details class="ac-tasks"><summary>이 차시의 실습 안내</summary>${lesson.missions.map(m=>`<h4>${esc(m.title)}</h4><p>${esc(m.instruction)}</p>`).join('')}${lesson.records.length?'<h4>이전 미션 기록</h4>'+lesson.records.map(r=>`<p><a href="#academy/record/${r.id}">${esc(r.title)}</a></p>`).join(''):''}</details><details class="ac-explanation" open><summary>해설 · ${esc(lesson.explanation.title)}</summary>${textBlocks(lesson.explanation.blocks)}</details></section>`;}
 function trainingLinks(subjects,scenarios){return `<section class="ac-training-links"><div class="ac-heading"><div><span class="ac-kicker">7F / LIVE FIRE</span><h3>배운 내용을 공방전으로 연결하기</h3></div><a href="#academy/scenarios">전체 15개 시나리오 ↗</a></div><div class="ac-subject-grid">${subjects.map(subject=>`<a class="ac-subject-card" href="#academy/scenarios/${subject.id}"><span>${subject.id==='xoc-web-defense'?'01':'02'} / COURSE</span><h3>${esc(subject.title)}</h3><p>${esc(subject.subtitle)}</p><strong>${scenarios.filter(s=>s.category===subject.id).length}개 시나리오 · Red / Blue / Purple ↗</strong></a>`).join('')}</div></section>`;}
 function markdown(text){return AcademyMarkup.render(text);}
 function renderTraining(id=null,mid=null){
  const data=course.livefire,s=data.scenarios.find(s=>s.id===id);
  if(!s){const selected=location.hash.split('/')[2];$('system-view').innerHTML=`${heading('Live Fire · 공방전 콘텐츠','<a class="secondary ac-button" href="#datacenter">데이터센터 ↗</a>')}${trainingLinks(data.subjects,data.scenarios)}${data.subjects.filter(x=>!selected||selected===x.id).map(subject=>`<section class="ac-course-section"><h3>${esc(subject.title)}</h3><div class="ac-scenario-grid">${data.scenarios.filter(s=>s.category===subject.id).map(s=>`<a class="ac-scenario-card" href="#academy/scenario/${s.id}"><span class="ac-kicker">${s.id.toUpperCase()}</span><h3>${esc(s.title)}</h3><p>${esc(s.briefing.story)}</p><div><span>7개 미션 · 100점</span><strong>RED · BLUE · PURPLE</strong></div></a>`).join('')}</div></section>`).join('')}`;return;}
  const m=s.missions.find(m=>m.id===mid)||s.missions[0];
  $('system-view').innerHTML=`${heading(s.title,'<a class="secondary ac-button" href="#academy/scenarios">시나리오 전체</a>')}<div class="ac-range-brief"><span class="ac-chip">LIVE FIRE · 콘텐츠 미리보기</span><p>${esc(s.briefing.story)}</p><div class="ac-linked-lessons">${s.academy.lessons.map(id=>`<a href="${link(course.id,id)}">${esc(course.lessons.find(l=>l.id===id).title)} ↗</a>`).join('')}</div></div><div class="ac-range-grid"><nav class="ac-range-missions" aria-label="공방전 미션">${['red','blue','purple'].map(role=>`<h3 class="team-${role}">${role.toUpperCase()} TEAM <small>${role==='red'?'공격':role==='blue'?'대응':'해석 · 보고'}</small></h3>${s.missions.filter(m=>m.learning_role===role).map(m=>`<button data-ac-training="${m.id}" data-ac-scenario="${s.id}" aria-current="${m.id===(mid||s.missions[0].id)?'step':'false'}" class="${m.id===(mid||s.missions[0].id)?'selected':''}"><span>${esc(m.title.replace(/^[A-Z]+ · /,''))}</span><b>${m.points}점</b></button>`).join('')}`).join('')}</nav><article class="ac-range-mission team-${m.learning_role}"><div class="ac-mission-meta"><strong>${m.learning_role.toUpperCase()} TEAM</strong><span>${m.points}점 · 제출 1개</span></div>${markdown(m.instruction)}<label class="ac-single-answer"><strong>${esc(m.submission.label)}</strong><textarea rows="5" disabled placeholder="${esc(m.submission.placeholder)}"></textarea></label><div class="ac-range-actions"><span>Live Fire 훈련 엔진 연결 예정</span><button class="primary" disabled>답안 제출 · AI 평가</button></div></article></div>`;
  $('sync-status').textContent='교재 연계 · 1개 미션 / 1개 입력';
 }
 function redrawReader(){document.querySelector('.ac-reader').outerHTML=reading();bindForm();}
 function bindForm(){
  if($('ac-page-select'))$('ac-page-select').onchange=e=>{page=Number(e.target.value);redrawReader();};
 }
 async function historyPage(page,sequence){const d=await api('academy/history/'+page);if(sequence!==loadSequence)return;
  $('system-view').innerHTML=`${heading('나의 실습 기록')}<div class="panel ac-history"><div class="toolbar"><strong>저장한 기록 ${d.count}건</strong><span class="ac-muted">${esc(session.username)}</span></div>${d.records.length?`<div class="ac-table-scroll"><table><thead><tr><th>실습 노트 · 기록</th><th>상태</th><th>버전</th><th>마지막 저장</th><th></th></tr></thead><tbody>${d.records.map(r=>`<tr><td><a href="#academy/record/${r.id}">${esc(r.title)}</a></td><td><span class="ac-chip ${r.status==='complete'?'ac-complete':''}">${r.status==='complete'?'기록 완료':'임시 저장'}</span></td><td>v${r.revision}</td><td>${date(r.updated_at)}</td><td><a href="#academy/record/${r.id}">기록 열기 ↗</a></td></tr>`).join('')}</tbody></table></div>`:empty('첫 실습 기록을 남겨 보세요','차시별 실습 노트와 이전 미션 기록을 확인할 수 있습니다.','<a class="primary ac-button" href="#academy">강좌 찾기</a>')}<div class="ac-pagination">${page>1?`<a href="#academy/history/${page-1}">← 이전</a>`:''}<span>${page} / ${Math.max(1,Math.ceil(d.count/20))}</span>${page*20<d.count?`<a href="#academy/history/${page+1}">다음 →</a>`:''}</div></div>`;$('sync-status').textContent='내 계정의 저장 기록';
 }
 async function recordPage(rid,sequence){const r=await api('academy/records/'+encodeURIComponent(rid));if(sequence!==loadSequence)return;recordDetail=r;renderRecord(r);}
 function renderRecord(r,snapshot=null,version=null){const v=snapshot||r;const images=snapshot?r.images.filter(i=>snapshot.images.includes(i.id)):r.images;
  $('system-view').innerHTML=`${heading('나의 실습 기록',`<a class="secondary ac-button" href="#academy/history">전체 기록</a>`)}<article class="panel ac-record-detail"><header><span class="ac-kicker">${v.status==='complete'?'기록 완료':'임시 저장'} · v${version||r.revision} · ${date(r.updated_at)}</span><h2>${esc(r.title)}</h2><div class="ac-chip-row"><a class="secondary ac-button" href="${link(r.course,r.lesson)}${r.scope==='lesson'?'':'/'+r.mission}">실습 이어쓰기 ↗</a><button data-ac-export class="secondary">기록 내보내기</button><select id="ac-version" aria-label="기록 버전">${[{number:r.revision,at:r.updated_at},...r.versions.filter(v=>v.number!==r.revision)].map(v=>`<option value="${v.number}" ${(version||r.revision)===v.number?'selected':''}>v${v.number} · ${date(v.at)}</option>`).join('')}</select></div></header>${r.scope==='lesson'?AcademyNotebook.read(r,snapshot):''}${[['input','내가 입력한 것'],['output','출력 · 결과'],['interpretation','나의 해석']].filter(([k])=>r.scope!=='lesson'&&(v[k]||k==='output'&&images.length)).map(([k,label])=>`<section><h3>${label}</h3><pre class="ac-saved-text">${esc(v[k]||'—')}</pre>${k==='output'?'<div class="ac-evidence-list">'+images.map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption)}"></a><figcaption>${esc(i.caption)}</figcaption></figure>`).join('')+'</div>':''}</section>`).join('')}</article>`;
  $('ac-version').onchange=e=>act(async()=>{if(Number(e.target.value)===r.revision){renderRecord(r);return;}const v=await api('academy/records/'+r.id+'/revisions/'+Number(e.target.value));renderRecord(r,v.snapshot,v.number);});$('sync-status').textContent='DB 저장 기록 · 교재 v'+r.content_version;
 }
 document.addEventListener('click',e=>{
  const training=e.target.closest('[data-ac-training]');if(training){renderTraining(training.dataset.acScenario,training.dataset.acTraining);return;}
  if(e.target.closest('[data-ac-outline]')){$('ac-outline-dialog').showModal();return;}
  if(e.target.closest('[data-ac-outline-close]')){$('ac-outline-dialog').close();return;}
  const b=e.target.closest('[data-ac-page],[data-ac-source],[data-ac-export]');if(!b)return;
  if(b.dataset.acPage){page=Math.max(0,Math.min(lesson.slides.length-1,page+Number(b.dataset.acPage)));redrawReader();}
  else if(b.dataset.acSource){page=lesson.slides.findIndex(s=>s.page===Number(b.dataset.acSource));redrawReader();}
  else if(b.hasAttribute('data-ac-export')){const url=URL.createObjectURL(new Blob([JSON.stringify(recordDetail,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='xoc-record-'+recordDetail.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 });
 return {view:viewPage,clear};
})();
