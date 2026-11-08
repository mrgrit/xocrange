'use strict';
const Academy=(()=>{
 let owner='',course=null,lesson=null,page=0,mission=0,dirty=false,recordDetail=null;
 const drafts=new Map();
 function clear(){owner='';course=null;lesson=null;recordDetail=null;drafts.clear();dirty=false;}
 function key(m){return lesson.course_id+'/'+lesson.id+'/'+m.id;}
 function draft(){const m=lesson.missions[mission],k=key(m);if(!drafts.has(k)){const r=lesson.records.find(r=>r.mission===m.id);drafts.set(k,{record:r||null,input:r?.input||'',output:r?.output||'',interpretation:r?.interpretation||'',dirty:false});}return drafts.get(k);}
 function remember(){if(!lesson||!$('ac-form'))return;const d=draft();let changed=false;for(const k of ['input','output','interpretation']){const node=$('ac-'+k);if(!node)continue;const v=node.value;if(d[k]!==v)changed=true;d[k]=v;}if(!changed)return;d.dirty=true;dirty=true;if($('ac-save-status'))$('ac-save-status').textContent='저장되지 않은 변경';}
 function link(cid,lid){return '#academy/lesson/'+cid+'/'+lid;}
 function progress(done,total){return `<progress value="${done}" max="${total}" aria-label="완료 미션 ${done}/${total}"></progress><small>${done} / ${total} 미션</small>`;}
 function artwork(){return `<div class="ac-art" aria-hidden="true"><div class="ac-art-grid"></div><img src="/assets/xoc-range-logo.png" alt=""><span class="ac-art-label">THREAT HUNTING</span><div class="ac-terminal"><span>WAZUH · DISCOVER</span><code><b>rule.level</b> : &gt;=7<br><b>event.outcome</b> : blocked<br><i>▍</i> evidence → insight</code></div><span class="ac-art-mark">01 — 30</span></div>`;}
 function stats(c){return `<div class="ac-stats"><span><b>${c.public_pages}</b> 교재 페이지</span><span><b>${c.lessons}</b> 차시</span><span><b>${c.missions}</b> 기록 미션</span></div>`;}
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
   if(changed){page=0;mission=0;}
   if(parts[4]){const target=l.missions.findIndex(m=>m.id===parts[4]);if(target>=0){mission=target;}}
   renderLesson();return;
  }
  if(parts[1]==='course'){
   const c=await api('academy/courses/'+encodeURIComponent(parts[2]));if(sequence!==loadSequence)return;course=c;renderCourse();return;
  }
  const [d,guides]=await Promise.all([api('academy'),api('library')]);if(sequence!==loadSequence)return;
  $('system-view').innerHTML=`<div class="ac-home">${heading('6F · 아카데미',`<a class="secondary ac-button" href="#academy/history">나의 실습 기록 <b>${d.history_count}</b></a>`)}<div class="ac-intro"><span class="ac-kicker">LEARN · INVESTIGATE · RECORD</span><h3>교재에서 실습으로, 실습에서 분석으로</h3><p>교재와 미션을 나란히 보며 답 하나씩 기록하고, 연결된 공방전에서 Red · Blue · Purple 역할을 익힙니다.</p></div><div class="ac-course-grid">${d.courses.map(c=>`<a class="ac-course-card" href="#academy/course/${c.id}">${artwork()}<div class="ac-course-copy"><div class="ac-chip-row"><span class="ac-chip">CORE 번들</span><span class="ac-muted">웹 · 리눅스</span></div><h3>${esc(c.title)}</h3><p>${esc(c.description)}</p>${stats(c)}<div class="ac-card-bottom"><div>${progress(c.completed,c.missions)}</div><strong>${c.records?'학습 이어가기':'강좌 열기'} ↗</strong></div></div></a>`).join('')}</div>${trainingLinks(d.subjects,d.scenarios)}<section class="ac-guides"><div class="ac-heading"><h3>Core 운영 가이드</h3><span class="ac-muted">장비와 운영 화면 익히기</span></div><div class="ac-guide-grid">${guides.articles.map((g,i)=>`<a class="panel" href="#academy/${g.id}"><span class="ac-guide-number">0${i+1}</span><h4>${esc(g.title)}</h4><p>${esc(g.summary)}</p><small>약 ${g.minutes}분 →</small></a>`).join('')}</div></section></div>`;
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
   if(b.type==='text'&&b.text.trim()==='•'&&visible[i+1]?.type==='text'){
    if(output.at(-1)?.type!=='list')output.push({type:'list',items:[]});
    output.at(-1).items.push(visible[++i].text);
   }else output.push(b);
  }
  const category=output[0]?.type==='text'&&/^(개념 —|웹 위협 ·|리눅스 위협 ·)/.test(output[0].text);
  const title=category?output.splice(1,1)[0]:output.shift();
  return (title?.type==='text'?'<h3 class="ac-slide-title">'+esc(title.text)+'</h3>':textBlocks(title?[title]:[]))+textBlocks(output);
 }
 function textBlocks(blocks){return blocks.map(b=>{
  if(b.type==='image')return b.asset?`<figure><a href="${assetURL(b.asset)}" target="_blank" rel="noopener"><img loading="lazy" src="${assetURL(b.asset)}" alt="${esc(b.alt||b.caption||'교재 화면')}"></a>${b.caption?'<figcaption>'+esc(b.caption)+'</figcaption>':''}</figure>`:'';
  if(b.type==='table')return `<div class="ac-table-scroll"><table>${b.head?'<thead><tr>'+b.head.map(h=>'<th>'+esc(h)+'</th>').join('')+'</tr></thead>':''}<tbody>${(b.rows||[]).map(r=>'<tr>'+r.map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>').join('')}</tbody></table></div>`;
  if(b.type==='list')return '<ul>'+(b.items||[]).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>';
  if(b.type==='code')return '<pre class="ac-code">'+esc(b.text)+'</pre>';
  if(b.type==='h')return '<h4>'+esc(b.text)+'</h4>';
  if(b.type==='box')return '<div class="ac-callout">'+(Array.isArray(b.text)?b.text:[b.text]).map(t=>'<p>'+esc(t)+'</p>').join('')+'</div>';
  return '<p class="ac-text">'+esc(b.text||'')+'</p>';
 }).join('');}
 function renderLesson(){
  const related=lesson.livefire_scenarios||[];
  $('system-view').innerHTML=`<div class="ac-learning ac-unified">${outline()}<section class="ac-workbench"><header class="ac-lesson-header"><span class="ac-kicker">6F ACADEMY / ${lesson.source_pages[0]}–${lesson.source_pages[1]}p</span><h2>${esc(lesson.title)}</h2><div class="ac-lesson-tools"><span>읽으며 한 단계씩 기록하기</span><a href="#academy/history">나의 기록 ↗</a></div></header><div class="ac-linked-range">${related.map(s=>`<a href="#academy/scenario/${s.id}"><span>연계 공방전</span><strong>${esc(s.title)}</strong><small>RED → BLUE → PURPLE ↗</small></a>`).join('')}</div><div id="ac-work-area" class="ac-study-grid">${reading()}${practice()}</div></section></div>`;
  $('sync-status').textContent='교재 · 해설 · 미션을 한 화면에서';bindForm();
 }
 function reading(){const s=lesson.slides[page];return `<section class="ac-reader"><div class="ac-page-controls"><strong>교재 ${s.page}p</strong><div><button data-ac-page="-1" ${page===0?'disabled':''} aria-label="이전 페이지">←</button><select id="ac-page-select" aria-label="교재 페이지">${lesson.slides.map((s,i)=>`<option value="${i}" ${i===page?'selected':''}>${s.page}p · ${esc(s.title).slice(0,60)}</option>`).join('')}</select><button data-ac-page="1" ${page===lesson.slides.length-1?'disabled':''} aria-label="다음 페이지">→</button></div></div><article class="ac-slide-page">${slideBlocks(s.blocks)}</article><details class="ac-explanation" open><summary>해설 · ${esc(lesson.explanation.title)}</summary>${textBlocks(lesson.explanation.blocks)}</details></section>`;}
 function practice(){const d=draft(),m=lesson.missions[mission],field=m.response_field||'input';return `<section class="ac-practice"><div class="ac-practice-heading"><span class="ac-kicker">GUIDED PRACTICE</span><strong>미션 ${mission+1} / ${lesson.missions.length}</strong></div><div class="ac-missions" role="tablist" aria-label="미션 선택">${lesson.missions.map((m,i)=>`<button data-ac-mission="${i}" role="tab" aria-selected="${i===mission}"><span>${String(i+1).padStart(2,'0')}</span>${esc(m.response_field==='input'?'명령':m.response_field==='output'?'증거':'해석')}</button>`).join('')}</div><div class="ac-mission-brief"><h3>${esc(m.title)}</h3><p>${esc(m.instruction)}</p><div class="ac-chip-row">${m.source_pages.map(p=>`<button class="ac-page-chip" data-ac-source="${p}">교재 ${p}p 보기</button>`).join('')}</div></div><form id="ac-form"><fieldset id="ac-fields"><label class="ac-single-answer"><strong>${esc(m.response_label||'이번 미션의 답')}</strong><textarea id="ac-${field}" maxlength="24000" rows="9" spellcheck="false" placeholder="${esc(m.response_label||'답을 입력하세요')}">${esc(d[field])}</textarea></label>${field==='output'?`<div class="ac-evidence-box" id="ac-paste" tabindex="0" aria-label="캡처 붙여넣기 영역"><div><strong>캡처로 대신 기록하기</strong><span>이 영역에서 Ctrl+V</span></div><label class="secondary ac-upload">이미지 선택<input id="ac-file" type="file" accept="image/png,image/jpeg,image/webp"></label></div><div class="ac-evidence-list">${(d.record?.images||[]).map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption||'실습 캡처')}"></a></figure>`).join('')}</div>`:''}<div class="ac-save-bar"><span id="ac-save-status">${d.dirty?'저장되지 않은 변경':d.record?'저장됨 · '+date(d.record.updated_at):'아직 저장하지 않았습니다.'}</span><div>${d.record?'<button type="button" class="secondary" data-ac-new>새 시도</button>':''}<button type="button" class="secondary" data-ac-save="draft">임시 저장</button><button type="button" class="primary" data-ac-save="complete">기록 완료</button></div></div></fieldset></form><p class="ac-practice-note">한 미션에 답 하나. 다음 미션에서 다음 단계를 기록합니다.</p></section>`;}
 function trainingLinks(subjects,scenarios){return `<section class="ac-training-links"><div class="ac-heading"><div><span class="ac-kicker">7F / LIVE FIRE</span><h3>배운 내용을 공방전으로 연결하기</h3></div><a href="#academy/scenarios">전체 15개 시나리오 ↗</a></div><div class="ac-subject-grid">${subjects.map(subject=>`<a class="ac-subject-card" href="#academy/scenarios/${subject.id}"><span>${subject.id==='xoc-web-defense'?'01':'02'} / COURSE</span><h3>${esc(subject.title)}</h3><p>${esc(subject.subtitle)}</p><strong>${scenarios.filter(s=>s.category===subject.id).length}개 시나리오 · Red / Blue / Purple ↗</strong></a>`).join('')}</div></section>`;}
 function markdown(text){
  const chunks=text.split(/```[^\n]*\n([\s\S]*?)```/g);
  const inline=t=>esc(t).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  return chunks.map((chunk,i)=>i%2?'<pre class="ac-code">'+esc(chunk)+'</pre>':chunk.split('\n').map(line=>/^###? /.test(line)?'<h4>'+inline(line.replace(/^#+ /,''))+'</h4>':line?'<p>'+inline(line)+'</p>':'').join('')).join('');
 }
 function renderTraining(id=null,mid=null){
  const data=course.livefire,s=data.scenarios.find(s=>s.id===id);
  if(!s){const selected=location.hash.split('/')[2];$('system-view').innerHTML=`${heading('Live Fire · 공방전 콘텐츠','<a class="secondary ac-button" href="#datacenter">데이터센터 ↗</a>')}${trainingLinks(data.subjects,data.scenarios)}${data.subjects.filter(x=>!selected||selected===x.id).map(subject=>`<section class="ac-course-section"><h3>${esc(subject.title)}</h3><div class="ac-scenario-grid">${data.scenarios.filter(s=>s.category===subject.id).map(s=>`<a class="ac-scenario-card" href="#academy/scenario/${s.id}"><span class="ac-kicker">${s.id.toUpperCase()}</span><h3>${esc(s.title)}</h3><p>${esc(s.briefing.story)}</p><div><span>7개 미션 · 100점</span><strong>RED · BLUE · PURPLE</strong></div></a>`).join('')}</div></section>`).join('')}`;return;}
  const m=s.missions.find(m=>m.id===mid)||s.missions[0];
  $('system-view').innerHTML=`${heading(s.title,'<a class="secondary ac-button" href="#academy/scenarios">시나리오 전체</a>')}<div class="ac-range-brief"><span class="ac-chip">LIVE FIRE · 콘텐츠 미리보기</span><p>${esc(s.briefing.story)}</p><div class="ac-linked-lessons">${s.academy.lessons.map(id=>`<a href="${link(course.id,id)}">${esc(course.lessons.find(l=>l.id===id).title)} ↗</a>`).join('')}</div></div><div class="ac-range-grid"><nav class="ac-range-missions" aria-label="공방전 미션">${['red','blue','purple'].map(role=>`<h3 class="team-${role}">${role.toUpperCase()} TEAM <small>${role==='red'?'공격':role==='blue'?'대응':'해석 · 보고'}</small></h3>${s.missions.filter(m=>m.learning_role===role).map(m=>`<button data-ac-training="${m.id}" data-ac-scenario="${s.id}" aria-current="${m.id===(mid||s.missions[0].id)?'step':'false'}" class="${m.id===(mid||s.missions[0].id)?'selected':''}"><span>${esc(m.title.replace(/^[A-Z]+ · /,''))}</span><b>${m.points}점</b></button>`).join('')}`).join('')}</nav><article class="ac-range-mission team-${m.learning_role}"><div class="ac-mission-meta"><strong>${m.learning_role.toUpperCase()} TEAM</strong><span>${m.points}점 · 제출 1개</span></div>${markdown(m.instruction)}<label class="ac-single-answer"><strong>${esc(m.submission.label)}</strong><textarea rows="5" disabled placeholder="${esc(m.submission.placeholder)}"></textarea></label><div class="ac-range-actions"><span>Live Fire 훈련 엔진 연결 예정</span><button class="primary" disabled>답안 제출 · AI 평가</button></div></article></div>`;
  $('sync-status').textContent='교재 연계 · 1개 미션 / 1개 입력';
 }
 function bindForm(){
  for(const k of ['input','output','interpretation'])if($('ac-'+k))$('ac-'+k).oninput=remember;
  if($('ac-form'))$('ac-form').onsubmit=e=>e.preventDefault();
  if($('ac-page-select'))$('ac-page-select').onchange=e=>{remember();page=Number(e.target.value);renderLesson();};
  if($('ac-file'))$('ac-file').onchange=e=>act(()=>upload([...e.target.files]));
 }
 async function save(status='draft',redraw=true){
  remember();const d=draft(),m=lesson.missions[mission],cid=lesson.course_id,lid=lesson.id;
  const payload={course:cid,lesson:lid,mission:m.id,input:d.input,output:d.output,interpretation:d.interpretation,status,revision:d.record?.revision||0};
  const r=await api('academy/records'+(d.record?'/'+d.record.id:''),payload);d.record=r;d.dirty=false;dirty=[...drafts.values()].some(d=>d.dirty);
  const known=lesson.records.findIndex(x=>x.mission===m.id);if(known>=0)lesson.records[known]=r;else lesson.records.push(r);
  if(redraw&&lesson.course_id===cid&&lesson.id===lid){renderLesson();notice(status==='complete'?'미션 기록을 완료했습니다.':'실습 기록을 저장했습니다.');}return r;
 }
 async function encode(file){
  if(!['image/png','image/jpeg','image/webp'].includes(file.type)||file.size>10*1024*1024)throw new Error('PNG, JPG, WebP 이미지(10 MiB 이하)를 선택해 주세요.');
  const bitmap=await createImageBitmap(file);if(bitmap.width*bitmap.height>40000000){bitmap.close();throw new Error('이미지가 너무 큽니다. 필요한 영역만 캡처해 주세요.');}
  const scale=Math.min(1,2200/Math.max(bitmap.width,bitmap.height));const canvas=document.createElement('canvas');canvas.width=Math.round(bitmap.width*scale);canvas.height=Math.round(bitmap.height*scale);canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);bitmap.close();
  let blob;for(const quality of [.9,.78,.62,.45]){blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/webp',quality));if(blob&&blob.size<=512*1024)break;}
  if(!blob||blob.size>512*1024)throw new Error('캡처 범위를 줄여 다시 붙여넣어 주세요.');
  return await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(r.result);r.onerror=reject;r.readAsDataURL(blob);});
 }
 async function upload(files){
  if(!files.length)return;const d=draft();if((d.record?.images.length||0)+files.length>3)throw new Error('미션 기록 한 건에 캡처를 최대 3장 저장할 수 있습니다. 새 시도를 만들면 별도로 기록할 수 있습니다.');
  busy=true;if($('ac-fields'))$('ac-fields').disabled=true;
  try{await save('draft',false);for(const file of files){const encoded=await encode(file);d.record=await api('academy/records/'+d.record.id+'/images',{image:encoded,caption:'실습 캡처',revision:d.record.revision});}renderLesson();notice('캡처와 실습 기록을 DB에 저장했습니다.');}finally{busy=false;if($('ac-fields'))$('ac-fields').disabled=false;}
 }
 async function historyPage(page,sequence){const d=await api('academy/history/'+page);if(sequence!==loadSequence)return;
  $('system-view').innerHTML=`${heading('나의 실습 기록')}<div class="panel ac-history"><div class="toolbar"><strong>저장한 기록 ${d.count}건</strong><span class="ac-muted">${esc(session.username)}</span></div>${d.records.length?`<div class="ac-table-scroll"><table><thead><tr><th>미션</th><th>상태</th><th>버전</th><th>마지막 저장</th><th></th></tr></thead><tbody>${d.records.map(r=>`<tr><td><a href="#academy/record/${r.id}">${esc(r.title)}</a></td><td><span class="ac-chip ${r.status==='complete'?'ac-complete':''}">${r.status==='complete'?'기록 완료':'임시 저장'}</span></td><td>v${r.revision}</td><td>${date(r.updated_at)}</td><td><a href="#academy/record/${r.id}">기록 열기 ↗</a></td></tr>`).join('')}</tbody></table></div>`:empty('첫 실습 기록을 남겨 보세요','강좌에서 미션의 답을 저장하면 여기에 모입니다.','<a class="primary ac-button" href="#academy">강좌 찾기</a>')}<div class="ac-pagination">${page>1?`<a href="#academy/history/${page-1}">← 이전</a>`:''}<span>${page} / ${Math.max(1,Math.ceil(d.count/20))}</span>${page*20<d.count?`<a href="#academy/history/${page+1}">다음 →</a>`:''}</div></div>`;$('sync-status').textContent='내 계정의 저장 기록';
 }
 async function recordPage(rid,sequence){const r=await api('academy/records/'+encodeURIComponent(rid));if(sequence!==loadSequence)return;recordDetail=r;renderRecord(r);}
 function renderRecord(r,snapshot=null,version=null){const v=snapshot||r;const images=snapshot?r.images.filter(i=>snapshot.images.includes(i.id)):r.images;
  $('system-view').innerHTML=`${heading('나의 실습 기록',`<a class="secondary ac-button" href="#academy/history">전체 기록</a>`)}<article class="panel ac-record-detail"><header><span class="ac-kicker">${v.status==='complete'?'기록 완료':'임시 저장'} · v${version||r.revision} · ${date(r.updated_at)}</span><h2>${esc(r.title)}</h2><div class="ac-chip-row"><a class="secondary ac-button" href="${link(r.course,r.lesson)}/${r.mission}">같은 미션 열기 ↗</a><button data-ac-export class="secondary">기록 내보내기</button><select id="ac-version" aria-label="기록 버전">${r.versions.map(v=>`<option value="${v.number}" ${(version||r.revision)===v.number?'selected':''}>v${v.number} · ${date(v.at)}</option>`).join('')}</select></div></header>${[['input','내가 입력한 것'],['output','출력 · 결과'],['interpretation','나의 해석']].filter(([k])=>v[k]||k==='output'&&images.length).map(([k,label])=>`<section><h3>${label}</h3><pre class="ac-saved-text">${esc(v[k]||'—')}</pre>${k==='output'?'<div class="ac-evidence-list">'+images.map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption)}"></a><figcaption>${esc(i.caption)}</figcaption></figure>`).join('')+'</div>':''}</section>`).join('')}</article>`;
  $('ac-version').onchange=e=>act(async()=>{const v=await api('academy/records/'+r.id+'/revisions/'+Number(e.target.value));renderRecord(r,v.snapshot,v.number);});$('sync-status').textContent='DB 저장 기록 · 교재 v'+r.content_version;
 }
 document.addEventListener('click',e=>{const training=e.target.closest('[data-ac-training]');if(training){renderTraining(training.dataset.acScenario,training.dataset.acTraining);return;}const b=e.target.closest('[data-ac-page],[data-ac-source],[data-ac-mission],[data-ac-save],[data-ac-new],[data-ac-export]');if(!b||busy)return;
  act(async()=>{
   if(b.dataset.acPage){remember();page=Math.max(0,Math.min(lesson.slides.length-1,page+Number(b.dataset.acPage)));renderLesson();}
   else if(b.dataset.acSource){remember();page=lesson.slides.findIndex(s=>s.page===Number(b.dataset.acSource));renderLesson();}
   else if(b.dataset.acMission){remember();mission=Number(b.dataset.acMission);renderLesson();}
   else if(b.dataset.acSave){busy=true;$('ac-fields').disabled=true;try{await save(b.dataset.acSave);}finally{busy=false;if($('ac-fields'))$('ac-fields').disabled=false;}}
   else if(b.hasAttribute('data-ac-new')){if(draft().dirty)await save('draft',false);drafts.set(key(lesson.missions[mission]),{record:null,input:'',output:'',interpretation:'',dirty:false});renderLesson();}
   else if(b.hasAttribute('data-ac-export')){const url=URL.createObjectURL(new Blob([JSON.stringify(recordDetail,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='xoc-mission-'+recordDetail.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  });
 });
 document.addEventListener('paste',e=>{if(view!=='academy'||busy||!$('ac-paste')||!e.target.closest('#ac-form'))return;const files=[...e.clipboardData.items].filter(i=>i.kind==='file'&&i.type.startsWith('image/')).map(i=>i.getAsFile());if(files.length){e.preventDefault();act(()=>upload(files));}});
 window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
 return {view:viewPage,clear};
})();
