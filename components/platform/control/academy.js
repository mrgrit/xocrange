'use strict';
const Academy=(()=>{
 let owner='',course=null,lesson=null,mode='explain',page=0,mission=0,dirty=false,recordDetail=null;
 const drafts=new Map();
 function clear(){owner='';course=null;lesson=null;recordDetail=null;drafts.clear();dirty=false;}
 function key(m){return lesson.course_id+'/'+lesson.id+'/'+m.id;}
 function draft(){const m=lesson.missions[mission],k=key(m);if(!drafts.has(k)){const r=lesson.records.find(r=>r.mission===m.id);drafts.set(k,{record:r||null,input:r?.input||'',output:r?.output||'',interpretation:r?.interpretation||'',dirty:false});}return drafts.get(k);}
 function remember(){if(!lesson||!$('ac-input'))return;const d=draft();let changed=false;for(const k of ['input','output','interpretation']){const v=$('ac-'+k).value;if(d[k]!==v)changed=true;d[k]=v;}if(!changed)return;d.dirty=true;dirty=true;if($('ac-save-status'))$('ac-save-status').textContent='저장되지 않은 변경';}
 function link(cid,lid){return '#academy/lesson/'+cid+'/'+lid;}
 function progress(done,total){return `<progress value="${done}" max="${total}" aria-label="완료 미션 ${done}/${total}"></progress><small>${done} / ${total} 미션</small>`;}
 function artwork(){return `<div class="ac-art" aria-hidden="true"><div class="ac-art-grid"></div><img src="/assets/xoc-range-logo.png" alt=""><span class="ac-art-label">THREAT HUNTING</span><div class="ac-terminal"><span>WAZUH · DISCOVER</span><code><b>rule.level</b> : &gt;=7<br><b>event.outcome</b> : blocked<br><i>▍</i> evidence → insight</code></div><span class="ac-art-mark">01 — 30</span></div>`;}
 function stats(c){return `<div class="ac-stats"><span><b>${c.public_pages}</b> 교재 페이지</span><span><b>${c.lessons}</b> 차시</span><span><b>${c.missions}</b> 기록 미션</span></div>`;}
 function heading(title,extra=''){return `<div class="ac-heading"><div><a class="ac-back" href="#academy">ACADEMY / CORE</a><h2>${esc(title)}</h2></div>${extra}</div>`;}
 async function viewPage(sequence){
  if(owner!==session.username){clear();owner=session.username;}
  const parts=location.hash.slice(1).split('/');
  if(parts[1]&&!['course','lesson','history','record'].includes(parts[1])){await libraryView(sequence);return;}
  if(parts[1]==='record'){await recordPage(parts[2],sequence);return;}
  if(parts[1]==='history'){await historyPage(Number(parts[2])||1,sequence);return;}
  if(parts[1]==='lesson'){
   const [c,l]=await Promise.all([api('academy/courses/'+encodeURIComponent(parts[2])),api('academy/lessons/'+encodeURIComponent(parts[2])+'/'+encodeURIComponent(parts[3]))]);
   if(sequence!==loadSequence)return;
   const changed=!lesson||lesson.id!==l.id||lesson.course_id!==l.course_id;course=c;lesson=l;
   if(changed){page=0;mission=0;mode='explain';}
   if(parts[4]){const target=l.missions.findIndex(m=>m.id===parts[4]);if(target>=0){mission=target;mode='practice';}}
   renderLesson();return;
  }
  if(parts[1]==='course'){
   const c=await api('academy/courses/'+encodeURIComponent(parts[2]));if(sequence!==loadSequence)return;course=c;renderCourse();return;
  }
  const [d,guides]=await Promise.all([api('academy'),api('library')]);if(sequence!==loadSequence)return;
  $('system-view').innerHTML=`<div class="ac-home">${heading('아카데미',`<a class="secondary ac-button" href="#academy/history">나의 실습 기록 <b>${d.history_count}</b></a>`)}<div class="ac-intro"><span class="ac-kicker">LEARN · INVESTIGATE · RECORD</span><h3>교재에서 실습으로, 실습에서 분석으로</h3><p>교재와 해설을 읽고, 미션마다 입력 · 결과 · 나의 해석을 기록합니다.</p></div><div class="ac-course-grid">${d.courses.map(c=>`<a class="ac-course-card" href="#academy/course/${c.id}">${artwork()}<div class="ac-course-copy"><div class="ac-chip-row"><span class="ac-chip">CORE 번들</span><span class="ac-muted">웹 · 리눅스</span></div><h3>${esc(c.title)}</h3><p>${esc(c.description)}</p>${stats(c)}<div class="ac-card-bottom"><div>${progress(c.completed,c.missions)}</div><strong>${c.records?'학습 이어가기':'강좌 열기'} ↗</strong></div></div></a>`).join('')}</div><section class="ac-guides"><div class="ac-heading"><h3>Core 운영 가이드</h3><span class="ac-muted">장비와 운영 화면 익히기</span></div><div class="ac-guide-grid">${guides.articles.map((g,i)=>`<a class="panel" href="#academy/${g.id}"><span class="ac-guide-number">0${i+1}</span><h4>${esc(g.title)}</h4><p>${esc(g.summary)}</p><small>약 ${g.minutes}분 →</small></a>`).join('')}</div></section></div>`;
  $('sync-status').textContent='아카데미 · 개인 학습 기록';
 }
 function renderCourse(){
  const sections=[...new Set(course.lessons.map(l=>l.section))];const count=course.lessons.reduce((n,l)=>n+l.missions,0),done=course.lessons.reduce((n,l)=>n+l.completed,0);
  $('system-view').innerHTML=`${heading(course.title,`<a class="secondary ac-button" href="#academy/history">나의 실습 기록 ↗</a>`)}<div class="ac-course-banner"><div>${artwork()}</div><div><span class="ac-kicker">CORE BUNDLE / WAZUH</span><h3>${esc(course.subtitle)}</h3><p>${esc(course.description)}</p>${stats({...course,lessons:course.lessons.length,missions:count})}${progress(done,count)}<div class="ac-chip-row"><span class="ac-chip">공개 범위 1–${course.public_pages}p</span><span class="ac-muted">교재 정합성 검토 예정</span></div></div></div>${sections.map(section=>`<section class="ac-course-section"><h3>${esc(section)}</h3><div class="ac-lesson-grid">${course.lessons.filter(l=>l.section===section).map(l=>`<a class="ac-lesson-card" href="${link(course.id,l.id)}"><span class="ac-lesson-symbol">${l.completed===l.missions?'✓':l.id.startsWith('case-')?l.id.slice(-2):'◈'}</span><div><h4>${esc(l.title)}</h4><p>${l.source_pages[0]}–${l.source_pages[1]}p · 설명 · 실습</p>${progress(l.completed,l.missions)}</div><span>↗</span></a>`).join('')}</div></section>`).join('')}`;
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
  $('system-view').innerHTML=`<div class="ac-learning">${outline()}<section class="ac-workbench"><header class="ac-lesson-header"><span class="ac-kicker">${esc(course.subtitle)} / ${lesson.source_pages[0]}–${lesson.source_pages[1]}p</span><h2>${esc(lesson.title)}</h2><div class="ac-mode-tabs" role="tablist" aria-label="학습 영역"><button data-ac-mode="explain" role="tab" aria-selected="${mode==='explain'}">설명 <small>교재 · 해설</small></button><button data-ac-mode="practice" role="tab" aria-selected="${mode==='practice'}">실습 <small>입력 · 결과 · 나의 해석</small></button><a href="#academy/history">나의 기록 ↗</a></div></header><div id="ac-work-area">${mode==='explain'?reading():practice()}</div></section></div>`;
  $('sync-status').textContent='학습 기록은 현재 로그인한 계정에 저장됩니다.';bindForm();
 }
 function reading(){const s=lesson.slides[page];return `<div class="ac-reading-grid"><section class="ac-slides"><div class="ac-page-controls"><strong>교재 <span>${s.page}p</span></strong><div><button data-ac-page="-1" ${page===0?'disabled':''} aria-label="이전 페이지">←</button><select id="ac-page-select" aria-label="교재 페이지">${lesson.slides.map((s,i)=>`<option value="${i}" ${i===page?'selected':''}>${s.page}p · ${esc(s.title).slice(0,60)}</option>`).join('')}</select><button data-ac-page="1" ${page===lesson.slides.length-1?'disabled':''} aria-label="다음 페이지">→</button></div></div><article class="ac-slide-page">${slideBlocks(s.blocks)}</article><div class="ac-reading-next"><span>${page+1} / ${lesson.slides.length} 페이지</span><button class="primary" data-ac-mode="practice">실습 기록하기 →</button></div></section><aside class="ac-explanation"><div class="ac-explanation-label">해설 <span>REV01</span></div><h3>${esc(lesson.explanation.title)}</h3>${textBlocks(lesson.explanation.blocks)}</aside></div>`;}
 function practice(){const d=draft(),m=lesson.missions[mission];return `<div class="ac-practice"><div class="ac-missions" role="tablist" aria-label="미션 선택">${lesson.missions.map((m,i)=>`<button data-ac-mission="${i}" role="tab" aria-selected="${i===mission}"><span>0${i+1}</span>${esc(m.title)}</button>`).join('')}</div><div class="ac-mission-brief"><span class="ac-kicker">MISSION ${String(mission+1).padStart(2,'0')}</span><h3>${esc(m.title)}</h3><p>${esc(m.instruction)}</p><div class="ac-chip-row">${m.source_pages.map(p=>`<button class="ac-page-chip" data-ac-source="${p}">교재 ${p}p ↗</button>`).join('')}<span class="ac-muted">${d.record?'기록 v'+d.record.revision:'새 기록'}</span></div></div><form id="ac-form"><fieldset id="ac-fields"><div class="ac-record-grid"><label><strong><span>01</span> 내가 입력한 것</strong><small>명령, 검색식, 실행 위치와 시각을 적으세요.</small><textarea id="ac-input" maxlength="24000" rows="8" spellcheck="false" placeholder="실행한 명령 또는 DQL 검색식">${esc(d.input)}</textarea></label><label><strong><span>02</span> 출력 · 결과</strong><small>결과 텍스트를 붙여넣거나 아래에 화면을 첨부하세요.</small><textarea id="ac-output" maxlength="24000" rows="8" spellcheck="false" placeholder="터미널 출력, 로그, 검색 결과">${esc(d.output)}</textarea></label></div><div class="ac-evidence-box" id="ac-paste" tabindex="0" aria-label="캡처 붙여넣기 영역"><div><strong>캡처 붙여넣기</strong><span>이 영역을 클릭한 뒤 Ctrl+V · 미션당 최대 3장</span></div><label class="secondary ac-upload">이미지 선택<input id="ac-file" type="file" accept="image/png,image/jpeg,image/webp" multiple></label></div><div class="ac-evidence-list">${(d.record?.images||[]).map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption||'저장한 실습 캡처')}"></a><figcaption>${esc(i.caption||'실습 캡처')} · ${i.width}×${i.height}</figcaption></figure>`).join('')}</div><label class="ac-interpretation"><strong><span>03</span> 나의 해석</strong><small>무엇을 확인했나요? 판단의 근거와 다음에 확인할 내용을 적으세요.</small><textarea id="ac-interpretation" maxlength="24000" rows="6" placeholder="탐지 사실과 실제 결과를 나누어 기록하세요.">${esc(d.interpretation)}</textarea></label><div class="ac-save-bar"><span id="ac-save-status">${d.dirty?'저장되지 않은 변경':d.record?'저장됨 · '+date(d.record.updated_at):'아직 저장한 기록이 없습니다.'}</span><div>${d.record?'<button type="button" class="quiet" data-ac-new>새 시도</button>':''}<button type="button" class="secondary" data-ac-save="draft">임시 저장</button><button type="button" class="primary" data-ac-save="complete">미션 기록 완료</button></div></div></fieldset></form><div class="ac-ai-boundary"><span>${icon('lock')} AI 채점 · 분석 · 피드백</span><span class="ac-chip">Live Fire</span></div></div>`;}
 function bindForm(){
  for(const k of ['input','output','interpretation'])if($('ac-'+k))$('ac-'+k).oninput=remember;
  if($('ac-form'))$('ac-form').onsubmit=e=>e.preventDefault();
  if($('ac-page-select'))$('ac-page-select').onchange=e=>{page=Number(e.target.value);renderLesson();};
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
  $('system-view').innerHTML=`${heading('나의 실습 기록')}<div class="panel ac-history"><div class="toolbar"><strong>저장한 기록 ${d.count}건</strong><span class="ac-muted">${esc(session.username)}</span></div>${d.records.length?`<div class="ac-table-scroll"><table><thead><tr><th>미션</th><th>상태</th><th>버전</th><th>마지막 저장</th><th></th></tr></thead><tbody>${d.records.map(r=>`<tr><td><a href="#academy/record/${r.id}">${esc(r.title)}</a></td><td><span class="ac-chip ${r.status==='complete'?'ac-complete':''}">${r.status==='complete'?'기록 완료':'임시 저장'}</span></td><td>v${r.revision}</td><td>${date(r.updated_at)}</td><td><a href="#academy/record/${r.id}">기록 열기 ↗</a></td></tr>`).join('')}</tbody></table></div>`:empty('첫 실습 기록을 남겨 보세요','강좌에서 미션을 열고 입력 · 결과 · 나의 해석을 저장하면 여기에 모입니다.','<a class="primary ac-button" href="#academy">강좌 찾기</a>')}<div class="ac-pagination">${page>1?`<a href="#academy/history/${page-1}">← 이전</a>`:''}<span>${page} / ${Math.max(1,Math.ceil(d.count/20))}</span>${page*20<d.count?`<a href="#academy/history/${page+1}">다음 →</a>`:''}</div></div>`;$('sync-status').textContent='내 계정의 저장 기록';
 }
 async function recordPage(rid,sequence){const r=await api('academy/records/'+encodeURIComponent(rid));if(sequence!==loadSequence)return;recordDetail=r;renderRecord(r);}
 function renderRecord(r,snapshot=null,version=null){const v=snapshot||r;const images=snapshot?r.images.filter(i=>snapshot.images.includes(i.id)):r.images;
  $('system-view').innerHTML=`${heading('나의 실습 기록',`<a class="secondary ac-button" href="#academy/history">전체 기록</a>`)}<article class="panel ac-record-detail"><header><span class="ac-kicker">${v.status==='complete'?'기록 완료':'임시 저장'} · v${version||r.revision} · ${date(r.updated_at)}</span><h2>${esc(r.title)}</h2><div class="ac-chip-row"><a class="secondary ac-button" href="${link(r.course,r.lesson)}/${r.mission}">같은 미션 열기 ↗</a><button data-ac-export class="secondary">기록 내보내기</button><select id="ac-version" aria-label="기록 버전">${r.versions.map(v=>`<option value="${v.number}" ${(version||r.revision)===v.number?'selected':''}>v${v.number} · ${date(v.at)}</option>`).join('')}</select></div></header>${[['input','01 · 내가 입력한 것'],['output','02 · 출력 · 결과'],['interpretation','03 · 나의 해석']].map(([k,label])=>`<section><h3>${label}</h3><pre class="ac-saved-text">${esc(v[k]||'—')}</pre>${k==='output'?'<div class="ac-evidence-list">'+images.map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption)}"></a><figcaption>${esc(i.caption)}</figcaption></figure>`).join('')+'</div>':''}</section>`).join('')}</article>`;
  $('ac-version').onchange=e=>act(async()=>{const v=await api('academy/records/'+r.id+'/revisions/'+Number(e.target.value));renderRecord(r,v.snapshot,v.number);});$('sync-status').textContent='DB 저장 기록 · 교재 v'+r.content_version;
 }
 document.addEventListener('click',e=>{const b=e.target.closest('[data-ac-mode],[data-ac-page],[data-ac-source],[data-ac-mission],[data-ac-save],[data-ac-new],[data-ac-export]');if(!b||busy)return;
  act(async()=>{
   if(b.dataset.acMode){remember();mode=b.dataset.acMode;renderLesson();}
   else if(b.dataset.acPage){page=Math.max(0,Math.min(lesson.slides.length-1,page+Number(b.dataset.acPage)));renderLesson();}
   else if(b.dataset.acSource){remember();page=lesson.slides.findIndex(s=>s.page===Number(b.dataset.acSource));mode='explain';renderLesson();}
   else if(b.dataset.acMission){remember();mission=Number(b.dataset.acMission);renderLesson();}
   else if(b.dataset.acSave){busy=true;$('ac-fields').disabled=true;try{await save(b.dataset.acSave);}finally{busy=false;if($('ac-fields'))$('ac-fields').disabled=false;}}
   else if(b.hasAttribute('data-ac-new')){if(draft().dirty)await save('draft',false);drafts.set(key(lesson.missions[mission]),{record:null,input:'',output:'',interpretation:'',dirty:false});renderLesson();}
   else if(b.hasAttribute('data-ac-export')){const url=URL.createObjectURL(new Blob([JSON.stringify(recordDetail,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='xoc-mission-'+recordDetail.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  });
 });
 document.addEventListener('paste',e=>{if(view!=='academy'||mode!=='practice'||busy||!e.target.closest('#ac-form'))return;const files=[...e.clipboardData.items].filter(i=>i.kind==='file'&&i.type.startsWith('image/')).map(i=>i.getAsFile());if(files.length){e.preventDefault();act(()=>upload(files));}});
 window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
 return {view:viewPage,clear};
})();
