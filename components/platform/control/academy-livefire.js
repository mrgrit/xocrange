/* Owner-scoped three-part mission reports. Registration stores a revision; grading is separate. */
'use strict';
const LiveFireReport=(()=>{
 const drafts=new Map(),fields=[['input','학습자 시도'],['output','시스템 반응'],['interpretation','학습자의 해석']];
 let current=null,epoch=0;
 function clear(){epoch++;for(const d of drafts.values())clearTimeout(d.timer);drafts.clear();current=null;}
 function key(cid,sid,mid){return [cid,sid,mid].join('/');}
 async function select(course,scenario,mission,sequence){
  const generation=epoch,rows=await api('academy/scenarios/'+course.id+'/'+scenario.id+'/records');
  if(generation!==epoch||sequence!==loadSequence)return false;
  for(const m of scenario.missions){
   const k=key(course.id,scenario.id,m.id),r=rows.records.find(r=>r.mission===m.id)||null;
   if(!drafts.has(k))drafts.set(k,{key:k,cid:course.id,sid:scenario.id,mid:m.id,record:r,values:Object.fromEntries(fields.map(([f])=>[f,r?.[f]||''])),dirty:false,pending:0,error:'',chain:Promise.resolve()});
   else{const d=drafts.get(k);if(!d.dirty&&!d.pending&&r&&r.revision!==d.record?.revision){d.record=r;d.values=Object.fromEntries(fields.map(([f])=>[f,r[f]]));}}
  }
  current=drafts.get(key(course.id,scenario.id,mission.id));return true;
 }
 function dirty(){return [...drafts.values()].some(d=>d.dirty||d.pending);}
 function mark(cid,sid,mid){const d=drafts.get(key(cid,sid,mid));return d?.dirty?'작성 중':d?.record?.status==='complete'?'등록됨':d?.record?'임시 저장':'미작성';}
 function status(d){
  if(d!==current||!$('lf-status'))return;
  $('lf-status').textContent=d.error?'저장 실패 · '+d.error:d.pending?'저장 중…':d.dirty?'변경됨 · 자동 저장 대기':d.record?(d.record.status==='complete'?'등록됨':'임시 저장됨')+' · '+date(d.record.updated_at):'작성하면 자동으로 임시 저장됩니다.';
  $('lf-status').classList.toggle('nb-error',!!d.error);$('lf-status').setAttribute('role',d.error?'alert':'status');
  const saved=$('lf-record-link');saved.hidden=!d.record;if(d.record)saved.href='#academy/record/'+d.record.id;
  document.querySelectorAll('[data-lf-progress]').forEach(n=>{n.textContent=mark(d.cid,d.sid,n.dataset.lfProgress);});
 }
 function failure(d,e){d.error=e.message;status(d);}
 function queue(d,fn){const generation=epoch;const next=d.chain.catch(()=>{}).then(async()=>{if(generation!==epoch)throw new Error('세션이 변경되었습니다.');return fn(generation);});d.chain=next;return next;}
 function changed(d){d.dirty=true;d.error='';clearTimeout(d.timer);status(d);d.timer=setTimeout(()=>save(d,'auto').catch(e=>failure(d,e)),1000);}
 async function persist(d,mode,state,generation){
  const values={...d.values};
  if(fields.some(([f])=>new TextEncoder().encode(values[f]).length>180000))throw new Error('항목당 180 KB까지 저장할 수 있습니다. 긴 기록은 파일로 보관하고 분석에 필요한 구간을 남겨 주세요.');
  d.pending++;status(d);
  try{
   const r=await api('academy/records'+(d.record?'/'+d.record.id:''),{course:d.cid,lesson:d.sid,mission:d.mid,scope:'livefire',...values,status:state,revision:d.record?.revision||0,save_mode:mode});
   if(generation!==epoch)return;
   d.record=r;d.dirty=fields.some(([f])=>d.values[f]!==values[f]);d.error='';
  }finally{d.pending--;status(d);}
 }
 function save(d=current,mode='manual',state='draft'){clearTimeout(d.timer);return queue(d,async g=>{if(mode==='auto'&&!d.dirty&&d.record)return;await persist(d,mode,state,g);});}
 async function flush(){for(const d of drafts.values()){clearTimeout(d.timer);await d.chain.catch(()=>{});while(d.dirty)await save(d,'auto');}}
 function leave(){for(const d of drafts.values())if(d.dirty){clearTimeout(d.timer);save(d,'auto').catch(e=>failure(d,e));}}
 function images(){return `<div class="lf-evidence ac-evidence-list">${(current?.record?.images||[]).map(i=>`<figure><a href="${i.url}" target="_blank" rel="noopener"><img src="${i.url}" alt="${esc(i.caption)}" loading="lazy"></a><figcaption>${esc(i.caption)}</figcaption></figure>`).join('')}</div>`;}
 function render(m){const d=current;return `<section id="lf-report" class="lf-report"><header><h3>미션 기록</h3><a id="lf-record-link" hidden>저장한 기록 · 수정 이력 ↗</a></header><p>실습에서 시도한 과정, 전체 결과와 캡처, 그 결과에 대한 해석을 기록하세요. 세 항목을 한 묶음으로 등록합니다.</p>${fields.map(([f,label],i)=>`<section class="lf-section"><label for="lf-${f}"><span>0${i+1}</span><strong>${label}</strong></label><textarea id="lf-${f}" data-lf-field="${f}" rows="${f==='interpretation'?5:7}" spellcheck="false" placeholder="${esc(m.submission.sections?.find(s=>s.id===f)?.placeholder||({input:'사용한 명령·검색식·수행 절차와 시행착오를 기록하세요.',output:'실제 출력·로그·오류·관측 결과를 기록하고 필요한 캡처를 모두 추가하세요.',interpretation:'결과의 의미, 판단 근거, 아직 확인하지 못한 점과 다음 조치를 적으세요.'}[f]))}">${esc(d.values[f])}</textarea>${f==='output'?'<div class="lf-capture-tools"><label class="nb-file">캡처 추가<input id="lf-images" type="file" multiple accept="image/png,image/jpeg,image/webp"></label><span>여러 캡처 선택 · Ctrl+V로 붙여넣기</span></div><div id="lf-images-list">'+images()+'</div>':''}</section>`).join('')}<footer><span id="lf-status" role="status"></span><div><button data-lf-export class="secondary">작성 내용 내보내기</button><button data-lf-save="draft" class="secondary">임시 저장</button><button data-lf-save="complete" class="primary">미션 등록</button></div></footer><p class="lf-grading">AI 채점·분석·피드백은 Live Fire 훈련 엔진 연결 후 제공됩니다.</p></section>`;}
 function bind(){if(!$('lf-report'))return;status(current);$('lf-images').onchange=e=>act(()=>upload([...e.target.files]));}
 async function upload(files){if(!files.length||!current)return;const d=current;clearTimeout(d.timer);
  return queue(d,async g=>{d.pending++;status(d);try{
   if((d.record?.images.length||0)+files.length>20)throw new Error('미션마다 캡처를 최대 20장 보관할 수 있습니다.');
   await persist(d,'auto','draft',g);if(g!==epoch)return;
   for(const file of files){const image=await AcademyNotebook.encode(file);if(g!==epoch)return;const r=await api('academy/records/'+d.record.id+'/images',{image,caption:(file.name||'실습 캡처').slice(0,200),revision:d.record.revision});if(g!==epoch)return;d.record=r;}
  }catch(e){failure(d,e);throw e;}finally{d.pending--;status(d);if(d===current&&$('lf-images-list'))$('lf-images-list').innerHTML=images();}});
 }
 document.addEventListener('input',e=>{if(!current||!e.target.matches('[data-lf-field]'))return;current.values[e.target.dataset.lfField]=e.target.value;changed(current);});
 document.addEventListener('click',e=>{const b=e.target.closest('[data-lf-save],[data-lf-export]');if(!b||!current)return;const d=current;
  if(b.hasAttribute('data-lf-export')){const url=URL.createObjectURL(new Blob([JSON.stringify({course:d.cid,scenario:d.sid,mission:d.mid,...d.values,images:d.record?.images||[]},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=d.mid+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;}
  act(async()=>{try{b.disabled=true;await save(d,'manual',b.dataset.lfSave);notice(b.dataset.lfSave==='complete'?'미션 기록을 등록했습니다.':'미션 기록을 저장했습니다.');}catch(e){failure(d,e);throw e;}finally{b.disabled=false;}});
 });
 document.addEventListener('paste',e=>{if(!e.target.closest('#lf-report'))return;const files=[...e.clipboardData.items].filter(i=>i.kind==='file'&&i.type.startsWith('image/')).map(i=>i.getAsFile());if(files.length){e.preventDefault();act(()=>upload(files));}});
 window.addEventListener('hashchange',leave);
 window.addEventListener('beforeunload',e=>{if(dirty()){e.preventDefault();e.returnValue='';}});
 return {select,clear,dirty,flush,render,bind,mark};
})();
