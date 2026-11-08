/* Ordered lesson journals. Draft writes never submit a graded battle answer. */
'use strict';
const AcademyNotebook=(()=>{
 const drafts=new Map();let current=null,epoch=0;
 const block=(type='paragraph',text='')=>({id:crypto.randomUUID(),type,text});
 function clear(){epoch++;for(const d of drafts.values())clearTimeout(d.timer);drafts.clear();current=null;}
 function select(lesson){
  const key=lesson.course_id+'/'+lesson.id;
  if(!drafts.has(key))drafts.set(key,{key,cid:lesson.course_id,lid:lesson.id,record:lesson.notebook,blocks:structuredClone(lesson.notebook?.notebook||[block()]),dirty:false,pending:0,error:'',chain:Promise.resolve()});
  current=drafts.get(key);
  if(!current.dirty&&!current.pending&&lesson.notebook&&lesson.notebook.revision!==current.record?.revision){current.record=lesson.notebook;current.blocks=structuredClone(lesson.notebook.notebook);}
  return current;
 }
 function dirty(){return [...drafts.values()].some(d=>d.dirty||d.pending);}
 function status(d){if(d!==current||!$('nb-status'))return;
  const node=$('nb-status');node.textContent=d.error?'저장 실패 · '+d.error:d.pending?'저장 중…':d.dirty?'변경됨 · 자동 저장 대기':d.record?'저장됨 · '+date(d.record.updated_at):'작성하면 자동으로 임시 저장됩니다.';
  node.classList.toggle('nb-error',!!d.error);node.setAttribute('role',d.error?'alert':'status');
 }
 function changed(d){d.dirty=true;d.error='';clearTimeout(d.timer);status(d);d.timer=setTimeout(()=>save(d,'auto').catch(e=>failure(d,e)),2500);}
 function failure(d,e){d.error=e.message;status(d);}
 function queue(d,fn){const generation=epoch;const next=d.chain.catch(()=>{}).then(async()=>{if(generation!==epoch)throw new Error('세션이 변경되었습니다.');return fn(generation);});d.chain=next;return next;}
 async function persist(d,mode='auto',state='draft',generation=epoch){
  const notebook=JSON.stringify(d.blocks),bytes=d.blocks.reduce((n,b)=>n+new TextEncoder().encode(b.text).length,0);
  if(bytes>262144||d.blocks.length>200)throw new Error('노트는 본문 256 KiB, 블록 200개까지 저장할 수 있습니다. 긴 로그는 필요한 구간을 나누어 정리해 주세요.');
  d.pending++;status(d);
  try{
   const r=await api('academy/records'+(d.record?'/'+d.record.id:''),{course:d.cid,lesson:d.lid,mission:'',scope:'lesson',input:'',output:'',interpretation:'',notebook,status:state,revision:d.record?.revision||0,save_mode:mode});
   if(generation!==epoch)return;
   d.record=r;d.dirty=JSON.stringify(d.blocks)!==notebook;d.error='';
  }finally{d.pending--;status(d);}
 }
 function save(d=current,mode='manual',state='draft'){clearTimeout(d.timer);return queue(d,g=>persist(d,mode,state,g));}
 function leave(){for(const d of drafts.values())if(d.dirty&&!d.pending){clearTimeout(d.timer);save(d,'auto').catch(e=>failure(d,e));}}
 async function flush(){for(const d of drafts.values()){clearTimeout(d.timer);await d.chain;if(d.dirty)await save(d,'auto');}}
 function read(record,snapshot=null){const data=snapshot||record,images=record.images||[];
  return `<div class="nb-published">${(data.notebook||[]).map(b=>{
   if(b.type==='image'){const i=images.find(i=>i.id===b.image_id);return i?`<figure><a href="${i.url}" target="_blank" rel="noopener"><img loading="lazy" width="${i.width}" height="${i.height}" src="${i.url}" alt="${esc(b.text||'실습 캡처')}"></a>${b.text?'<figcaption>'+esc(b.text)+'</figcaption>':''}</figure>`:'';}
   return b.type==='heading'?'<h3>'+esc(b.text)+'</h3>':b.type==='code'?'<pre class="ac-code">'+esc(b.text)+'</pre>':'<p>'+esc(b.text)+'</p>';
  }).join('')}</div>`;
 }
 function render(){const d=current;if(!d)return '';
  return `<section class="ac-notebook" id="ac-notebook"><header class="nb-head"><div><strong>나의 실습 노트</strong><small id="nb-status" role="status"></small></div><div><button class="secondary" data-nb-save="draft">지금 저장</button><button class="primary" data-nb-save="complete">작성 완료</button></div></header><p class="nb-intro">실습하며 사용한 명령, 검색식, 전체 결과, 시행착오와 해석을 기록하세요. 글과 캡처를 원하는 순서로 이어 붙일 수 있습니다.</p><div class="nb-tools" aria-label="기록 추가"><button data-nb-add="paragraph">＋ 글</button><button data-nb-add="heading">제목</button><button data-nb-add="code">명령 · 출력</button><label class="nb-file">캡처 추가<input id="nb-file" type="file" multiple accept="image/png,image/jpeg,image/webp"></label><button data-nb-preview>미리보기</button></div><div id="nb-blocks">${d.blocks.map((b,i)=>editBlock(d,b,i)).join('')}</div><button class="nb-append" data-nb-add="paragraph">＋ 이어서 글쓰기</button><p class="nb-hint">Ctrl+V로 캡처 붙여넣기 · 여러 이미지 선택/끌어놓기 · 순서 변경 가능</p><dialog id="nb-preview"><header><strong>실습 노트 미리보기</strong><button data-nb-close>닫기</button></header><div id="nb-preview-body"></div></dialog></section>`;
 }
 function editBlock(d,b,i){const image=b.type==='image'?d.record?.images.find(x=>x.id===b.image_id):null;
  return `<section class="nb-block nb-${b.type}" data-nb-block="${b.id}"><div class="nb-block-tools"><small>${i+1} · ${{paragraph:'글',heading:'제목',code:'명령 · 출력',image:'캡처'}[b.type]}</small><span><button data-nb-move="-1" ${i===0?'disabled':''} aria-label="위로 이동">↑</button><button data-nb-move="1" ${i===d.blocks.length-1?'disabled':''} aria-label="아래로 이동">↓</button><button data-nb-remove aria-label="블록 삭제">×</button></span></div>${image?`<a href="${image.url}" target="_blank" rel="noopener"><img loading="lazy" width="${image.width}" height="${image.height}" src="${image.url}" alt="실습 캡처"></a>`:''}<textarea data-nb-text="${b.id}" rows="${b.type==='code'?5:2}" aria-label="${b.type==='image'?'캡처 설명':'실습 '+(b.type==='heading'?'제목':'내용')}" spellcheck="false" placeholder="${b.type==='image'?'이 화면에서 확인한 내용을 설명하세요.':b.type==='code'?'명령과 전체 출력, 로그를 붙여넣으세요.':b.type==='heading'?'구간 제목':'실습 과정과 확인한 내용을 자유롭게 기록하세요.'}">${esc(b.text)}</textarea></section>`;
 }
 function resize(node){if(node.closest('.nb-code'))return;node.style.height='auto';node.style.height=Math.min(900,Math.max(50,node.scrollHeight))+'px';}
 function bind(){if(!$('ac-notebook'))return;status(current);document.querySelectorAll('[data-nb-text]').forEach(resize);$('nb-file').onchange=e=>act(()=>upload([...e.target.files]));}
 function repaint(focus){if(!$('nb-blocks'))return;$('nb-blocks').innerHTML=current.blocks.map((b,i)=>editBlock(current,b,i)).join('');bind();if(focus)document.querySelector(`[data-nb-text="${focus}"]`)?.focus();}
 async function encode(file){
  if(!['image/png','image/jpeg','image/webp'].includes(file.type)||file.size>10*1024*1024)throw new Error('PNG, JPG, WebP 이미지(10 MiB 이하)를 선택해 주세요.');
  const bitmap=await createImageBitmap(file);if(bitmap.width*bitmap.height>40000000){bitmap.close();throw new Error('캡처 크기를 줄여 주세요.');}
  const scale=Math.min(1,2200/Math.max(bitmap.width,bitmap.height)),canvas=document.createElement('canvas');canvas.width=Math.round(bitmap.width*scale);canvas.height=Math.round(bitmap.height*scale);canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);bitmap.close();
  let blob;for(const quality of [.9,.78,.62,.45]){blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/webp',quality));if(blob&&blob.size<=512*1024)break;}
  if(!blob||blob.size>512*1024)throw new Error('캡처 범위를 줄여 다시 붙여넣어 주세요.');
  return await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(r.result);r.onerror=reject;r.readAsDataURL(blob);});
 }
 async function upload(files,after=null){
  if(!files.length||!current)return;const d=current;clearTimeout(d.timer);
  return queue(d,async generation=>{
   if(d.blocks.length+files.length>200)throw new Error('노트의 블록은 최대 200개입니다.');
   if((d.record?.images.length||0)+files.length>50)throw new Error('노트 한 편에는 캡처를 최대 50장 보관할 수 있습니다.');
   d.pending++;status(d);
   try{
    await persist(d,'auto','draft',generation);if(generation!==epoch)return;
    for(const file of files){
     const image=await encode(file);if(generation!==epoch)return;
     const previous=new Set(d.record.images.map(i=>i.id));
     const r=await api('academy/records/'+d.record.id+'/images',{image,caption:'실습 캡처',revision:d.record.revision});if(generation!==epoch)return;d.record=r;
     const uploaded=r.images.find(i=>!previous.has(i.id));const b={...block('image'),image_id:uploaded.id};let at=after?d.blocks.findIndex(b=>b.id===after)+1:d.blocks.length;
     d.blocks.splice(at,0,b);after=b.id;d.dirty=true;
     // Each accepted image immediately becomes a persisted document block.
     await persist(d,'auto','draft',generation);if(generation!==epoch)return;
    }
    if(d===current)repaint();
   }catch(e){failure(d,e);if(d===current)repaint();throw e;}finally{d.pending--;status(d);}
  });
 }
 document.addEventListener('input',e=>{if(!e.target.matches('[data-nb-text]')||!current)return;const b=current.blocks.find(b=>b.id===e.target.dataset.nbText);if(b){b.text=e.target.value;resize(e.target);changed(current);}});
 document.addEventListener('click',e=>{
  const button=e.target.closest('[data-nb-add],[data-nb-save],[data-nb-move],[data-nb-remove],[data-nb-preview],[data-nb-close]');if(!button||!current)return;
  act(async()=>{
   if(button.hasAttribute('data-nb-add')){if(current.blocks.length>=200)throw new Error('노트의 블록은 최대 200개입니다.');const b=block(button.dataset.nbAdd);current.blocks.push(b);changed(current);repaint(b.id);}
   else if(button.hasAttribute('data-nb-save')){const d=current;try{await save(d,'manual',button.dataset.nbSave);notice(button.dataset.nbSave==='complete'?'실습 노트를 완료했습니다.':'실습 노트를 저장했습니다.');}catch(e){failure(d,e);throw e;}}
   else if(button.hasAttribute('data-nb-preview')){$('nb-preview-body').innerHTML=read({...current.record,notebook:current.blocks});$('nb-preview').showModal();}
   else if(button.hasAttribute('data-nb-close'))$('nb-preview').close();
   else{const id=button.closest('[data-nb-block]').dataset.nbBlock,at=current.blocks.findIndex(b=>b.id===id);if(button.hasAttribute('data-nb-remove'))current.blocks.splice(at,1);else{const target=at+Number(button.dataset.nbMove);if(target>=0&&target<current.blocks.length)[current.blocks[at],current.blocks[target]]=[current.blocks[target],current.blocks[at]];}changed(current);repaint();}
  });
 });
 document.addEventListener('paste',e=>{if(!e.target.closest('#ac-notebook'))return;const files=[...e.clipboardData.items].filter(i=>i.kind==='file'&&i.type.startsWith('image/')).map(i=>i.getAsFile());if(files.length){e.preventDefault();act(()=>upload(files,e.target.closest('[data-nb-block]')?.dataset.nbBlock));}});
 document.addEventListener('dragover',e=>{if(e.target.closest('#ac-notebook')&&[...e.dataTransfer.types].includes('Files'))e.preventDefault();});
 document.addEventListener('drop',e=>{if(!e.target.closest('#ac-notebook')||!e.dataTransfer.files.length)return;e.preventDefault();act(()=>upload([...e.dataTransfer.files],e.target.closest('[data-nb-block]')?.dataset.nbBlock));});
 window.addEventListener('beforeunload',e=>{if(dirty()){e.preventDefault();e.returnValue='';}});
 window.addEventListener('hashchange',leave);
 return {select,render,bind,read,clear,leave,flush,dirty,encode};
})();
