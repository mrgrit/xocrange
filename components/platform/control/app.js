'use strict';
let csrf = '';
const el = id => document.getElementById(id);
async function api(path, body) {
  const response = await fetch('/core/api/' + path, {method: body ? 'POST' : 'GET', credentials: 'same-origin', headers: body ? {'Content-Type':'application/json','X-CSRFToken':csrf} : {}, body: body ? JSON.stringify(body) : undefined});
  const data = await response.json();
  if (data.csrf_token) csrf = data.csrf_token;
  if (!response.ok) throw new Error(({invalid_credentials:'계정과 비밀번호를 확인해 주세요.',invalid_input:'입력 형식과 비밀번호 조건을 확인해 주세요.',permission_denied:'이 작업을 실행할 권한이 없습니다.',try_later:'로그인 시도 제한에 도달했습니다. 15분 뒤 다시 시도해 주세요.',csrf_failed:'세션을 새로 불러온 뒤 다시 시도해 주세요.'})[data.error] || '요청을 처리하지 못했습니다: ' + data.error);
  return data;
}
async function refresh() {
  const s = await api('session');
  el('login').hidden = s.authenticated; el('account').hidden = !s.authenticated;
  if (!s.authenticated) return;
  el('identity').textContent = s.username + ' · ' + s.role;
  el('devices').hidden = s.must_change_password; el('admin').hidden = s.role !== 'admin' || s.must_change_password;
  el('siem-link').hidden = !s.siem_available;
  if (s.must_change_password) { el('password-panel').open = true; el('notice').textContent = '초기 비밀번호를 변경해 주세요.'; return; }
  const result = await api('devices'); el('device-list').replaceChildren();
  for (const d of result.devices) {
    const row = document.createElement('li'); row.textContent = d.device.toUpperCase() + ' · 쓰기 ' + (d.write_enabled ? '허용' : '잠금');
    if (s.role === 'admin') { const b=document.createElement('button'); b.textContent=d.write_enabled?'잠그기':'쓰기 허용'; b.onclick=()=>act(async()=>{await api('devices/'+d.device,{write_enabled:!d.write_enabled,version:d.version}); await refresh();}); row.append(b); }
    el('device-list').append(row);
  }
  if (s.role === 'admin') { el('users').textContent=JSON.stringify((await api('users')).users,null,2); el('audit').textContent=JSON.stringify((await api('audit')).events,null,2); }
}
async function act(fn) { el('notice').textContent=''; try {await fn();} catch(e){el('notice').textContent=e.message;} }
for(const [id,path] of [['login-form','login'],['password-form','password'],['user-form','users']]) el(id).onsubmit=e=>{e.preventDefault();act(async()=>{const b=Object.fromEntries(new FormData(e.target)); if(path==='users')b.active=true; await api(path,b); e.target.reset(); await refresh();});};
el('logout').onclick=()=>act(async()=>{await api('logout',{});await refresh();});
act(refresh);
