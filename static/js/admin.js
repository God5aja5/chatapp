async function loadSettings(){
  const r = await fetch('/api/admin/settings');
  const j = await r.json();
  const s = j.settings || {};
  document.getElementById('set_app_name').value = s.APP_NAME || '';
  document.getElementById('set_app_icon').value = s.APP_ICON || '';
  document.getElementById('set_app_tagline').value = s.APP_TAGLINE || '';
  document.getElementById('set_login_subtitle').value = s.LOGIN_SUBTITLE || '';
  document.getElementById('set_register_subtitle').value = s.REGISTER_SUBTITLE || '';
  document.getElementById('set_welcome_message').value = s.WELCOME_MESSAGE || '';
  document.getElementById('set_room_name').value = s.DEFAULT_ROOM_NAME || '';
  document.getElementById('set_theme_accent').value = s.THEME_ACCENT || '';
  document.getElementById('set_theme_accent2').value = s.THEME_ACCENT_2 || '';
  document.getElementById('set_theme_bg').value = s.THEME_BG || '';
  document.getElementById('set_theme_panel').value = s.THEME_PANEL || '';
  document.getElementById('set_theme_card').value = s.THEME_CARD || '';
  document.getElementById('set_theme_text').value = s.THEME_TEXT || '';
  document.getElementById('set_theme_muted').value = s.THEME_MUTED || '';
  document.getElementById('set_theme_border').value = s.THEME_BORDER || '';
}

async function saveSettings(){
  const payload = {
    APP_NAME: document.getElementById('set_app_name').value.trim(),
    APP_ICON: document.getElementById('set_app_icon').value.trim(),
    APP_TAGLINE: document.getElementById('set_app_tagline').value.trim(),
    LOGIN_SUBTITLE: document.getElementById('set_login_subtitle').value.trim(),
    REGISTER_SUBTITLE: document.getElementById('set_register_subtitle').value.trim(),
    WELCOME_MESSAGE: document.getElementById('set_welcome_message').value.trim(),
    DEFAULT_ROOM_NAME: document.getElementById('set_room_name').value.trim(),
    THEME_ACCENT: document.getElementById('set_theme_accent').value.trim(),
    THEME_ACCENT_2: document.getElementById('set_theme_accent2').value.trim(),
    THEME_BG: document.getElementById('set_theme_bg').value.trim(),
    THEME_PANEL: document.getElementById('set_theme_panel').value.trim(),
    THEME_CARD: document.getElementById('set_theme_card').value.trim(),
    THEME_TEXT: document.getElementById('set_theme_text').value.trim(),
    THEME_MUTED: document.getElementById('set_theme_muted').value.trim(),
    THEME_BORDER: document.getElementById('set_theme_border').value.trim()
  };
  const r = await fetch('/api/admin/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const j = await r.json();
  if(j.ok){
    alert('Settings saved. Refresh chat to see updates.');
  } else {
    alert(j.error || 'Save failed');
  }
}

async function loadUsers(){
  const r = await fetch('/api/admin/users');
  const j = await r.json();
  const list = document.getElementById('users_list');
  list.innerHTML = '';
  (j.users || []).forEach(u => {
    const row = document.createElement('div');
    row.className = 'user-row';
    const info = document.createElement('div');
    info.className = 'user-info';
    info.innerHTML = `<div class="user-name">${u.display_name} (@${u.username})</div><div class="user-meta">id: ${u.id} ${u.is_admin ? ' • admin' : ''}</div>`;
    const actions = document.createElement('div');
    actions.className = 'user-actions';

    const toggle = document.createElement('button');
    toggle.className = 'btn ghost';
    toggle.textContent = u.is_admin ? 'Demote' : 'Promote';
    toggle.onclick = ()=> toggleAdmin(u.id, !u.is_admin);
    actions.appendChild(toggle);

    const remove = document.createElement('button');
    remove.className = 'btn';
    remove.textContent = 'Remove';
    remove.onclick = ()=> removeUser(u.id, u.username);
    actions.appendChild(remove);

    row.appendChild(info);
    row.appendChild(actions);
    list.appendChild(row);
  });
}

async function toggleAdmin(id, isAdmin){
  const r = await fetch(`/api/admin/user/${id}/toggle_admin`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_admin: isAdmin})});
  const j = await r.json();
  if(!j.ok){ alert(j.error || 'Update failed'); return; }
  loadUsers();
}

async function removeUser(id, username){
  if(!confirm(`Remove user ${username}?`)) return;
  const r = await fetch(`/api/admin/user/${id}/remove`, {method:'POST'});
  const j = await r.json();
  if(!j.ok){ alert(j.error || 'Remove failed'); return; }
  loadUsers();
}

async function sendBroadcast(){
  const text = document.getElementById('broadcast_text').value.trim();
  if(!text){ alert('Enter a message'); return; }
  const r = await fetch('/api/admin/broadcast', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
  const j = await r.json();
  if(j.ok){
    alert('Broadcast sent');
    document.getElementById('broadcast_text').value = '';
  } else {
    alert(j.error || 'Broadcast failed');
  }
}

document.getElementById('btn_save_settings').addEventListener('click', (e)=>{ e.preventDefault(); saveSettings(); });
document.getElementById('btn_cancel_settings').addEventListener('click', (e)=>{ e.preventDefault(); loadSettings(); });
document.getElementById('btn_broadcast').addEventListener('click', (e)=>{ e.preventDefault(); sendBroadcast(); });
document.getElementById('btn_broadcast_cancel').addEventListener('click', (e)=>{ e.preventDefault(); document.getElementById('broadcast_text').value = ''; });

loadSettings();
loadUsers();
