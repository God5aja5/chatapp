const APP_CONFIG = window.APP_CONFIG || {};
const MAX_FILES = APP_CONFIG.maxFiles || 5;
const IMAGE_EXTS = APP_CONFIG.imageExts || [];
const VIDEO_EXTS = APP_CONFIG.videoExts || [];
const MAX_FILE_SIZE = APP_CONFIG.maxFileSize || (25 * 1024 * 1024);
const INITIAL_ROOM_ID = APP_CONFIG.roomId || 1;
const CURRENT_USER = APP_CONFIG.user || {};

const MY_USERNAME = CURRENT_USER.username || "";
const MY_ID = CURRENT_USER.id ?? null;

let socket;
let selected = [];
let currentRoomId = INITIAL_ROOM_ID;
let replyTo = null;
let stickersCache = [];

const messagesEl = document.getElementById("messages");
const inputEl = document.getElementById("input");
const fileInput = document.getElementById("file_input");
const previewEl = document.getElementById("preview");
const toast = document.getElementById("toast");
const notifCenter = document.getElementById("notif_center");
const roomsPanel = document.getElementById("rooms_panel");
const settingsModal = document.getElementById("settings_modal");
const chatTitle = document.getElementById("chat_title");
const stickersPanel = document.getElementById("stickers_panel");

function escapeHtml(s){
  return (s || "").replace(/[&<>"']/g, m => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));
}
function escapeAttr(s){
  return escapeHtml(s).replace(/`/g, "&#96;");
}

function showToast(msg, timeout=2500){
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(()=> toast.classList.remove("show"), timeout);
}

function init(){
  socket = io({transports:["websocket","polling"], upgrade:true});
  socket.on("connect", ()=> {
    try { socket.emit("switch_room", {room_id: currentRoomId}); } catch(e) {}
  });
  socket.on("connect_error", (err)=> console.warn("socket connect error", err));
  socket.on("new_message", onNewMessageEvent);
  socket.on("reaction", onReactionEvent);
  socket.on("edit", onEditEvent);
  socket.on("delete", onDeleteEvent);
  socket.on("pinned", onPinnedEvent);
  socket.on("notification", n=> showToast(n.text || "Notification"));
  socket.on("typing", d=> showTyping(d));
  socket.on("profile_update", onProfileUpdate);

  loadMessages();
  loadRooms();

  document.getElementById("btn_send").addEventListener("click", sendMessage);
  document.getElementById("btn_file").addEventListener("click", ()=> fileInput.click());
  fileInput.addEventListener("change", handleFiles);
  document.getElementById("btn_sticker").addEventListener("click", toggleStickers);
  document.getElementById("btn_notif").addEventListener("click", showNotifCenter);
  document.getElementById("btn_settings").addEventListener("click", toggleSettings);
  document.getElementById("btn_hamburger").addEventListener("click", toggleRoomsPanel);
  inputEl.addEventListener("input", ()=> {
    try { socket.emit("typing", {is_typing: true}); } catch(e) {}
    clearTimeout(window._typingTimer);
    window._typingTimer = setTimeout(()=> { try { socket.emit("typing", {is_typing: false}); } catch(e) {} }, 1000);
  });
  window.addEventListener("resize", ()=> messagesEl.scrollTop = messagesEl.scrollHeight);
  messagesEl.addEventListener("click", handleMessageClick);
  addSwipeListeners();
  initSetupModal();
}

async function loadRooms(){
  const r = await fetch("/api/rooms");
  const j = await r.json();
  roomsPanel.innerHTML = "";
  j.rooms.forEach(room=>{
    const el = document.createElement("div");
    el.className = "room";
    el.textContent = room.name;
    el.dataset.id = room.id;
    if(room.id == j.current) el.classList.add("active");
    el.onclick = ()=> switchRoom(room.id);
    roomsPanel.appendChild(el);
  });
  currentRoomId = j.current;
}

async function switchRoom(rid){
  const r = await fetch("/api/switch_room", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({room_id: rid})});
  const j = await r.json();
  if(!j.ok){ showToast(j.error || "Cannot switch"); return; }
  currentRoomId = rid;
  roomsPanel.querySelectorAll(".room").forEach(el=> el.classList.toggle("active", el.dataset.id == rid));
  try { socket.emit("switch_room", {room_id: rid}); } catch(e) {}
  await loadMessages();
  const m = await fetch("/api/messages?limit=1");
  const mj = await m.json();
  if(mj.room) chatTitle.textContent = mj.room.name;
  showToast("Switched room");
}

function toggleRoomsPanel(){
  roomsPanel.style.display = roomsPanel.style.display === "block" ? "none" : "block";
}

function toggleSettings(){
  if(settingsModal.style.display === "block"){ settingsModal.style.display = "none"; return; }
  const displayName = escapeAttr(CURRENT_USER.display_name || CURRENT_USER.username || "");
  const username = escapeAttr(CURRENT_USER.username || "");
  const bio = escapeHtml(CURRENT_USER.bio || "");
  const avatar = escapeAttr(CURRENT_USER.avatar || "");
  settingsModal.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3>Settings</h3>
      <button id="close_settings" class="copy-btn">✕</button>
    </div>
    <div style="margin-top:8px;">
      <strong>Profile</strong>
      <div style="margin-top:8px">
        <div class="settings-row">
          <img id="settings_avatar_preview" src="${avatar}" style="width:64px;height:64px;border-radius:12px;object-fit:cover">
          <div style="flex:1">
            <input id="settings_display" placeholder="Display name (Please enter your telegram profile name)" value="${displayName}">
            <input id="settings_username" placeholder="Username" value="${username}">
            <textarea id="settings_bio" placeholder="Bio" rows="2">${bio}</textarea>
            <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
              <input id="settings_avatar_file" type="file" accept="image/*" style="display:none">
              <button id="btn_change_avatar" class="copy-btn">Change avatar</button>
              <button id="btn_save_profile" class="full-btn">Save profile</button>
            </div>
          </div>
        </div>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.06);margin:12px 0">

      <strong>Create room</strong>
      <div style="margin-top:8px" id="create_room_box">
        <div class="settings-row">
          <input id="create_room_name" placeholder="Room name">
          <input id="create_room_password" placeholder="Optional password">
        </div>
        <div style="margin-top:8px">
          <button id="btn_create_room" class="full-btn">Create room</button>
        </div>
        <div class="small-muted" style="margin-top:8px">After create you'll see the room key (copied to clipboard). Share it to let others join.</div>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.06);margin:12px 0">

      <strong>Join room</strong>
      <div style="margin-top:8px" id="join_room_box">
        <div class="settings-row">
          <input id="join_room_key" placeholder="Room key">
          <input id="join_room_password" placeholder="Room password (if any)">
        </div>
        <div style="margin-top:8px">
          <button id="btn_join_room" class="full-btn">Join room</button>
        </div>
      </div>

      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.06);margin:12px 0">

      <strong>My rooms</strong>
      <div id="my_rooms_list" style="margin-top:8px;max-height:220px;overflow:auto"></div>

      <div style="margin-top:12px;display:flex;gap:8px">
        <button id="btn_cancel_settings" class="copy-btn">Cancel</button>
      </div>
    </div>
  `;
  settingsModal.style.display = "block";
  document.getElementById("close_settings").onclick = ()=> settingsModal.style.display = "none";
  document.getElementById("btn_cancel_settings").onclick = ()=> settingsModal.style.display = "none";
  document.getElementById("btn_change_avatar").onclick = ()=> document.getElementById("settings_avatar_file").click();
  document.getElementById("settings_avatar_file").addEventListener("change", handleAvatarFile);
  document.getElementById("btn_save_profile").onclick = saveProfile;
  document.getElementById("btn_create_room").onclick = createRoomFromSettings;
  document.getElementById("btn_join_room").onclick = joinRoomFromSettings;
  loadSettingsRooms();
}

function handleAvatarFile(ev){
  const f = ev.target.files && ev.target.files[0];
  if(!f) return;
  if(f.size > MAX_FILE_SIZE){ showToast("Avatar too large"); return; }
  const preview = document.getElementById("settings_avatar_preview");
  preview.src = URL.createObjectURL(f);
}

async function saveProfile(){
  const display = document.getElementById("settings_display").value.trim();
  const username = document.getElementById("settings_username").value.trim();
  const bio = document.getElementById("settings_bio").value.trim();
  const fileInputEl = document.getElementById("settings_avatar_file");
  const fd = new FormData();
  fd.append("display_name", display);
  fd.append("username", username);
  fd.append("bio", bio);
  if(fileInputEl.files && fileInputEl.files[0]){ fd.append("avatar", fileInputEl.files[0]); }
  const r = await fetch("/api/profile", {method:"POST", body: fd});
  const j = await r.json();
  if(j.ok){
    showToast("Profile saved");
    if(j.profile && j.profile.avatar){
      document.getElementById("my_avatar").src = j.profile.avatar;
      CURRENT_USER.avatar = j.profile.avatar;
    }
    if(j.profile){
      CURRENT_USER.display_name = j.profile.display_name;
      CURRENT_USER.username = j.profile.username;
      CURRENT_USER.bio = j.profile.bio;
    }
  } else {
    showToast(j.error || "Save failed");
  }
}

async function createRoomFromSettings(){
  const name = document.getElementById("create_room_name").value.trim() || (document.getElementById("chat_title").textContent || "");
  const password = document.getElementById("create_room_password").value || "";
  const fd = new FormData();
  fd.append("name", name);
  fd.append("password", password);
  const r = await fetch("/api/room_create", {method:"POST", body: fd});
  const j = await r.json();
  if(!j.ok){ showToast(j.error || "Create failed"); return; }
  showToast("Room created — key copied");
  try { await navigator.clipboard.writeText(j.room.key); } catch(e) {}
  const info = `Room: ${j.room.name}\nKey: ${j.room.key}\n${j.password ? ("Password: " + j.password) : "No password"}`;
  alert(info);
  loadSettingsRooms();
  loadRooms();
}

async function joinRoomFromSettings(){
  const key = document.getElementById("join_room_key").value.trim();
  const password = document.getElementById("join_room_password").value || "";
  if(!key){ showToast("Enter room key"); return; }
  const fd = new FormData();
  fd.append("room_key", key);
  fd.append("password", password);
  const r = await fetch("/api/room_join", {method:"POST", body: fd});
  const j = await r.json();
  if(!j.ok){ showToast(j.error || "Join failed"); return; }
  showToast("Joined room");
  loadSettingsRooms();
  loadRooms();
}

async function loadSettingsRooms(){
  const r = await fetch("/api/rooms");
  const j = await r.json();
  const el = document.getElementById("my_rooms_list");
  el.innerHTML = "";
  j.rooms.forEach(room=>{
    const div = document.createElement("div"); div.className = "room-item";
    const left = document.createElement("div"); left.style.flex = "1";
    left.innerHTML = `<div style="font-weight:700">${escapeHtml(room.name)}</div><div class="small-muted">id: ${room.id}</div>`;
    const right = document.createElement("div"); right.style.display="flex"; right.style.gap="6px";
    const btnSwitch = document.createElement("button"); btnSwitch.className="copy-btn"; btnSwitch.textContent = "Switch";
    btnSwitch.onclick = ()=> { switchRoom(room.id); settingsModal.style.display = "none"; };
    right.appendChild(btnSwitch);
    if(room.owned){
      const keyBtn = document.createElement("button"); keyBtn.className="copy-btn"; keyBtn.textContent = "Copy key";
      keyBtn.onclick = async ()=> { try { await navigator.clipboard.writeText(room.key); showToast("Key copied"); } catch(e){ showToast("Copy failed"); } };
      right.appendChild(keyBtn);
      const setPwd = document.createElement("button"); setPwd.className="copy-btn"; setPwd.textContent = "Set password";
      setPwd.onclick = async ()=> {
        const pw = prompt("New password (leave blank to clear):");
        if(pw === null) return;
        const fd = new FormData(); fd.append("room_id", room.id); fd.append("password", pw || "");
        const r2 = await fetch("/api/room_set_password", {method:"POST", body: fd});
        const j2 = await r2.json();
        if(!j2.ok) { showToast(j2.error || "Failed"); return; }
        showToast(pw ? "Password set" : "Password cleared");
        if(pw) { alert("Password (copy it now): " + pw); }
        loadSettingsRooms();
      };
      right.appendChild(setPwd);
      const info = document.createElement("div"); info.className="small-muted"; info.style.marginLeft="8px"; info.textContent = `Key: ${room.key} ${room.has_password ? " • password set" : ""}`;
      left.appendChild(info);
    }
    div.appendChild(left); div.appendChild(right);
    el.appendChild(div);
  });
}

function showNotifCenter(){
  if(notifCenter.style.display === "block"){ notifCenter.style.display = "none"; return; }
  fetch("/api/notifications").then(r=>r.json()).then(j=>{
    notifCenter.style.display = "block";
    notifCenter.innerHTML = "<strong>Notifications</strong><hr>";
    j.notifications.forEach(n=>{
      const d = document.createElement("div");
      d.style.padding = "6px";
      d.innerHTML = `<small>${new Date(n.created_at).toLocaleString()}</small><div>${escapeHtml(n.text)}</div>`;
      notifCenter.appendChild(d);
    });
  });
}

function showTyping(d){
  const p = document.getElementById("presence");
  p.textContent = d.is_typing ? `${d.username} is typing…` : "Online";
}

function renderMessageMeta(el, displayName, createdAt, edited){
  if(!el) return;
  const meta = el.querySelector(".meta");
  if(!meta) return;
  const time = createdAt ? new Date(createdAt).toLocaleTimeString() : "";
  const editedText = edited ? " • edited" : "";
  meta.innerHTML = `<strong>${escapeHtml(displayName)}</strong>${time ? " • " + time : ""}${editedText}`;
}

async function loadMessages(){
  const r = await fetch("/api/messages?limit=200");
  const j = await r.json();
  messagesEl.innerHTML = "";
  chatTitle.textContent = j.room ? j.room.name : chatTitle.textContent;
  j.messages.forEach(renderMessage);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessage(m){
  if(!m || !m.id) return null;
  const el = document.createElement("div");
  const am = (m.sender && m.sender.username === MY_USERNAME);
  el.className = "msg " + (am ? "me" : "");
  if(m.sender && m.sender.is_admin){ el.classList.add("admin"); }
  el.id = "m" + m.id;
  el.dataset.msgId = m.id;
  el.dataset.senderId = (m.sender && m.sender.id != null) ? String(m.sender.id) : "";
  el.dataset.createdAt = m.created_at || "";
  el.dataset.edited = m.edited ? "1" : "0";
  const meta = document.createElement("div"); meta.className="meta";
  const displayName = (m.sender && m.sender.display_name) ? m.sender.display_name : (m.sender && m.sender.username) ? m.sender.username : "System";
  el.appendChild(meta);
  renderMessageMeta(el, displayName, m.created_at, m.edited);
  if(m.reply_to){
    const rep = document.createElement("div"); rep.style.fontSize="12px"; rep.style.color="var(--muted)";
    rep.textContent = "Replying to message #" + m.reply_to;
    el.appendChild(rep);
  }
  const body = document.createElement("div"); body.className="text"; body.innerHTML = m.rendered || escapeHtml(m.text || "");
  el.appendChild(body);
  if(m.attachments && m.attachments.length){
    const att = document.createElement("div"); att.className="attach";
    m.attachments.forEach(a=>{
      try {
        if(a.type === "image"){
          const img = document.createElement("img"); img.src = a.url; img.loading = "lazy"; img.onclick = ()=> openPreview(a.url); att.appendChild(img);
        } else if(a.type === "video"){
          const v = document.createElement("video"); v.src = a.url; v.controls = true; v.preload = "none"; att.appendChild(v);
        } else if(a.type === "sticker"){
          const img = document.createElement("img"); img.src = a.url; img.style.width = "90px"; att.appendChild(img);
        } else if(a.type === "file"){
          const link = document.createElement("a"); link.href = a.url; link.textContent = a.filename || "download.txt"; link.target = "_blank"; att.appendChild(link);
        }
      } catch(e) {}
    });
    el.appendChild(att);
  }
  const reactionsWrap = document.createElement("div"); reactionsWrap.className="reactions";
  for(const [emoji, users] of Object.entries(m.reactions || {})){
    const pill = document.createElement("div"); pill.className="react-pill"; pill.textContent = `${emoji} ${users.length}`;
    pill.onclick = ()=> react(m.id, emoji);
    reactionsWrap.appendChild(pill);
  }
  el.appendChild(reactionsWrap);
  const actions = document.createElement("div"); actions.className="actions";
  actions.innerHTML = `<button onclick="startReply(${m.id})">↩️</button> <button onclick="react(${m.id},'👍')">👍</button>`;
  if(am){
    actions.innerHTML += ` <button onclick="editMessage(${m.id})">✏️</button> <button onclick="deleteMessage(${m.id})">🗑️</button>`;
  }
  el.appendChild(actions);
  messagesEl.appendChild(el);
  return el;
}

function onNewMessageEvent(payload){
  const chatId = payload.chat_id || (payload.message && payload.message.chat_id);
  if(chatId != null && currentRoomId != null && chatId !== currentRoomId) return;
  const msg = payload.message || payload;
  renderMessage(msg);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}
function onReactionEvent(d){
  const el = document.getElementById("m" + d.message_id);
  if(!el) return;
  const wrap = el.querySelector(".reactions");
  if(!wrap) return;
  wrap.innerHTML = "";
  for(const [emoji, users] of Object.entries(d.reactions || {})){
    const pill = document.createElement("div"); pill.className="react-pill"; pill.textContent = `${emoji} ${users.length}`;
    pill.onclick = ()=> react(d.message_id, emoji);
    wrap.appendChild(pill);
  }
}
function onEditEvent(d){
  const el = document.getElementById("m" + d.message_id);
  if(!el) return;
  const body = el.querySelector(".text");
  if(body) body.innerHTML = d.rendered || escapeHtml(d.text || "");
  const meta = el.querySelector(".meta");
  if(meta && d.edited){
    if(!meta.innerHTML.includes("• edited")) meta.innerHTML = meta.innerHTML + " • edited";
  }
  if(d.edited) el.dataset.edited = "1";
}
function onDeleteEvent(d){
  const el = document.getElementById("m" + d.message_id);
  if(el) el.remove();
}
function onPinnedEvent(d){
  const el = document.getElementById("m" + d.message_id);
  if(el) el.style.border = "1px solid gold";
}

function onProfileUpdate(d){
  if(!d || !d.user) return;
  const u = d.user;
  if(u.id == null) return;
  if(u.id === MY_ID){
    if(u.avatar){
      const myAvatar = document.getElementById("my_avatar");
      if(myAvatar) myAvatar.src = u.avatar;
      CURRENT_USER.avatar = u.avatar;
    }
    CURRENT_USER.display_name = u.display_name;
    CURRENT_USER.username = u.username;
    CURRENT_USER.bio = u.bio;
    const preview = document.getElementById("settings_avatar_preview");
    if(preview) preview.src = u.avatar || "";
    const displayInput = document.getElementById("settings_display");
    if(displayInput) displayInput.value = u.display_name || u.username || "";
    const usernameInput = document.getElementById("settings_username");
    if(usernameInput) usernameInput.value = u.username || "";
    const bioInput = document.getElementById("settings_bio");
    if(bioInput) bioInput.value = u.bio || "";
  }
  document.querySelectorAll(`.msg[data-sender-id="${u.id}"]`).forEach(el=>{
    renderMessageMeta(el, u.display_name || u.username || "System", el.dataset.createdAt, el.dataset.edited === "1");
  });
}

function handleFiles(ev){
  const files = Array.from(ev.target.files || []);
  if(!files.length) return;
  if(selected.length + files.length > MAX_FILES){ showToast("Max " + MAX_FILES + " files"); return; }
  for(const f of files){
    const ext = f.name.split(".").pop().toLowerCase();
    const type = IMAGE_EXTS.includes(ext) ? "image" : (VIDEO_EXTS.includes(ext) ? "video" : null);
    if(!type){ showToast("Unsupported: " + f.name); continue; }
    if(f.size > MAX_FILE_SIZE){ showToast("Too large: " + f.name); continue; }
    const previewUrl = URL.createObjectURL(f);
    selected.push({file:f, preview:previewUrl, type:type, uploadedName:null});
  }
  updatePreview();
  ev.target.value = "";
}
function updatePreview(){
  previewEl.innerHTML = "";
  if(!selected.length) return;
  selected.forEach((s, idx)=>{
    const wrap = document.createElement("div"); wrap.style.position="relative";
    const thumb = document.createElement(s.type === "image" ? "img" : "video"); thumb.className="preview-thumb"; thumb.src = s.preview;
    if(s.type === "video"){ thumb.muted = true; thumb.autoplay = true; thumb.loop = true; thumb.playsInline = true; }
    wrap.appendChild(thumb);
    const del = document.createElement("button"); del.textContent = "✕"; del.style.position = "absolute"; del.style.top = "6px"; del.style.right = "6px";
    del.onclick = ()=> { selected.splice(idx, 1); updatePreview(); };
    wrap.appendChild(del);
    previewEl.appendChild(wrap);
  });
}

async function sendMessage(){
  if(!navigator.onLine){ showToast("Offline"); return; }
  let text = inputEl.value;
  if(!text && selected.length === 0) return;

  const toUpload = selected.filter(s=> !s.uploadedName).map(s=> s.file);
  if(toUpload.length){
    const fd = new FormData();
    toUpload.forEach(f=> fd.append("files", f));
    const r = await fetch("/api/upload_multiple", {method:"POST", body: fd});
    const j = await r.json();
    if(!j.ok){ showToast(j.error || "Upload failed"); return; }
    let idx = 0;
    for(let i=0;i<selected.length;i++){
      if(!selected[i].uploadedName){
        selected[i].uploadedName = j.files[idx].filename;
        selected[i].type = j.files[idx].type;
        idx++;
      }
    }
  }
  const attachments = selected.map(s => ({filename: s.uploadedName, type: s.type}));
  try {
    socket.emit("send_message", {text: text, attachments: attachments, reply_to: replyTo || null});
  } catch(e) { console.error(e); }
  inputEl.value = ""; selected = []; updatePreview();
  replyTo = null; renderReplyBanner();
}

async function react(msgId, emoji){
  const r = await fetch(`/api/message/${msgId}/react`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({emoji:emoji})});
  const j = await r.json();
  if(!j.ok) showToast(j.error || "React failed");
}
function startReply(msgId){
  replyTo = msgId; renderReplyBanner();
  inputEl.focus();
  showToast("Replying to message " + msgId);
}
function renderReplyBanner(){
  const existing = document.querySelector(".reply-banner");
  if(existing) existing.remove();
  if(!replyTo) return;
  const banner = document.createElement("div"); banner.className = "reply-banner";
  banner.innerHTML = `<div>Replying to #${replyTo}</div><div><button id="cancel_reply" class="copy-btn">✕</button></div>`;
  const inputbar = document.querySelector(".inputbar");
  inputbar.parentNode.insertBefore(banner, inputbar);
  document.getElementById("cancel_reply").onclick = ()=> { replyTo = null; banner.remove(); };
}
function editMessage(msgId){
  const text = prompt("Edit message");
  if(text === null) return;
  fetch(`/api/message/${msgId}/edit`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({text:text})})
    .then(r=>r.json()).then(j=>{ if(!j.ok) showToast(j.error || "Edit failed"); });
}
function deleteMessage(msgId){
  if(!confirm("Delete this message?")) return;
  fetch(`/api/message/${msgId}/delete`, {method:"POST"})
    .then(r=>r.json()).then(j=>{ if(!j.ok) showToast(j.error || "Delete failed"); });
}

function addSwipeListeners(){
  let startX=0, startY=0, startT=0;
  messagesEl.addEventListener('touchstart', e=> {
    const t = e.touches[0];
    startX = t.clientX; startY = t.clientY; startT = Date.now();
  });
  messagesEl.addEventListener('touchend', e=> {
    const t = e.changedTouches[0];
    const dx = t.clientX - startX, dy = t.clientY - startY, dt = Date.now() - startT;
    if(dx > 80 && Math.abs(dy) < 60 && dt < 600){
      let node = document.elementFromPoint(t.clientX, t.clientY);
      while(node && !node.dataset?.msgId) node = node.parentNode;
      if(node && node.dataset?.msgId){
        startReply(node.dataset.msgId);
      }
    }
  });
}
let lastTap = {id:null, time:0};
function handleMessageClick(e){
  let node = e.target;
  while(node && !node.dataset?.msgId) node = node.parentNode;
  if(!node) return;
  const id = node.dataset.msgId;
  const now = Date.now();
  if(lastTap.id == id && (now - lastTap.time) < 400){
    react(id, "👍");
    lastTap = {id:null, time:0};
  } else {
    lastTap = {id:id, time:now};
  }
}

async function ensureStickersLoaded(){
  if(stickersCache.length) return;
  const r = await fetch("/api/stickers");
  const j = await r.json();
  stickersCache = j.stickers || [];
}

function buildStickerPanel(){
  if(stickersPanel.dataset.ready) return;
  stickersPanel.innerHTML = `
    <div class="stickers-header">
      <h4>Stickers</h4>
      <button id="stickers_close" class="icon mini" title="Close">✕</button>
    </div>
    <div class="stickers-search">
      <input id="stickers_search" placeholder="Search emoji or paste one" />
    </div>
    <div id="stickers_grid" class="stickers-grid"></div>
  `;
  stickersPanel.dataset.ready = "1";
  document.getElementById("stickers_close").onclick = ()=> stickersPanel.classList.remove("open");
  document.getElementById("stickers_search").addEventListener("input", (e)=> renderStickers(e.target.value));
}

async function toggleStickers(){
  buildStickerPanel();
  if(stickersPanel.classList.contains("open")){
    stickersPanel.classList.remove("open");
    return;
  }
  await ensureStickersLoaded();
  renderStickers("");
  stickersPanel.classList.add("open");
}

function renderStickers(query){
  const grid = document.getElementById("stickers_grid");
  const q = (query || "").trim();
  grid.innerHTML = "";
  const items = stickersCache.filter(s => {
    if(!q) return true;
    const emoji = s.emoji || "";
    return emoji.includes(q) || s.filename.toLowerCase().includes(q.toLowerCase());
  });
  items.forEach(s => {
    const btn = document.createElement("div");
    btn.className = "sticker-item";
    btn.title = s.emoji || s.filename;
    const img = document.createElement("img");
    img.src = s.url;
    img.alt = s.emoji || s.filename;
    btn.appendChild(img);
    btn.onclick = ()=> sendSticker(s.filename);
    grid.appendChild(btn);
  });
}

function sendSticker(filename){
  if(!filename) return;
  try {
    socket.emit("send_message", {text:"", attachments:[{filename: filename, type:"sticker"}], reply_to: null});
  } catch(e) {}
  stickersPanel.classList.remove("open");
}

function openPreview(url){
  const w = window.open("");
  w.document.write(`<html><body style="margin:0;background:#000"><img src="${url}" style="width:100%;height:auto"></body></html>`);
}

function initSetupModal(){
  const modal = document.getElementById("setup_modal");
  if(!modal) return;
  if(localStorage.getItem("setup_done") === "1") return;
  const ok = document.getElementById("btn_setup_ok");
  const cancel = document.getElementById("btn_setup_cancel");
  modal.classList.add("show");
  if("Notification" in window && Notification.permission === "default" && localStorage.getItem("notif_prompted") !== "1"){
    localStorage.setItem("notif_prompted", "1");
    setTimeout(()=> { try { Notification.requestPermission(); } catch(e) {} }, 600);
  }
  ok.onclick = async ()=> {
    if("Notification" in window){
      try { await Notification.requestPermission(); } catch(e) {}
    }
    localStorage.setItem("setup_done", "1");
    modal.classList.remove("show");
  };
  cancel.onclick = ()=> {
    localStorage.setItem("setup_done", "1");
    modal.classList.remove("show");
  };
}

window.addEventListener("load", init);
