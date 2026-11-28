/* Navsuite UI: one window for files and networks.
 * Plain JS on Tauri's global API. Backend commands are in app/src/lib.rs.
 */
'use strict';

const T = window.__TAURI__;
const invoke = (cmd, args = {}) => T.core.invoke(cmd, args);
const listen = (ev, fn) => T.event.listen(ev, e => fn(e.payload));
const $ = sel => document.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
};
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* Externally tagged or internally tagged serde enums → {type, ...fields}. */
function untag(v) {
  if (v == null || typeof v !== 'object') return { type: String(v) };
  if (v.type) return v;
  const k = Object.keys(v)[0];
  const inner = v[k];
  return Object.assign({ type: k[0].toLowerCase() + k.slice(1) }, typeof inner === 'object' && inner !== null ? inner : { value: inner });
}

/* ---------- formatting ---------- */
function fmtSize(n) {
  if (n == null) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + ' ' + u[i];
}
function fmtTime(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}
function fmtAgo(ms) {
  if (!ms) return '';
  const s = (Date.now() - ms) / 1000;
  if (s < 90) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' days ago';
}
function fmtEta(s) {
  if (s == null || !isFinite(s)) return '';
  if (s < 60) return Math.round(s) + ' s';
  if (s < 3600) return Math.round(s / 60) + ' min';
  return (s / 3600).toFixed(1) + ' h';
}

/* ---------- sections and channels ---------- */
const CHANNELS = {
  lan: 'LAN', tailscale: 'Tailscale', bonjour: 'Bonjour', netbios: 'NetBIOS', smb: 'SMB', ssh: 'SSH',
  sftp: 'SFTP', ftp: 'FTP', printer: 'Printer', web: 'Web', cast: 'Cast', rdp: 'RDP', vnc: 'VNC',
};
const SECTIONS = [
  { id: 'all', name: 'All systems', ico: '◉' },
  { id: 'lan', name: 'Home LAN', ico: '⌂', ch: ['lan'] },
  { id: 'tailscale', name: 'Tailscale', ico: '⛓', ch: ['tailscale'] },
  { id: 'bonjour', name: 'Bonjour / Avahi', ico: '✶', ch: ['bonjour'] },
  { id: 'netbios', name: 'NetBIOS / WINS', ico: '▦', ch: ['netbios'] },
  { id: 'smb', name: 'SMB shares', ico: '🗀', ch: ['smb'] },
  { id: 'ssh', name: 'SSH / SFTP', ico: '>_', ch: ['ssh', 'sftp'] },
  { id: 'ftp', name: 'FTP', ico: '⇅', ch: ['ftp'] },
  { id: 'printer', name: 'Printers', ico: '⎙', ch: ['printer'] },
  { id: 'web', name: 'Web pages', ico: '◎', ch: ['web'] },
  { id: 'cast', name: 'Casting & media', ico: '▶', ch: ['cast'] },
];
const KIND_ICO = { router: '⌬', printer: '⎙', nas: '🗄', media: '▶', phone: '📱', windows: '⊞', server: '▤', computer: '💻', iot: '◌', device: '◦', pi: 'π', tv: '▶' };

/* ---------- state ---------- */
const S = {
  settings: null,
  view: { type: 'roots' },
  back: [],
  fwd: [],
  entries: [],
  sel: new Set(),
  anchor: null,
  sort: { key: 'name', dir: 1 },
  records: [],
  tailnet: null,
  scanning: false,
  clip: null,            // {op:'copy'|'move', locs:[uri]}
  shells: [],
  terms: new Map(),      // id -> {term, fit, div, tab, shell}
  termPending: new Map(),// id -> [Uint8Array] output that arrived before the tab registered
  activeTerm: null,
  probeId: null,
  jobs: new Map(),
  phones: [],
  inbox: [],
  drop: null,
  forms: [],
};

function recName(r) {
  const n = S.settings?.systems?.[r.id];
  return (n && n.label) || r.label || r.name;
}
function recKind(r) {
  const n = S.settings?.systems?.[r.id];
  return (n && n.kind) || r.kind;
}
function inSection(r, sec) {
  if (sec.id === 'all') return true;
  return (r.channels || []).some(c => sec.ch.includes(c.kind));
}
function channel(r, ...kinds) {
  return (r.channels || []).find(c => kinds.includes(c.kind));
}

/* ---------- toast, log, menu, modal ---------- */
let toastTimer;
function toast(msg, ms = 2600) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), ms);
}
function log(msg) {
  const o = $('#log-out');
  const line = `[${new Date().toLocaleTimeString()}] ${msg}\n`;
  o.textContent += line;
  if (o.textContent.length > 200000) o.textContent = o.textContent.slice(-150000);
  o.scrollTop = o.scrollHeight;
}
function errText(e) {
  if (e == null) return 'Unknown error';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  return JSON.stringify(e);
}
function fail(e, what) {
  const m = (what ? what + ': ' : '') + errText(e);
  log(m);
  toast(m, 5000);
}

// Surface otherwise-invisible failures: an uncaught error or rejected promise in a
// click handler used to vanish silently (e.g. a feature that "does nothing").
addEventListener('error', e => fail(e.message || e.error, 'Error'));
addEventListener('unhandledrejection', e => fail(e.reason, 'Error'));

function menu(items, x, y) {
  const m = $('#menu');
  m.innerHTML = '';
  const build = (list, host) => {
    for (const it of list) {
      if (!it) continue;
      if (it === '-') { host.append(el('div', { class: 'sep' })); continue; }
      const row = el('div', { class: 'mi' + (it.disabled ? ' disabled' : '') + (it.mono ? ' sub' : '') },
        el('span', { text: it.label }), it.key ? el('span', { class: 'k', text: it.key }) : null,
        it.sub ? el('span', { class: 'k', text: '▸' }) : null);
      row.addEventListener('click', ev => {
        ev.stopPropagation();
        if (it.sub) { menu(it.sub, x + 12, y + 12); return; }
        hideMenu();
        it.run && it.run();
      });
      host.append(row);
    }
  };
  build(items, m);
  m.hidden = false;
  const r = m.getBoundingClientRect();
  m.style.left = Math.min(x, innerWidth - r.width - 8) + 'px';
  m.style.top = Math.min(y, innerHeight - r.height - 8) + 'px';
}
function hideMenu() { $('#menu').hidden = true; }
document.addEventListener('click', hideMenu);
document.addEventListener('contextmenu', e => { if (!e.target.closest('input,textarea,.xterm')) e.preventDefault(); });

function modal(title, body, buttons) {
  return new Promise(resolve => {
    const m = $('#modal');
    m.innerHTML = '';
    m.append(el('h3', { text: title }));
    if (typeof body === 'string') m.append(el('div', { html: body })); else m.append(body);
    const foot = el('div', { class: 'foot' });
    const close = v => { m.hidden = true; $('#modal-backdrop').hidden = true; document.removeEventListener('keydown', onKey, true); resolve(v); };
    for (const b of buttons) foot.append(el('button', { class: b.primary ? 'primary' : '', text: b.label, onclick: () => close(b.value !== undefined ? b.value : b.label) }));
    m.append(foot);
    const onKey = e => {
      if (e.key === 'Escape') { e.stopPropagation(); close(null); }
      if (e.key === 'Enter' && !e.target.matches('textarea')) {
        const p = buttons.find(b => b.primary);
        if (p) { e.preventDefault(); e.stopPropagation(); close(p.value !== undefined ? p.value : p.label); }
      }
    };
    document.addEventListener('keydown', onKey, true);
    m.hidden = false;
    $('#modal-backdrop').hidden = false;
    const f = m.querySelector('input,select,button.primary');
    f && f.focus();
  });
}
/* A modal that stays open (for a browser) and returns a close function. */
function modalPersistent(title, body) {
  const m = $('#modal');
  m.innerHTML = '';
  m.append(el('h3', { text: title }));
  m.append(body);
  const foot = el('div', { class: 'foot' });
  const close = () => { m.hidden = true; $('#modal-backdrop').hidden = true; document.removeEventListener('keydown', onKey, true); };
  foot.append(el('button', { class: 'primary', text: 'Close', onclick: close }));
  m.append(foot);
  const onKey = e => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
  document.addEventListener('keydown', onKey, true);
  m.hidden = false;
  $('#modal-backdrop').hidden = false;
  return close;
}
async function ask(title, label, value = '') {
  const input = el('input', { value });
  const body = el('div', {}, el('label', { text: label }), input);
  const ok = await modal(title, body, [{ label: 'Cancel', value: null }, { label: 'OK', primary: true, value: true }]);
  return ok ? input.value : null;
}

/* ---------- vfs errors that need the user ---------- */
async function handleVfsError(e, retry) {
  const k = e && e.kind ? untag(e.kind) : null;
  if (k && k.type === 'authRequired') {
    const user = el('input', { value: k.user || '' });
    const pass = el('input', { type: 'password' });
    const body = el('div', {},
      el('p', { text: `${k.host} needs a user name and password. They are kept in this computer's keychain and never shared.` }),
      el('label', { text: 'User' }), user, el('label', { text: 'Password' }), pass);
    const ok = await modal('Sign in', body, [{ label: 'Cancel', value: null }, { label: 'Sign in', primary: true, value: true }]);
    if (!ok) return false;
    try {
      await invoke('fs_set_credentials', { host: k.host, user: user.value, password: pass.value });
      return retry ? retry() : true;
    } catch (err) { fail(err, 'Saving the sign-in'); return false; }
  }
  if (k && k.type === 'hostKeyUnknown') {
    const body = el('div', {},
      el('p', { text: `This is the first connection to ${k.host}. Check that its key fingerprint matches before trusting it.` }),
      el('p', { class: 'mono', text: k.fingerprint }));
    const ok = await modal('Trust this system?', body, [{ label: 'Cancel', value: null }, { label: 'Trust and connect', primary: true, value: true }]);
    if (!ok) return false;
    try {
      await invoke('fs_trust_host_key', { host: k.host, port: k.port, key: k.keyOpenssh });
      return retry ? retry() : true;
    } catch (err) { fail(err, 'Saving the host key'); return false; }
  }
  fail(e);
  return false;
}

/* ---------- media (play media and music in the window) ---------- */
const MEDIA_EXT = {
  video: ['mp4', 'm4v', 'webm', 'mov', 'mkv', 'ogv'],
  audio: ['mp3', 'm4a', 'aac', 'flac', 'wav', 'ogg', 'oga', 'opus', 'weba'],
};
function mediaKind(name) {
  const ext = (/\.([^.]+)$/.exec(name) || [])[1]?.toLowerCase();
  if (!ext) return null;
  if (MEDIA_EXT.video.includes(ext)) return 'video';
  if (MEDIA_EXT.audio.includes(ext)) return 'audio';
  return null;
}
async function mediaBase() {
  if (!S.media) S.media = await invoke('media_base');
  return S.media;
}
function mediaUrl(path, loc) {
  const b = S.media;
  return `${b.url}/${path}?t=${encodeURIComponent(b.token)}&u=${encodeURIComponent(loc)}`;
}
/* The playlist is every playable sibling in the current listing, so Next/Prev work. */
function mediaSiblings(loc) {
  const here = S.entries.filter(e => !e.isDir && mediaKind(e.name));
  const i = here.findIndex(e => e.loc === loc);
  return { list: here, index: i < 0 ? 0 : i };
}
async function playMedia(loc, name) {
  try { await mediaBase(); } catch (e) { fail(e, 'Media player'); return; }
  const kind = mediaKind(name) || 'video';
  let { list, index } = mediaSiblings(loc);
  if (!list.length) list = [{ loc, name }];
  if (index < 0) index = 0;
  const backdrop = $('#modal-backdrop');
  backdrop.hidden = false;
  const player = el('div', { class: 'player' });
  const stage = el('div', { class: 'player-stage' });
  const bar = el('div', { class: 'player-bar' });
  player.append(stage, bar);
  $('#modal').hidden = true;
  const host = el('div', { class: 'player-host', onclick: e => { if (e.target === host) close(); } }, player);
  document.body.append(host);
  let media;
  const close = () => { try { media && media.pause(); } catch {} host.remove(); backdrop.hidden = true; document.removeEventListener('keydown', onKey, true); };
  const onKey = e => {
    if (e.key === 'Escape') { e.stopPropagation(); close(); }
    else if (e.key === ' ' && media) { e.preventDefault(); media.paused ? media.play() : media.pause(); }
    else if (e.key === 'ArrowRight' && e.shiftKey) step(1);
    else if (e.key === 'ArrowLeft' && e.shiftKey) step(-1);
    else if (e.key === 'ArrowRight' && media) media.currentTime += 10;
    else if (e.key === 'ArrowLeft' && media) media.currentTime -= 10;
  };
  document.addEventListener('keydown', onKey, true);
  function step(d) { const n = index + d; if (n >= 0 && n < list.length) { index = n; load(); } }
  async function load() {
    const item = list[index];
    stage.innerHTML = '';
    bar.innerHTML = '';
    const k = mediaKind(item.name) || 'video';
    media = el(k === 'audio' ? 'audio' : 'video', { controls: true, autoplay: true, src: mediaUrl('f', item.loc), class: 'player-media' });
    media.addEventListener('ended', () => step(1));
    media.addEventListener('error', () => stage.append(el('div', { class: 'player-msg', text: 'This file could not be played here. Try Open with system app.' })));
    const art = el('div', { class: 'player-art' });
    if (k === 'audio') { stage.append(art, media); } else { stage.append(media); }
    const title = el('div', { class: 'player-title', text: item.name });
    const meta = el('div', { class: 'player-meta muted', text: 'Reading…' });
    bar.append(el('div', {},
      el('div', { class: 'player-nav' },
        el('button', { text: '⏮ Prev', disabled: index === 0, onclick: () => step(-1) }),
        el('span', { class: 'muted', text: `${index + 1} / ${list.length}` }),
        el('button', { text: 'Next ⏭', disabled: index === list.length - 1, onclick: () => step(1) }),
        el('span', { style: 'flex:1' }),
        el('button', { text: 'Open with system app', onclick: () => { openWithSystem(item.loc); close(); } }),
        el('button', { text: 'Close', onclick: close })),
      title, meta));
    fetch(mediaUrl('meta', item.loc)).then(r => r.json()).then(info => {
      if (list[index].loc !== item.loc) return;
      const parts = [info.artist, info.album, info.genre].filter(Boolean);
      meta.textContent = parts.join(' · ') || (k === 'audio' ? 'No tags' : '');
      if (info.title && k === 'audio') title.textContent = info.title + (info.artist ? ' — ' + info.artist : '');
      if (info.hasCover && k === 'audio') art.style.backgroundImage = `url("${mediaUrl('cover', item.loc)}")`;
      else if (k === 'audio') art.textContent = '♪';
    }).catch(() => { meta.textContent = ''; if (k === 'audio') art.textContent = '♪'; });
  }
  load();
}

/* ---------- navigation ---------- */
function sameView(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function go(view, { push = true, select = null } = {}) {
  if (push && !sameView(view, S.view)) { S.back.push(S.view); S.fwd = []; }
  S.view = view;
  S.sel = new Set(select ? [select] : []);
  S.anchor = select;
  $('#filter').value = '';
  render(select);
}
function goBack() { if (!S.back.length) return; S.fwd.push(S.view); S.view = S.back.pop(); S.sel.clear(); render(); }
function goFwd() { if (!S.fwd.length) return; S.back.push(S.view); S.view = S.fwd.pop(); S.sel.clear(); render(); }
async function goUp() {
  const v = S.view;
  if (v.type === 'folder') {
    try {
      const p = await invoke('fs_parent', { loc: v.loc });
      if (p) go({ type: 'folder', loc: p }, { select: v.loc });
      else {
        const sys = systemForLoc(v.loc);
        go(sys ? { type: 'system', id: sys.id } : { type: 'roots' });
      }
    } catch (e) { fail(e); }
  } else if (v.type === 'system') go({ type: 'section', id: 'all' });
  else go({ type: 'roots' });
}
function hostOf(loc) {
  const m = /^(?:smb|sftp|ssh):\/\/(?:[^@/]+@)?([^/:]+)/i.exec(loc) || /^\\\\([^\\]+)/.exec(loc);
  return m ? m[1].toLowerCase() : null;
}
function systemForLoc(loc) {
  const h = hostOf(loc);
  if (!h) return null;
  return S.records.find(r => (r.ips || []).includes(h) || (r.names || []).some(n => n.name.toLowerCase().replace(/\.$/, '') === h) || (r.name || '').toLowerCase() === h);
}
/* Open a location typed or pasted anywhere (E1). Also accepts a system's name. */
async function openTyped(text) {
  text = text.trim();
  if (!text) return;
  const sys = S.records.find(r => recName(r).toLowerCase() === text.toLowerCase() || (r.ips || []).includes(text));
  if (sys && !/[\\/:]/.test(text.replace(/^\d+\.\d+\.\d+\.\d+$/, ''))) { go({ type: 'system', id: sys.id }); return; }
  try {
    const loc = await invoke('fs_normalize', { input: text });
    const st = await invoke('fs_stat', { loc }).catch(() => null);
    if (st && !st.isDir && st.kind !== 'share' && st.kind !== 'drive') {
      const parent = await invoke('fs_parent', { loc });
      go({ type: 'folder', loc: parent }, { select: loc });
    } else go({ type: 'folder', loc });
  } catch (e) {
    if (sys) go({ type: 'system', id: sys.id }); else fail(e, 'Cannot open');
  }
}

/* ---------- render ---------- */
async function render(select) {
  renderSidebar();
  renderCrumbs();
  const v = S.view;
  $('#content-head').innerHTML = '';
  if (v.type === 'roots') await showRoots();
  else if (v.type === 'folder') await showFolder(v.loc, select);
  else if (v.type === 'section') showSection(v.id);
  else if (v.type === 'system') showSystem(v.id);
  else if (v.type === 'favourites') showFavourites();
  else if (v.type === 'disks') await showDisks();
  markTree();
}

function renderSidebar() {
  const sb = $('#sidebar');
  sb.innerHTML = '';
  const v = S.view;
  const item = (ico, name, active, onclick, count) =>
    el('div', { class: 'side-item' + (active ? ' active' : ''), onclick },
      el('span', { class: 'ico', text: ico }), el('span', { text: name }),
      count != null ? el('span', { class: 'count', text: count }) : null);
  const g1 = el('div', { class: 'side-group' }, el('div', { class: 'side-title', text: 'This computer' }));
  g1.append(item('💻', 'Drives and folders', v.type === 'roots', () => go({ type: 'roots' })));
  g1.append(item('★', 'Favourites', v.type === 'favourites', () => go({ type: 'favourites' }), (S.settings?.favourites || []).length || null));
  g1.append(item('🖴', 'Drives & partitions', v.type === 'disks', () => go({ type: 'disks' })));
  sb.append(g1);
  const g2 = el('div', { class: 'side-group' }, el('div', { class: 'side-title', text: 'Network' + (S.scanning ? ' · scanning…' : '') }));
  for (const sec of SECTIONS) {
    const n = S.records.filter(r => inSection(r, sec)).length;
    if (sec.id !== 'all' && sec.id !== 'lan' && sec.id !== 'tailscale' && !n) continue;
    const active = (v.type === 'section' && v.id === sec.id);
    g2.append(item(sec.ico, sec.name, active, () => go({ type: 'section', id: sec.id }), n));
  }
  sb.append(g2);
  const g3 = el('div', { class: 'side-group' }, el('div', { class: 'side-title', text: 'Phones' }));
  g3.append(item('📱', 'Drop page', false, () => openDock('phones'), S.phones.length || null));
  sb.append(g3);
}

function renderCrumbs() {
  const c = $('#crumbs');
  c.innerHTML = '';
  const v = S.view;
  const add = (label, view) => {
    if (c.childNodes.length) c.append(el('span', { class: 'sep', text: '›' }));
    c.append(el('span', { class: 'c', text: label, onclick: e => { e.stopPropagation(); go(view); } }));
  };
  if (v.type === 'roots') add('This computer', v);
  else if (v.type === 'disks') { add('This computer', { type: 'roots' }); add('Drives & partitions', v); }
  else if (v.type === 'favourites') add('Favourites', v);
  else if (v.type === 'section') { add('Network', { type: 'section', id: 'all' }); if (v.id !== 'all') add(SECTIONS.find(s => s.id === v.id)?.name || v.id, v); }
  else if (v.type === 'system') { const r = S.records.find(r => r.id === v.id); add('Network', { type: 'section', id: 'all' }); add(r ? recName(r) : v.id, v); }
  else if (v.type === 'folder') {
    const parts = crumbParts(v.loc);
    const sys = systemForLoc(v.loc);
    if (sys) { add('Network', { type: 'section', id: 'all' }); add(recName(sys), { type: 'system', id: sys.id }); }
    for (const p of parts) add(p.label, { type: 'folder', loc: p.loc });
  }
  $('#address-input').value = v.type === 'folder' ? v.loc : '';
}
/* Break a location into clickable crumbs without a round trip per level. */
function crumbParts(loc) {
  const out = [];
  let m;
  if ((m = /^(smb|sftp):\/\/([^/]+)(\/.*)?$/i.exec(loc))) {
    const base = `${m[1]}://${m[2]}`;
    out.push({ label: `${m[1].toUpperCase()} ${m[2]}`, loc: base + (m[1].toLowerCase() === 'sftp' ? '/' : '') });
    let acc = base;
    for (const seg of (m[3] || '').split('/').filter(Boolean)) { acc += '/' + seg; out.push({ label: decodeURIComponent(seg), loc: acc }); }
    return out;
  }
  if ((m = /^\\\\([^\\]+)\\?(.*)$/.exec(loc))) {
    let acc = `\\\\${m[1]}`;
    out.push({ label: m[1], loc: acc });
    for (const seg of m[2].split('\\').filter(Boolean)) { acc += '\\' + seg; out.push({ label: seg, loc: acc }); }
    return out;
  }
  if ((m = /^([A-Za-z]:)[\\/]?(.*)$/.exec(loc))) {
    let acc = m[1] + '\\';
    out.push({ label: m[1], loc: acc });
    for (const seg of m[2].split(/[\\/]/).filter(Boolean)) { acc = acc.replace(/\\?$/, '\\') + seg; out.push({ label: seg, loc: acc }); }
    return out;
  }
  if (loc.startsWith('/')) {
    out.push({ label: '/', loc: '/' });
    let acc = '';
    for (const seg of loc.split('/').filter(Boolean)) { acc += '/' + seg; out.push({ label: seg, loc: acc }); }
    return out;
  }
  return [{ label: loc, loc }];
}

function status(text) { $('#statusbar').textContent = text; }

/* ----- drives and favourites ----- */
async function showRoots() {
  try {
    S.entries = await invoke('fs_roots');
  } catch (e) { S.entries = []; fail(e); }
  $('#content-head').append(el('div', { class: 'sys-head' }, el('h2', { text: 'This computer' })));
  renderListing();
}
function showFavourites() {
  const favs = S.settings.favourites || [];
  $('#content-head').append(el('div', { class: 'sys-head' }, el('h2', { text: 'Favourites' }),
    el('span', { class: 'muted', text: 'Add folders and systems from their menus.' })));
  S.entries = favs.map(f => ({ name: f.name, loc: f.target, isDir: true, kind: f.target.startsWith('sys:') ? 'system' : 'dir', fav: true }));
  renderListing();
}

/* ----- drives and partitions (DB1–DB6, DB10) ----- */
const FS_WRITE_TIP = {};
async function showDisks() {
  const head = $('#content-head');
  head.append(el('div', { class: 'sys-head' }, el('h2', { text: 'Drives & partitions' }),
    el('span', { class: 'muted', text: 'Other operating systems and EFI partitions open read-only, to keep them safe.' })));
  const body = $('#content-body');
  body.innerHTML = '<div class="empty">Reading disks…</div>';
  let disks, elevated = false;
  try { [disks, elevated] = await Promise.all([invoke('disks_list'), invoke('disks_is_elevated')]); }
  catch (e) { body.innerHTML = ''; body.append(el('div', { class: 'empty', text: 'Could not read disks: ' + errText(e) })); return; }
  S.elevated = elevated;
  body.innerHTML = '';
  const wrap = el('div', { class: 'cards', style: 'grid-template-columns:1fr' });
  for (const disk of disks) {
    const card = el('div', { class: 'card' });
    card.append(el('h4', {}, `🖴  ${disk.model || disk.id}`, el('span', { class: 'muted', text: `  ${disk.bus || ''} · ${fmtSize(disk.size)}${disk.removable ? ' · removable' : ''}` })));
    if (disk.removable) card.append(el('div', { class: 'btn-row' }, el('button', { text: '⏏ Eject', onclick: () => ejectDisk(disk) })));
    const tbl = el('table', { class: 'list-table', style: 'margin-top:6px' }, el('thead', {}, el('tr', {},
      ...['Partition', 'File system', 'Size', 'Free', 'Mounted', 'Access', ''].map(h => el('th', { text: h })))));
    const tb = el('tbody');
    for (const p of disk.partitions) {
      const access = untag(p.access);
      const ro = access.type === 'readOnly';
      const osName = p.os ? `${p.os.name}${p.os.version ? ' ' + p.os.version : ''}` : '';
      const label = [p.label, osName, p.isEfi ? 'EFI' : '', p.isRecovery ? 'Recovery' : ''].filter(Boolean).join(' · ') || `Partition ${p.number}`;
      const acts = el('div', { class: 'btns' });
      if (p.mount) acts.append(el('button', { class: 'primary', text: 'Browse', onclick: () => go({ type: 'folder', loc: p.mount }) }));
      else if (canRawBrowse(p)) acts.append(el('button', { class: 'primary', text: 'Browse (read-only)', onclick: () => rawBrowse(disk, p) }));
      if (!p.mount && p.fs && mountableHere(p)) acts.append(el('button', { text: ro ? 'Mount read-only' : 'Mount', onclick: () => mountPart(p, ro) }));
      if (p.mount && p.mount !== 'C:\\' && !p.isSystem) acts.append(el('button', { text: 'Unmount', onclick: () => unmountPart(p) }));
      if (p.needsAdmin && !elevated) acts.append(el('span', { class: 'muted', title: 'Reading this partition needs a one-time admin approval', text: '🔒 admin' }));
      const hib = p.hibernated ? el('div', { class: 'warn', text: 'hibernated — read-only' }) : (p.dirty ? el('div', { class: 'warn', text: 'not cleanly unmounted — read-only' }) : null);
      tb.append(el('tr', {},
        el('td', {}, el('b', { text: label }), hib),
        el('td', { text: fsName(p.fs) }),
        el('td', { class: 'num muted', text: fmtSize(p.size) }),
        el('td', { class: 'num muted', text: p.free != null ? fmtSize(p.free) : '' }),
        el('td', { class: 'mono muted', text: p.mount || (p.mounts && p.mounts[0]) || '' }),
        el('td', {}, ro ? el('span', { class: 'warn', title: access.reason, text: 'read-only' }) : el('span', { class: 'good', text: 'read/write' })),
        el('td', {}, acts)));
    }
    tbl.append(tb);
    card.append(tbl);
    wrap.append(card);
  }
  body.append(wrap);
  status(`${disks.length} disk${disks.length > 1 ? 's' : ''}${elevated ? ' · running as admin' : ''}`);
  $('#details').innerHTML = '<p class="muted">Mounted partitions open in the file view. Another OS\'s files open read-only and copy over through the verified queue.</p>';
}
function fsName(fs) { const t = untag(fs).type || fs; return ({ ntfs: 'NTFS', ext4: 'ext4', ext3: 'ext3', ext2: 'ext2', fat32: 'FAT32', fat16: 'FAT16', exfat: 'exFAT', hfsPlus: 'HFS+', apfs: 'APFS', swap: 'swap', unknown: 'unknown' }[t] || t); }
function canRawBrowse(p) { const fs = untag(p.fs).type; return ['ext2', 'ext3', 'ext4', 'ntfs'].includes(fs); }
function mountableHere(p) {
  const fs = untag(p.fs).type;
  const win = navigator.userAgent.includes('Windows');
  if (win) return ['ntfs', 'fat32', 'fat16', 'exfat'].includes(fs); // Windows can't mount ext/HFS
  return !['swap', 'unknown'].includes(fs);
}
async function mountPart(p, readOnly) {
  try { const mp = await invoke('disks_mount', { partitionId: p.id, readOnly }); toast('Mounted at ' + mp); go({ type: 'folder', loc: mp }); }
  catch (e) { fail(e.message ? e.message : errText(e), 'Mount'); }
}
async function unmountPart(p) {
  try { await invoke('disks_unmount', { partitionId: p.id }); toast('Unmounted'); go(S.view, { push: false }); }
  catch (e) { fail(errText(e), 'Unmount'); }
}
async function ejectDisk(disk) {
  try { await invoke('disks_eject', { diskId: disk.id }); toast('Safe to remove ' + (disk.model || disk.id)); go(S.view, { push: false }); }
  catch (e) {
    const er = e && e.type ? e : untag(e);
    if (er.type === 'busy') await modal('Still in use', el('div', {}, el('p', { text: 'These programs still have files open on the drive:' }), el('ul', {}, ...(er.processes || []).map(p => el('li', { text: p })))), [{ label: 'OK', primary: true }]);
    else fail(errText(e), 'Eject');
  }
}
/* A simple read-only browser for an unmounted partition (e.g. ext4 from Windows). */
async function rawBrowse(disk, part, path = '/') {
  const body = el('div', { class: 'raw-browser' });
  const crumb = el('div', { class: 'mono muted', text: `${part.label || fsName(part.fs)} : ${path}` });
  const listing = el('div', { class: 'list' }, el('div', { class: 'empty', text: 'Reading…' }));
  body.append(crumb, listing);
  const close = await modalPersistent(`${part.label || fsName(part.fs)} (read-only)`, body);
  async function load(p) {
    crumb.textContent = `${part.label || fsName(part.fs)} : ${p}`;
    listing.innerHTML = '<div class="empty">Reading…</div>';
    let entries;
    try { entries = await invoke('disks_raw_list', { partition: part, path: p }); }
    catch (e) {
      const er = untag(e);
      listing.innerHTML = '';
      if (er.type === 'needsAdmin') listing.append(el('div', { class: 'empty' }, el('p', { text: 'Reading this partition needs a one-time admin approval.' }), el('button', { class: 'primary', text: 'Reopen with admin', onclick: () => relaunchElevated() })));
      else listing.append(el('div', { class: 'empty', text: errText(e) }));
      return;
    }
    listing.innerHTML = '';
    if (p !== '/') listing.append(el('div', { class: 'raw-row', onclick: () => load(parentPath(p)) }, '📁  ..'));
    entries.sort((a, b) => (b.isDir - a.isDir) || a.name.localeCompare(b.name));
    for (const e of entries) {
      const row = el('div', { class: 'raw-row' }, `${e.isDir ? '📁' : entryIcon({ name: e.name })}  ${e.name}`, el('span', { class: 'muted', style: 'margin-left:auto', text: e.isDir ? '' : fmtSize(e.size) }));
      row.onclick = () => e.isDir ? load(e.path) : rawFileMenu(part, e);
      listing.append(row);
    }
  }
  function parentPath(p) { const s = p.replace(/\/$/, '').split('/'); s.pop(); return s.join('/') || '/'; }
  load(path);
}
async function rawFileMenu(part, e) {
  const action = await modal(e.name, el('div', {}, el('p', { class: 'muted', text: 'This file is on another operating system\'s partition and is read-only here.' })), [
    { label: 'Cancel', value: null }, mediaKind(e.name) ? { label: 'Play', value: 'play' } : { label: 'Open', value: 'open' }, { label: 'Copy to a folder…', value: 'copy', primary: true },
  ]);
  if (!action) return;
  toast('Fetching from the read-only partition…');
  let tmp;
  try { tmp = await invoke('disks_raw_fetch', { partition: part, path: e.path }); }
  catch (err) { fail(errText(err), 'Fetch'); return; }
  const loc = await invoke('fs_normalize', { input: tmp });
  if (action === 'play') playMedia(loc, e.name);
  else if (action === 'open') openWithSystem(loc);
  else if (action === 'copy') {
    const dest = S.view.type === 'folder' ? S.view.loc : null;
    if (dest) startTransfer([loc], dest, 'copy');
    else toast('Open a destination folder first, then try Copy again.');
  }
}
async function relaunchElevated() { toast('Close the app and reopen it as administrator to read raw partitions.'); }

/* ----- folders ----- */
async function showFolder(loc, select) {
  const body = $('#content-body');
  body.innerHTML = '<div class="empty">Loading…</div>';
  const t0 = performance.now();
  try {
    S.entries = await invoke('fs_list', { loc });
  } catch (e) {
    S.entries = [];
    body.innerHTML = '';
    const k = e && e.kind ? untag(e.kind) : null;
    const msg = el('div', { class: 'empty' }, el('p', { text: errText(e) }));
    if (k && (k.type === 'authRequired' || k.type === 'hostKeyUnknown')) {
      msg.append(el('button', { class: 'primary', text: k.type === 'authRequired' ? 'Sign in' : 'Check the key', onclick: () => handleVfsError(e, () => showFolder(loc, select)) }));
      handleVfsError(e, () => showFolder(loc, select));
    } else if (k && k.type === 'offline') {
      msg.append(el('p', { class: 'muted', text: 'The system did not answer. It may be asleep or off the network.' }));
    }
    body.append(msg);
    status('');
    return;
  }
  renderListing(select);
  const ms = Math.round(performance.now() - t0);
  const dirs = S.entries.filter(e => e.isDir).length;
  status(`${S.entries.length} items (${dirs} folders) · ${ms} ms`);
  if (select) showDetailsFor(select);
  else showFolderDetails(loc);
}

function visibleEntries() {
  const f = $('#filter').value.trim().toLowerCase();
  let list = S.entries;
  if (!S.settings.showHidden) list = list.filter(e => !e.hidden);
  if (f) list = list.filter(e => e.name.toLowerCase().includes(f));
  const { key, dir } = S.sort;
  const val = e => key === 'size' ? (e.size ?? -1) : key === 'modified' ? (e.modified ?? 0) : key === 'kind' ? kindLabel(e) : e.name.toLowerCase();
  return [...list].sort((a, b) => (b.isDir - a.isDir) || (val(a) < val(b) ? -dir : val(a) > val(b) ? dir : 0));
}
function kindLabel(e) {
  if (e.kind === 'drive') return 'Drive';
  if (e.kind === 'share') return 'Share';
  if (e.kind === 'system') return 'System';
  if (e.isDir) return 'Folder';
  const m = /\.([^.]+)$/.exec(e.name);
  return m ? m[1].toUpperCase() + ' file' : 'File';
}
function entryIcon(e) {
  if (e.kind === 'drive') return '🖴';
  if (e.kind === 'share') return '🗀';
  if (e.kind === 'system') return '◉';
  if (e.isDir) return '📁';
  if (/\.(png|jpe?g|gif|webp|bmp|heic|svg)$/i.test(e.name)) return '🖼';
  if (/\.(mp4|mov|mkv|avi|webm)$/i.test(e.name)) return '🎞';
  if (/\.(mp3|wav|flac|m4a|ogg)$/i.test(e.name)) return '♪';
  if (/\.(zip|7z|rar|tar|gz|xz)$/i.test(e.name)) return '🗜';
  if (/\.pdf$/i.test(e.name)) return '📕';
  return '📄';
}

function renderListing(select) {
  const body = $('#content-body');
  body.innerHTML = '';
  const list = visibleEntries();
  if (!list.length) { body.append(el('div', { class: 'empty', text: S.entries.length ? 'Nothing matches the filter.' : 'This folder is empty.' })); return; }
  const th = (key, label, cls) => el('th', {
    class: cls, text: label + (S.sort.key === key ? (S.sort.dir > 0 ? ' ▲' : ' ▼') : ''),
    onclick: () => { S.sort = { key, dir: S.sort.key === key ? -S.sort.dir : 1 }; renderListing(); },
  });
  const table = el('table', { class: 'list-table' }, el('thead', {}, el('tr', {},
    th('name', 'Name'), th('modified', 'Modified'), th('kind', 'Type'), th('size', 'Size', 'num'))));
  const tb = el('tbody');
  for (const e of list) {
    const tr = el('tr', {
      class: (S.sel.has(e.loc) ? 'sel ' : '') + (e.hidden ? 'hidden-file' : ''), draggable: 'true', 'data-loc': e.loc,
    },
      el('td', {}, el('span', { text: entryIcon(e) + '  ' }), e.name),
      el('td', { class: 'muted', text: fmtTime(e.modified) }),
      el('td', { class: 'muted', text: kindLabel(e) }),
      el('td', { class: 'num muted', text: e.isDir ? '' : fmtSize(e.size) }));
    tr.addEventListener('click', ev => selectRow(e, ev, list));
    tr.addEventListener('dblclick', () => openEntry(e));
    tr.addEventListener('contextmenu', ev => {
      if (!S.sel.has(e.loc)) { S.sel = new Set([e.loc]); S.anchor = e.loc; paintSel(); showDetailsFor(e.loc); }
      entryMenu(ev.clientX, ev.clientY);
    });
    tr.addEventListener('dragstart', ev => {
      if (!S.sel.has(e.loc)) { S.sel = new Set([e.loc]); paintSel(); }
      ev.dataTransfer.setData('text/x-navsuite', JSON.stringify([...S.sel]));
      ev.dataTransfer.setData('text/plain', [...S.sel].join('\n'));
      ev.dataTransfer.effectAllowed = 'copyMove';
    });
    if (e.isDir) dropTarget(tr, () => e.loc);
    tb.append(tr);
  }
  table.append(tb);
  body.append(table);
  if (select) {
    const row = body.querySelector(`tr[data-loc="${CSS.escape(select)}"]`);
    row && row.scrollIntoView({ block: 'center' });
  }
}
function paintSel() {
  for (const tr of document.querySelectorAll('#content-body tr[data-loc]')) tr.classList.toggle('sel', S.sel.has(tr.dataset.loc));
}
function selectRow(e, ev, list) {
  if (ev.shiftKey && S.anchor) {
    const a = list.findIndex(x => x.loc === S.anchor), b = list.findIndex(x => x.loc === e.loc);
    const [lo, hi] = a < b ? [a, b] : [b, a];
    if (!ev.ctrlKey && !ev.metaKey) S.sel.clear();
    for (let i = lo; i <= hi; i++) S.sel.add(list[i].loc);
  } else if (ev.ctrlKey || ev.metaKey) {
    S.sel.has(e.loc) ? S.sel.delete(e.loc) : S.sel.add(e.loc);
    S.anchor = e.loc;
  } else {
    S.sel = new Set([e.loc]);
    S.anchor = e.loc;
  }
  paintSel();
  if (S.sel.size === 1) showDetailsFor([...S.sel][0]);
  else showMultiDetails();
}
function entryByLoc(loc) { return S.entries.find(e => e.loc === loc); }
async function openEntry(e) {
  if (e.fav && e.loc.startsWith('sys:')) { go({ type: 'system', id: e.loc.slice(4) }); return; }
  if (e.isDir || e.kind === 'drive' || e.kind === 'share') { go({ type: 'folder', loc: e.loc }); return; }
  if (mediaKind(e.name)) { playMedia(e.loc, e.name); return; }
  openWithSystem(e.loc);
}
async function openWithSystem(loc) {
  try { await invoke('fs_open_system', { loc }); log('Opened with the system app: ' + loc); } catch (err) { fail(err, 'Open'); }
}
async function revealInFolder(loc) {
  // Prefer the OS file manager (Explorer/Finder) with the item selected.
  try { await invoke('fs_reveal', { loc }); log('Revealed in file manager: ' + loc); return; }
  catch { /* remote or unsupported path: browse to its parent inside Narada instead */ }
  try {
    const parent = await invoke('fs_parent', { loc });
    if (parent) go({ type: 'folder', loc: parent }, { select: loc });
  } catch (e) { fail(e, 'Show in folder'); }
}

function dropTarget(node, destFn) {
  node.addEventListener('dragover', ev => {
    if (!ev.dataTransfer.types.includes('text/x-navsuite')) return;
    ev.preventDefault();
    ev.dataTransfer.dropEffect = ev.shiftKey ? 'move' : 'copy';
    node.classList.add('drop-target');
  });
  node.addEventListener('dragleave', () => node.classList.remove('drop-target'));
  node.addEventListener('drop', ev => {
    node.classList.remove('drop-target');
    const data = ev.dataTransfer.getData('text/x-navsuite');
    if (!data) return;
    ev.preventDefault();
    const locs = JSON.parse(data);
    const dest = destFn();
    if (locs.includes(dest)) return;
    startTransfer(locs, dest, ev.shiftKey ? 'move' : 'copy');
  });
}

/* ----- systems ----- */
function showSection(id) {
  const sec = SECTIONS.find(s => s.id === id) || SECTIONS[0];
  const list = S.records.filter(r => inSection(r, sec));
  const head = $('#content-head');
  head.append(el('div', { class: 'sys-head' }, el('h2', { text: sec.name }),
    el('span', { class: 'muted', text: S.scanning ? 'Scanning…' : (S.lastScan ? 'Scanned ' + fmtAgo(S.lastScan) : 'Not scanned yet') })));
  if (id === 'tailscale' && S.tailnetError) head.append(el('p', { class: 'warn', text: S.tailnetError }));
  const body = $('#content-body');
  body.innerHTML = '';
  const f = $('#filter').value.trim().toLowerCase();
  const shown = list.filter(r => !f || recName(r).toLowerCase().includes(f) || (r.ips || []).some(i => i.includes(f)))
    .sort((a, b) => (b.online - a.online) || (b.isSelf - a.isSelf) || recName(a).localeCompare(recName(b)));
  if (!shown.length) {
    body.append(el('div', { class: 'empty' }, el('p', { text: S.records.length ? 'No systems in this section.' : 'Press Scan to find the systems on your network and tailnet.' })));
    status('');
    return;
  }
  const table = el('table', { class: 'list-table' }, el('thead', {}, el('tr', {},
    el('th', { text: '' }), el('th', { text: 'Name' }), el('th', { text: 'Kind' }), el('th', { text: 'Addresses' }), el('th', { text: 'Ways in' }))));
  const tb = el('tbody');
  for (const r of shown) {
    const chips = (r.channels || []).filter((c, i, a) => a.findIndex(x => x.kind === c.kind) === i)
      .map(c => el('span', {
        class: 'chip' + (sec.ch && sec.ch.includes(c.kind) ? ' on' : ''), text: CHANNELS[c.kind] || c.kind, title: c.address,
        onclick: ev => { ev.stopPropagation(); useChannel(r, c); },
      }));
    const tr = el('tr', { 'data-id': r.id, class: S.sel.has(r.id) ? 'sel' : '' },
      el('td', {}, el('span', { class: 'dot' + (r.online ? ' on' : ''), title: r.online ? 'Online' : 'Offline' })),
      el('td', {}, el('span', { text: (KIND_ICO[recKind(r)] || '◦') + '  ' }), recName(r), r.isSelf ? el('span', { class: 'muted', text: '  (this computer)' }) : null),
      el('td', { class: 'muted', text: recKind(r) }),
      el('td', { class: 'mono muted', text: (r.ips || []).slice(0, 3).join(', ') }),
      el('td', {}, chips));
    tr.addEventListener('click', () => { S.sel = new Set([r.id]); for (const t of tb.children) t.classList.toggle('sel', t.dataset.id === r.id); showSystemDetails(r); });
    tr.addEventListener('dblclick', () => go({ type: 'system', id: r.id }));
    tr.addEventListener('contextmenu', ev => { S.sel = new Set([r.id]); showSystemDetails(r); systemMenu(r, ev.clientX, ev.clientY); });
    tb.append(tr);
  }
  table.append(tb);
  body.append(table);
  status(`${shown.length} systems · ${shown.filter(r => r.online).length} online`);
  if (!S.sel.size) $('#details').innerHTML = '<p class="muted">Select a system to see every way into it.</p>';
}

function showSystem(id) {
  const r = S.records.find(x => x.id === id);
  const body = $('#content-body');
  body.innerHTML = '';
  if (!r) { body.append(el('div', { class: 'empty', text: 'This system is no longer in the list. Scan again.' })); return; }
  $('#content-head').append(el('div', { class: 'sys-head' },
    el('span', { class: 'dot' + (r.online ? ' on' : '') }), el('h2', { text: recName(r) }),
    el('span', { class: 'muted', text: `${recKind(r)} · ${(r.ips || []).join(', ')}` })));
  const cards = el('div', { class: 'cards' });
  const byKind = {};
  for (const c of r.channels || []) (byKind[c.kind] ||= []).push(c);
  for (const [kind, list] of Object.entries(byKind)) {
    const card = el('div', { class: 'card' }, el('h4', { text: CHANNELS[kind] || kind }));
    for (const c of list) card.append(el('div', { class: 'mono muted', text: c.address }));
    const actions = el('div', { class: 'actions' });
    for (const a of channelActions(r, list[0])) actions.append(el('button', { class: a.primary ? 'primary' : '', text: a.label, onclick: a.run }));
    card.append(actions);
    cards.append(card);
  }
  const probeCard = el('div', { class: 'card' }, el('h4', { text: 'Probes' }), el('div', { class: 'muted', text: 'Ping, traceroute, ports, DNS and HTTP, with results in the Probes tab.' }));
  const pa = el('div', { class: 'actions' });
  for (const [k, label] of [['ping', 'Ping'], ['traceroute', 'Traceroute'], ['dns', 'DNS'], ['http', 'HTTP']]) pa.append(el('button', { text: label, onclick: () => runProbe(bestAddress(r), k) }));
  probeCard.append(pa);
  cards.append(probeCard);
  body.append(cards);
  if (byKind.smb) {
    const shareBox = el('div', { class: 'cards' }, el('div', { class: 'muted', text: 'Loading shares…' }));
    body.append(el('div', { class: 'section-label', style: 'padding:0 12px', text: 'Shares' }), shareBox);
    invoke('fs_list', { loc: byKind.smb[0].address }).then(list => {
      shareBox.innerHTML = '';
      const disks = list.filter(s => s.kind !== 'ipc');
      if (!disks.length) shareBox.append(el('div', { class: 'muted', text: 'No shares are visible.' }));
      for (const s of disks) shareBox.append(el('div', { class: 'card', style: 'cursor:pointer', ondblclick: () => go({ type: 'folder', loc: s.loc }) },
        el('h4', { text: '🗀  ' + s.name }), el('div', { class: 'mono muted', text: s.loc }),
        el('div', { class: 'actions' }, el('button', { class: 'primary', text: 'Open', onclick: () => go({ type: 'folder', loc: s.loc }) }))));
    }).catch(e => {
      shareBox.innerHTML = '';
      const k = e && e.kind ? untag(e.kind) : null;
      shareBox.append(el('div', { class: 'muted', text: errText(e) }));
      if (k && k.type === 'authRequired') shareBox.append(el('button', { text: 'Sign in', onclick: () => handleVfsError(e, () => showSystem(id)) }));
    });
  }
  showSystemDetails(r);
  status(`${(r.channels || []).length} ways in · ${(r.services || []).length} services`);
}

function bestAddress(r) {
  const ip = (r.ips || []).find(i => /^\d+\.\d+\.\d+\.\d+$/.test(i) && !i.startsWith('100.')) || (r.ips || [])[0];
  return ip || r.name;
}
function sshTarget(r, c) {
  const m = /^(?:ssh|sftp):\/\/([^/]+)/i.exec(c?.address || '');
  if (!m) return { target: bestAddress(r), port: null };
  let hostport = m[1];
  let port = null;
  const pm = /:(\d+)$/.exec(hostport);
  if (pm) { port = Number(pm[1]); hostport = hostport.slice(0, -pm[0].length); }
  return { target: hostport, port };
}
function channelActions(r, c) {
  const a = [];
  switch (c.kind) {
    case 'smb': a.push({ label: 'Browse shares', primary: true, run: () => go({ type: 'folder', loc: c.address }) }); break;
    case 'ssh': case 'sftp': {
      const sftp = (channel(r, 'sftp') || c).address.replace(/^ssh:/i, 'sftp:');
      a.push({ label: 'Browse files', primary: true, run: () => go({ type: 'folder', loc: sftp.replace(/\/?$/, '/') }) });
      a.push({ label: 'Open terminal', run: () => { const t = sshTarget(r, channel(r, 'ssh') || c); newTerminal({ ssh: t.target, sshPort: t.port, shell: S.settings.systems?.[r.id]?.shell || '' }); } });
      break;
    }
    case 'web': case 'printer': case 'rdp': case 'vnc': case 'cast':
      if (/^[a-z]+:\/\//i.test(c.address)) a.push({ label: c.kind === 'web' ? 'Open web page' : 'Open', primary: true, run: () => openUrl(c.address) });
      break;
    case 'ftp': a.push({ label: 'Open', run: () => openUrl(c.address) }); break;
    default: a.push({ label: 'Details', run: () => showSystemDetails(r) });
  }
  return a;
}
function useChannel(r, c) {
  const acts = channelActions(r, c);
  (acts.find(x => x.primary) || acts[0])?.run();
}
async function openUrl(url) {
  try { await invoke('open_url', { url }); log('Opened ' + url); } catch (e) { fail(e, 'Open'); }
}

/* ---------- details pane ---------- */
function dl(pairs) {
  const d = el('dl');
  for (const [k, v] of pairs) if (v != null && v !== '') d.append(el('dt', { text: k }), el('dd', { text: v }));
  return d;
}
async function pathForms(loc, host) {
  try {
    const forms = await invoke('fs_forms', { loc });
    S.forms = forms;
    host.innerHTML = '';
    for (const f of forms) host.append(el('button', { title: f.label, text: f.value, onclick: () => copyText(f.value, f.label) }));
  } catch (e) { host.textContent = errText(e); }
}
async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); toast(`Copied ${what ? what.toLowerCase() : ''}: ${text}`); }
  catch { try { await invoke('clipboard_write', { text }); toast('Copied'); } catch (e) { fail(e, 'Copy'); } }
}
function showFolderDetails(loc) {
  const d = $('#details');
  d.innerHTML = '';
  d.append(el('h3', { text: crumbParts(loc).at(-1)?.label || loc }));
  const cp = el('details', { class: 'copypath' });
  cp.append(el('summary', { text: 'Copy path' }));
  const forms = el('div', { class: 'forms' });
  cp.append(forms);
  d.append(cp);
  pathForms(loc, forms);
  d.append(el('div', { class: 'btn-row' },
    el('button', { text: 'Open terminal here', onclick: () => terminalHere(loc) }),
    el('button', { text: 'Open in system app', onclick: () => openWithSystem(loc) }),
    el('button', { text: 'Add to favourites', onclick: () => addFavourite(crumbParts(loc).at(-1)?.label || loc, loc) })));
}
function showMultiDetails() {
  const d = $('#details');
  const items = [...S.sel].map(entryByLoc).filter(Boolean);
  const bytes = items.reduce((a, e) => a + (e.size || 0), 0);
  d.innerHTML = '';
  d.append(el('h3', { text: `${items.length} items selected` }));
  d.append(dl([['Files', items.filter(e => !e.isDir).length], ['Folders', items.filter(e => e.isDir).length], ['Size', fmtSize(bytes) + (items.some(e => e.isDir) ? ' + folders' : '')]]));
  d.append(el('div', { class: 'btn-row' },
    el('button', { text: 'Copy', onclick: () => clipSet('copy') }), el('button', { text: 'Cut', onclick: () => clipSet('move') }),
    el('button', { text: 'Copy paths', onclick: () => copyText(items.map(e => e.loc).join('\n'), 'paths') })));
}
async function showDetailsFor(loc) {
  const e = entryByLoc(loc);
  const d = $('#details');
  d.innerHTML = '';
  if (!e) return;
  if (e.fav && loc.startsWith('sys:')) { const r = S.records.find(x => x.id === loc.slice(4)); r && showSystemDetails(r); return; }
  d.append(el('h3', { text: e.name }));
  const prev = el('div', { class: 'preview', hidden: true });
  d.append(prev);
  d.append(dl([['Type', kindLabel(e)], ['Size', e.isDir ? '' : fmtSize(e.size) + (e.size ? ` (${e.size.toLocaleString()} bytes)` : '')], ['Modified', fmtTime(e.modified)], ['Hidden', e.hidden ? 'yes' : ''], ['Link', e.isLink ? 'yes' : '']]));
  const cp = el('details', { class: 'copypath' });
  cp.append(el('summary', { text: 'Copy path' }));
  const forms = el('div', { class: 'forms' });
  cp.append(forms);
  d.append(cp);
  pathForms(loc, forms);
  const isLocal = !/^(smb|sftp):/i.test(loc) || navigator.userAgent.includes('Windows') && /^smb:/i.test(loc);
  d.append(el('div', { class: 'btn-row' },
    e.isDir ? el('button', { text: 'Open', onclick: () => openEntry(e) })
      : mediaKind(e.name) ? el('button', { class: 'primary', text: (mediaKind(e.name) === 'audio' ? '♪ Play' : '▶ Play'), onclick: () => playMedia(loc, e.name) })
        : el('button', { text: 'Open with system app', onclick: () => openWithSystem(loc) }),
    !e.isDir && mediaKind(e.name) ? el('button', { text: 'Open with system app', onclick: () => openWithSystem(loc) }) : null,
    el('button', { text: 'Show in folder', onclick: () => revealInFolder(loc) }),
    el('button', { text: 'Terminal here', onclick: () => terminalHere(e.isDir ? loc : null, loc) }),
    !e.isDir && S.phones.length && isLocal ? el('button', { text: 'Send to phone', onclick: ev => sendToPhoneMenu([loc], ev.clientX, ev.clientY) }) : null));
  if (!e.isDir && e.kind === 'file') loadPreview(e, prev);
}
async function loadPreview(e, box) {
  const ext = (/\.([^.]+)$/.exec(e.name) || [])[1]?.toLowerCase() || '';
  const isImg = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'].includes(ext);
  const isPdf = ext === 'pdf';
  const isHtml = ext === 'html' || ext === 'htm';
  const isText = /^(txt|md|log|json|ya?ml|toml|ini|cfg|conf|csv|tsv|xml|html?|css|js|ts|jsx|tsx|rs|py|go|java|kt|c|h|cpp|hpp|cs|sh|ps1|bat|sql|rb|php|swift|env|gitignore|dockerfile)$/.test(ext) || (!ext && (e.size || 0) < 65536);
  if (!isImg && !isPdf && !isText) return;
  const max = isText ? 256 * 1024 : 12 * 1024 * 1024;
  if (!isText && (e.size || 0) > max) { box.hidden = false; box.append(el('pre', { text: `Too large to preview here (${fmtSize(e.size)}). Open it with the system app.` })); return; }
  try {
    const p = await invoke('fs_preview', { loc: e.loc, maxBytes: max });
    if (S.sel.size !== 1 || !S.sel.has(e.loc)) return;
    box.hidden = false;
    if (isImg) box.append(el('img', { src: `data:${p.mime};base64,${p.bytesBase64}`, alt: e.name }));
    else if (isPdf) box.append(el('iframe', { class: 'doc-frame', src: `data:application/pdf;base64,${p.bytesBase64}`, title: e.name }));
    else if (isHtml) {
      // Render the page with the built-in engine; sandboxed (no scripts) since the file is untrusted.
      const frame = el('iframe', { class: 'doc-frame', title: e.name, sandbox: '', src: `data:text/html;base64,${p.bytesBase64}` });
      const bytes = Uint8Array.from(atob(p.bytesBase64), c => c.charCodeAt(0));
      const pre = el('pre', { text: new TextDecoder('utf-8', { fatal: false }).decode(bytes), hidden: true });
      let src = false;
      const toggle = el('button', { text: 'View source', onclick: () => { src = !src; frame.hidden = src; pre.hidden = !src; toggle.textContent = src ? 'View rendered' : 'View source'; } });
      box.append(el('div', { class: 'preview-bar' }, toggle), frame, pre);
    } else {
      const bytes = Uint8Array.from(atob(p.bytesBase64), c => c.charCodeAt(0));
      let text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      if (p.truncated) text += '\n… (first ' + fmtSize(bytes.length) + ')';
      box.append(el('pre', { text }));
    }
  } catch (err) { box.hidden = false; box.append(el('pre', { text: 'No preview: ' + errText(err) })); }
}

function showSystemDetails(r) {
  const d = $('#details');
  d.innerHTML = '';
  const note = S.settings.systems?.[r.id] || {};
  d.append(el('h3', {}, el('span', { class: 'dot' + (r.online ? ' on' : '') }), ' ', recName(r)));
  d.append(dl([
    ['Kind', recKind(r)], ['Status', r.online ? 'Online' : ('Offline' + (r.lastSeen ? ', seen ' + fmtAgo(r.lastSeen) : ''))],
    ['Addresses', (r.ips || []).join(', ')], ['MAC', r.mac],
  ]));
  if ((r.names || []).length) {
    d.append(el('div', { class: 'section-label', text: 'Names' }));
    d.append(dl(r.names.map(n => [n.source, n.name])));
  }
  d.append(el('div', { class: 'section-label', text: 'Ways in' }));
  const ways = el('div', { class: 'forms' });
  for (const c of r.channels || []) ways.append(el('button', { title: 'Use this way in', text: `${CHANNELS[c.kind] || c.kind}: ${c.address}`, onclick: () => useChannel(r, c) }));
  d.append(ways);
  if ((r.services || []).length) {
    d.append(el('div', { class: 'section-label', text: 'Services' }));
    d.append(dl(r.services.map(s => [`${s.port}/${s.proto}`, `${s.label}${s.name ? ' · ' + s.name : ''} (${s.source})`])));
  }
  d.append(el('div', { class: 'section-label', text: 'Probe' }));
  d.append(el('div', { class: 'btn-row' }, ...[['ping', 'Ping'], ['traceroute', 'Traceroute'], ['dns', 'DNS'], ['http', 'HTTP']].map(([k, l]) => el('button', { text: l, onclick: () => runProbe(bestAddress(r), k) }))));
  d.append(el('div', { class: 'section-label', text: 'Your label and notes' }));
  const label = el('input', { value: note.label || '', placeholder: r.name, style: 'width:100%' });
  const kind = el('select', { style: 'width:100%;margin-top:4px' }, ...['', 'computer', 'windows', 'server', 'pi', 'nas', 'router', 'printer', 'phone', 'tv', 'media', 'iot', 'device'].map(k => el('option', { value: k, text: k ? k : `Kind: ${r.kind} (guessed)`, selected: (note.kind || '') === k })));
  const shell = el('select', { style: 'width:100%;margin-top:4px' }, el('option', { value: '', text: 'Terminal shell: default' }), ...S.shells.map(s => el('option', { value: s.id, text: 'Terminal shell: ' + s.name, selected: note.shell === s.id })));
  const notes = el('textarea', { placeholder: 'Notes' }, note.notes || '');
  const save = el('button', { class: 'primary', text: 'Save', onclick: async () => {
    S.settings.systems ||= {};
    S.settings.systems[r.id] = { ...note, label: label.value.trim() || null, kind: kind.value || null, shell: shell.value || null, notes: notes.value.trim() || null };
    await saveSettings();
    toast('Saved');
    render();
  } });
  d.append(label, kind, shell, notes, el('div', { class: 'btn-row' }, save, el('button', { text: 'Add to favourites', onclick: () => addFavourite(recName(r), 'sys:' + r.id) })));
}

/* ---------- context menus ---------- */
function selectedEntries() { return [...S.sel].map(entryByLoc).filter(Boolean); }
function entryMenu(x, y) {
  const items = selectedEntries();
  if (!items.length) return;
  const one = items.length === 1 ? items[0] : null;
  const locs = items.map(e => e.loc);
  const formsSub = one ? [{ label: 'Loading…', disabled: true }] : null;
  const m = [
    one && mediaKind(one.name) && { label: 'Play', key: 'Enter', run: () => playMedia(one.loc, one.name) },
    one && { label: one.isDir ? 'Open' : (mediaKind(one.name) ? 'Open with system app' : 'Open with system app'), key: mediaKind(one?.name) ? '' : 'Enter', run: () => (mediaKind(one.name) ? openWithSystem(one.loc) : openEntry(one)) },
    one && one.isDir && { label: 'Open in system app', run: () => openWithSystem(one.loc) },
    one && { label: 'Show in containing folder', run: () => revealInFolder(one.loc) },
    '-',
    { label: 'Copy', key: 'Ctrl+C', run: () => clipSet('copy') },
    { label: 'Cut', key: 'Ctrl+X', run: () => clipSet('move') },
    one && one.isDir && S.clip && { label: 'Paste into this folder', key: 'Ctrl+V', run: () => paste(one.loc) },
    '-',
    one && { label: 'Copy path', sub: formsSub },
    !one && { label: 'Copy paths', run: () => copyText(locs.join('\n'), 'paths') },
    { label: 'Open terminal here', key: 'Ctrl+Shift+T', run: () => terminalHere(one && one.isDir ? one.loc : null, one?.loc) },
    S.phones.length && { label: 'Send to phone', sub: S.phones.map(p => ({ label: p.name, run: () => sendToPhone(p.id, locs) })) },
    '-',
    one && { label: 'Rename', key: 'F2', run: () => renameEntry(one) },
    { label: 'Delete', key: 'Del', run: () => deleteEntries(items) },
    '-',
    S.view.type === 'folder' && { label: 'New folder', key: 'Ctrl+Shift+N', run: newFolder },
    one && one.isDir && { label: 'Add to favourites', run: () => addFavourite(one.name, one.loc) },
  ];
  if (one) {
    invoke('fs_forms', { loc: one.loc }).then(forms => {
      formsSub.length = 0;
      for (const f of forms) formsSub.push({ label: `${f.label}:  ${f.value}`, mono: true, run: () => copyText(f.value, f.label) });
    }).catch(() => { formsSub[0] = { label: one.loc, mono: true, run: () => copyText(one.loc) }; });
  }
  menu(m.filter(Boolean), x, y);
}
function systemMenu(r, x, y) {
  const addr = bestAddress(r);
  const acts = (r.channels || []).filter((c, i, a) => a.findIndex(z => z.kind === c.kind) === i)
    .flatMap(c => channelActions(r, c).map(a => ({ label: `${a.label} (${CHANNELS[c.kind] || c.kind})`, run: a.run })));
  menu([
    { label: 'Open', key: 'Enter', run: () => go({ type: 'system', id: r.id }) },
    '-', ...acts, '-',
    { label: 'Ping', run: () => runProbe(addr, 'ping') },
    { label: 'Traceroute', run: () => runProbe(addr, 'traceroute') },
    { label: 'Port check…', run: async () => { const p = await ask('Port check', 'Port', '22'); if (p) runProbe(addr, 'port', Number(p)); } },
    '-',
    { label: 'Copy address', sub: [...(r.ips || []).map(i => ({ label: i, mono: true, run: () => copyText(i, 'address') })), ...(r.channels || []).map(c => ({ label: c.address, mono: true, run: () => copyText(c.address, 'address') }))] },
    { label: 'Add to favourites', run: () => addFavourite(recName(r), 'sys:' + r.id) },
  ], x, y);
}

/* ---------- file operations ---------- */
function clipSet(op) {
  const locs = [...S.sel];
  if (!locs.length) return;
  S.clip = { op, locs };
  toast(`${op === 'copy' ? 'Copied' : 'Cut'} ${locs.length} item${locs.length > 1 ? 's' : ''}. Paste in any folder.`);
}
async function paste(dest) {
  dest = dest || (S.view.type === 'folder' ? S.view.loc : null);
  if (!S.clip || !dest) return;
  const { op, locs } = S.clip;
  const ok = await startTransfer(locs, dest, op);
  if (ok && op === 'move') S.clip = null;
}
/* Copy preview (E7), then the queue (E8, E9). */
async function startTransfer(locs, dest, op) {
  let plan;
  try { plan = await invoke('xfer_plan', { sources: locs, dest, op }); }
  catch (e) { fail(e, 'Planning the copy'); return false; }
  const body = el('div');
  body.append(el('div', { class: 'stat-row' },
    el('div', {}, el('b', { text: plan.files.toLocaleString() }), 'files'),
    el('div', {}, el('b', { text: plan.dirs.toLocaleString() }), 'folders'),
    el('div', {}, el('b', { text: fmtSize(plan.totalBytes) }), 'to copy'),
    el('div', {}, el('b', { class: plan.enoughSpace === false ? 'bad' : '', text: plan.freeSpace != null ? fmtSize(plan.freeSpace) : 'unknown' }), 'free at target')));
  body.append(el('p', { class: 'muted mono', text: `${op === 'move' ? 'Move' : 'Copy'} to ${dest}` }));
  if (plan.enoughSpace === false) body.append(el('p', { class: 'bad', text: 'There is not enough free space at the target.' }));
  const res = {};
  if (plan.conflicts.length) {
    const all = el('select', {}, ...['keepBoth', 'replace', 'skip'].map(v => el('option', { value: v, text: { replace: 'Replace all', skip: 'Skip all', keepBoth: 'Keep both for all' }[v] })));
    const rows = [];
    body.append(el('p', {}, el('b', { text: `${plan.conflicts.length} already exist at the target. ` }), all));
    const table = el('table', {}, el('tr', {}, el('th', { text: 'File' }), el('th', { text: 'Source' }), el('th', { text: 'Target' }), el('th', { text: 'Action' })));
    for (const c of plan.conflicts.slice(0, 500)) {
      const sel = el('select', {}, ...['keepBoth', 'replace', 'skip'].map(v => el('option', { value: v, text: { replace: 'Replace', skip: 'Skip', keepBoth: 'Keep both' }[v] })));
      res[c.dst] = 'keepBoth';
      sel.onchange = () => (res[c.dst] = sel.value);
      rows.push([c.dst, sel]);
      const newer = (c.srcModified || 0) > (c.dstModified || 0);
      table.append(el('tr', {}, el('td', { class: 'mono', text: c.dst.split(/[\\/]/).pop() }),
        el('td', { text: `${fmtSize(c.srcSize)} · ${fmtTime(c.srcModified)}${newer ? ' (newer)' : ''}` }),
        el('td', { text: `${fmtSize(c.dstSize)} · ${fmtTime(c.dstModified)}` }), el('td', {}, sel)));
    }
    all.onchange = () => { for (const [dst, sel] of rows) { sel.value = all.value; res[dst] = all.value; } for (const c of plan.conflicts) res[c.dst] = all.value; };
    body.append(table);
  }
  if (plan.skipped.length) {
    body.append(el('p', { class: 'warn', text: `${plan.skipped.length} will be skipped:` }));
    body.append(el('ul', {}, ...plan.skipped.slice(0, 20).map(s => el('li', { class: 'mono', text: `${s.src} (${s.reason})` }))));
  }
  const verify = el('input', { type: 'checkbox', checked: S.settings.verifyCopies !== false });
  const manifest = el('input', { type: 'checkbox', checked: !!S.settings.writeManifest });
  body.append(el('p', {}, el('label', { style: 'display:inline;color:inherit' }, verify, ' Check every file against the source with SHA-256')),
    el('p', {}, el('label', { style: 'display:inline;color:inherit' }, manifest, ' Write a SHA256SUMS file in the target folder')));
  if (!plan.items.length) { await modal('Nothing to copy', body, [{ label: 'Close', primary: true }]); return false; }
  const go2 = await modal(op === 'move' ? 'Move preview' : 'Copy preview', body, [{ label: 'Cancel', value: null }, { label: op === 'move' ? 'Start moving' : 'Start copying', primary: true, value: true }]);
  if (!go2) return false;
  try {
    const id = await invoke('xfer_enqueue', { plan, resolutions: res, verify: verify.checked, manifest: manifest.checked });
    log(`Transfer ${id}: ${op} ${plan.files} files (${fmtSize(plan.totalBytes)}) to ${dest}`);
    openDock('transfers');
    return true;
  } catch (e) { fail(e, 'Starting the copy'); return false; }
}
async function renameEntry(e) {
  const name = await ask('Rename', 'New name', e.name);
  if (!name || name === e.name) return;
  try {
    const parent = await invoke('fs_parent', { loc: e.loc });
    const to = await invoke('fs_join', { loc: parent, name });
    await invoke('fs_rename', { from: e.loc, to });
    log(`Renamed ${e.loc} to ${name}`);
    go(S.view, { push: false, select: to });
  } catch (err) { handleVfsError(err); }
}
async function deleteEntries(items) {
  const remote = items.some(e => /^(sftp|smb):/i.test(e.loc) || e.loc.startsWith('\\\\'));
  const body = el('div', {}, el('p', { text: items.length === 1 ? items[0].name : `${items.length} items` }),
    remote ? el('p', { class: 'warn', text: 'These are on another system. There is no trash there, so the delete is permanent.' })
      : el('p', { class: 'muted', text: 'Local items go to the system trash.' }));
  const ok = await modal('Delete?', body, [{ label: 'Cancel', value: null }, { label: 'Delete', primary: true, value: true }]);
  if (!ok) return;
  for (const e of items) {
    try { const r = await invoke('fs_remove', { loc: e.loc, recursive: true }); log(`${r.trashed ? 'Moved to trash' : 'Deleted'}: ${e.loc}`); }
    catch (err) { fail(err, 'Delete ' + e.name); }
  }
  go(S.view, { push: false });
}
async function newFolder() {
  if (S.view.type !== 'folder') return;
  const name = await ask('New folder', 'Name', 'New folder');
  if (!name) return;
  try {
    const loc = await invoke('fs_join', { loc: S.view.loc, name });
    await invoke('fs_mkdir', { loc });
    go(S.view, { push: false, select: loc });
  } catch (e) { handleVfsError(e); }
}
async function addFavourite(name, target) {
  S.settings.favourites ||= [];
  if (S.settings.favourites.some(f => f.target === target)) { toast('Already a favourite'); return; }
  S.settings.favourites.push({ name, target });
  await saveSettings();
  toast('Added to favourites');
  renderSidebar();
  buildTree();
}

/* ---------- tree (V3) ---------- */
function treeNode(label, ico, opts) {
  const li = el('li');
  const twisty = el('span', { class: 'twisty', text: opts.load ? '▸' : '' });
  const row = el('div', { class: 'row', title: opts.title || label }, twisty, el('span', { text: ico }), el('span', { class: 'label', text: label }));
  if (opts.view) row.dataset.view = JSON.stringify(opts.view);
  li.append(row);
  let open = false, ul = null;
  const toggle = async () => {
    if (!opts.load) return;
    open = !open;
    twisty.textContent = open ? '▾' : '▸';
    if (!open) { ul && ul.remove(); ul = null; return; }
    ul = el('ul', {}, el('li', { class: 'muted', text: '…' }));
    li.append(ul);
    try {
      const kids = await opts.load();
      ul.innerHTML = '';
      if (!kids.length) ul.append(el('li', { class: 'muted', style: 'padding-left:18px', text: 'empty' }));
      for (const k of kids) ul.append(k);
    } catch (e) { ul.innerHTML = ''; ul.append(el('li', { class: 'muted', style: 'padding-left:18px', text: errText(e).slice(0, 60) })); }
  };
  twisty.addEventListener('click', ev => { ev.stopPropagation(); toggle(); });
  row.addEventListener('click', () => { if (opts.view) go(opts.view); else toggle(); });
  row.addEventListener('dblclick', toggle);
  if (opts.dropLoc) dropTarget(row, () => opts.dropLoc);
  if (opts.expanded) setTimeout(toggle);
  return li;
}
const folderKids = loc => async () => {
  const list = await invoke('fs_list', { loc });
  return list.filter(e => (e.isDir || e.kind === 'share' || e.kind === 'drive') && (S.settings.showHidden || !e.hidden) && e.kind !== 'ipc')
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(e => treeNode(e.name, e.kind === 'share' ? '🗀' : e.kind === 'drive' ? '🖴' : '📁', { view: { type: 'folder', loc: e.loc }, load: folderKids(e.loc), dropLoc: e.loc, title: e.loc }));
};
function systemKids(r) {
  return async () => {
    const out = [];
    const smb = channel(r, 'smb');
    if (smb) out.push(treeNode('SMB shares', '🗀', { view: { type: 'folder', loc: smb.address }, load: folderKids(smb.address) }));
    const sftp = channel(r, 'sftp', 'ssh');
    if (sftp) { const loc = sftp.address.replace(/^ssh:/i, 'sftp:').replace(/\/?$/, '/'); out.push(treeNode('SFTP files', '🗁', { view: { type: 'folder', loc }, load: folderKids(loc) })); }
    for (const c of r.channels || []) if (['web', 'printer'].includes(c.kind)) out.push(treeNode(`${CHANNELS[c.kind]} ${c.address}`, '◎', { view: null, title: c.address }));
    return out;
  };
}
function buildTree() {
  const t = $('#tree');
  t.innerHTML = '';
  const ul = el('ul');
  ul.append(treeNode('This computer', '💻', { view: { type: 'roots' }, expanded: true, load: async () => {
    const roots = await invoke('fs_roots');
    return roots.map(e => treeNode(e.name, e.kind === 'drive' ? '🖴' : '📁', { view: { type: 'folder', loc: e.loc }, load: folderKids(e.loc), dropLoc: e.loc, title: e.loc }));
  } }));
  const favs = S.settings.favourites || [];
  if (favs.length) ul.append(treeNode('Favourites', '★', { view: { type: 'favourites' }, load: async () => favs.map(f => f.target.startsWith('sys:')
    ? treeNode(f.name, '◉', { view: { type: 'system', id: f.target.slice(4) } })
    : treeNode(f.name, '📁', { view: { type: 'folder', loc: f.target }, load: folderKids(f.target), dropLoc: f.target })) }));
  ul.append(treeNode('Network', '🌐', { view: { type: 'section', id: 'all' }, expanded: true, load: async () =>
    SECTIONS.filter(s => s.id !== 'all').map(sec => ({ sec, list: S.records.filter(r => inSection(r, sec)) })).filter(x => x.list.length).map(({ sec, list }) =>
      treeNode(`${sec.name} (${list.length})`, sec.ico, { view: { type: 'section', id: sec.id }, load: async () =>
        list.sort((a, b) => recName(a).localeCompare(recName(b))).map(r => treeNode(recName(r), KIND_ICO[recKind(r)] || '◦', { view: { type: 'system', id: r.id }, load: systemKids(r) })) })) }));
  t.append(ul);
  markTree();
}
function markTree() {
  const cur = JSON.stringify(S.view);
  for (const r of document.querySelectorAll('#tree .row')) r.classList.toggle('active', r.dataset.view === cur);
}

/* ---------- scanning ---------- */
async function scan() {
  if (S.scanning) { invoke('scan_cancel'); return; }
  S.scanning = true;
  $('#btn-scan').textContent = 'Stop';
  renderSidebar();
  log('Scan started');
  try { await invoke('scan_start'); } catch (e) { fail(e, 'Scan'); S.scanning = false; $('#btn-scan').textContent = 'Scan'; }
}
function onScanEvent(ev) {
  const e = untag(ev);
  if (e.type === 'started') log('Scanning ' + (e.subnets || []).join(', '));
  else if (e.type === 'log') log(e.message);
  else if (e.type === 'progress') status(`Scanning: ${e.phase} ${e.done}/${e.total}`);
  else if (e.type === 'tailnetError') { S.tailnetError = e.message; log('Tailscale: ' + e.message); }
  else if (e.type === 'done') {
    S.scanning = false;
    S.lastScan = Date.now();
    $('#btn-scan').textContent = 'Scan';
    log(`Scan finished: ${e.systems ?? e.hosts} systems in ${((e.millis || 0) / 1000).toFixed(1)} s${e.cancelled ? ' (stopped)' : ''}`);
    status(`Scan finished in ${((e.millis || 0) / 1000).toFixed(1)} s`);
    renderSidebar();
  }
}
let recordsTimer;
function onRecords(list) {
  S.records = list || [];
  clearTimeout(recordsTimer);
  recordsTimer = setTimeout(() => {
    renderSidebar();
    if (S.view.type === 'section') { const keep = new Set(S.sel); showSection(S.view.id); S.sel = keep; }
    if (S.view.type === 'system' && !document.querySelector('#modal:not([hidden])')) { /* keep the page stable while scanning */ }
    buildTree();
  }, 250);
}

/* ---------- terminal (E5, E11–E13) ---------- */
async function loadShells() {
  try { S.shells = await invoke('term_shells'); } catch (e) { S.shells = []; fail(e, 'Shells'); }
  const sel = $('#term-shell');
  sel.innerHTML = '';
  for (const s of S.shells) sel.append(el('option', { value: s.id, text: s.name, selected: s.id === S.settings.defaultShell }));
  sel.onchange = async () => { S.settings.defaultShell = sel.value; await saveSettings(); };
}
function termTheme() {
  return { background: '#111111', foreground: '#e6e6e6', cursor: '#e6e6e6', selectionBackground: '#3a5a8a' };
}
async function newTerminal(opts = {}) {
  showDock('terminal');
  if (typeof Terminal === 'undefined' || typeof FitAddon === 'undefined') {
    fail('The terminal component failed to load.', 'Terminal');
    return;
  }
  const div = el('div', { class: 'term' });
  $('#term-host').append(div);
  let term, fit;
  try {
    term = new Terminal({ fontFamily: getComputedStyle(document.body).getPropertyValue('--mono'), fontSize: 13, cursorBlink: true, theme: termTheme(), scrollback: 5000, allowProposedApi: false });
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(div);
    activateTermDiv(div);
    fit.fit();
  } catch (e) { div.remove(); fail(e, 'Terminal'); return; }
  const shellId = opts.shell || $('#term-shell').value || '';
  let id;
  try {
    id = await invoke('term_spawn', { start: { shell: shellId, cwd: opts.cwd || null, ssh: opts.ssh || null, sshPort: opts.sshPort || null, remoteDir: opts.remoteDir || null, cols: term.cols, rows: term.rows } });
  } catch (e) { div.remove(); fail(e, 'Terminal'); return; }
  const label = opts.ssh ? `ssh ${opts.ssh}` : (S.shells.find(s => s.id === shellId)?.name || 'Shell') + (opts.cwd ? ' · ' + opts.cwd.split(/[\\/]/).filter(Boolean).pop() : '');
  const tab = el('span', { class: 'term-tab', title: opts.cwd || opts.ssh || '' }, el('span', { text: label }), el('span', { class: 'x', text: '×', onclick: ev => { ev.stopPropagation(); closeTerm(id); } }));
  tab.addEventListener('click', () => activateTerm(id));
  $('#term-tabs').insertBefore(tab, $('#term-shell'));
  S.terms.set(id, { term, fit, div, tab, shell: shellId });
  // Flush any output that streamed in before this tab was registered (the shell's first prompt).
  const early = S.termPending.get(id);
  if (early) { for (const b of early) term.write(b); S.termPending.delete(id); }
  term.onData(data => invoke('term_write', { id, data }).catch(() => {}));
  term.onResize(({ cols, rows }) => invoke('term_resize', { id, cols, rows }).catch(() => {}));
  // Drop files from the listing into the terminal: paste their paths quoted for this shell (E13).
  div.addEventListener('dragover', ev => { if (ev.dataTransfer.types.includes('text/x-navsuite')) ev.preventDefault(); });
  div.addEventListener('drop', async ev => {
    const data = ev.dataTransfer.getData('text/x-navsuite');
    if (!data) return;
    ev.preventDefault();
    const locs = JSON.parse(data);
    const parts = await Promise.all(locs.map(l => invoke('term_quote', { shell: shellId, path: l }).catch(() => l)));
    invoke('term_write', { id, data: parts.join(' ') + ' ' });
    term.focus();
  });
  activateTerm(id);
  term.focus();
}
function activateTermDiv(div) { for (const d of document.querySelectorAll('#term-host .term')) d.classList.toggle('active', d === div); }
function activateTerm(id) {
  S.activeTerm = id;
  for (const [tid, t] of S.terms) { t.div.classList.toggle('active', tid === id); t.tab.classList.toggle('active', tid === id); }
  const t = S.terms.get(id);
  if (t) setTimeout(() => { t.fit.fit(); t.term.focus(); }, 0);
}
function closeTerm(id) {
  const t = S.terms.get(id);
  if (!t) return;
  invoke('term_close', { id }).catch(() => {});
  t.term.dispose(); t.div.remove(); t.tab.remove();
  S.terms.delete(id);
  const next = [...S.terms.keys()].pop();
  if (next != null) activateTerm(next);
}
/* Open a terminal in a folder; for SFTP folders, ssh to the host and cd there (E5). */
async function terminalHere(folderLoc, anyLoc) {
  let loc = folderLoc;
  if (!loc && anyLoc) loc = await invoke('fs_parent', { loc: anyLoc }).catch(() => null);
  if (!loc && S.view.type === 'folder') loc = S.view.loc;
  if (!loc) { newTerminal(); return; }
  const m = /^sftp:\/\/([^/]+)(\/.*)?$/i.exec(loc);
  if (m) {
    let hp = m[1], port = null;
    const pm = /:(\d+)$/.exec(hp);
    if (pm) { port = Number(pm[1]); hp = hp.slice(0, -pm[0].length); }
    const sys = systemForLoc(loc);
    newTerminal({ ssh: hp, sshPort: port, remoteDir: decodeURIComponent(m[2] || '/'), shell: sys ? S.settings.systems?.[sys.id]?.shell : '' });
    return;
  }
  let cwd = loc;
  if (/^smb:/i.test(loc)) {
    try { cwd = (await invoke('fs_forms', { loc })).find(f => /UNC|mount/i.test(f.label))?.value || loc; } catch { /* keep */ }
  }
  newTerminal({ cwd });
}

/* ---------- probes (E6) ---------- */
async function runProbe(target, kind, port) {
  openDock('probes');
  $('#probe-target').value = target;
  $('#probe-kind').value = kind;
  $('#probe-port').hidden = kind !== 'port';
  if (port) $('#probe-port').value = port;
  if (S.probeId != null) await invoke('probe_cancel', { id: S.probeId }).catch(() => {});
  const out = $('#probe-out');
  out.textContent = `${kind} ${target}${port ? ':' + port : ''}\n`;
  const k = kind === 'ping' ? { kind: 'ping', count: 4 } : kind === 'traceroute' ? { kind: 'traceroute', maxHops: 30 }
    : kind === 'port' ? { kind: 'port', port: Number(port || $('#probe-port').value || 22) } : kind === 'dns' ? { kind: 'dns' } : { kind: 'http', url: null };
  try { S.probeId = await invoke('probe_run', { target, kind: k }); }
  catch (e) { out.textContent += 'Failed: ' + errText(e) + '\n'; }
}
function onProbeEvent({ id, event }) {
  if (id !== S.probeId) return;
  const out = $('#probe-out');
  const e = untag(event);
  const ms = v => v == null ? '*' : v.toFixed(1) + ' ms';
  if (e.type === 'line') out.textContent += e.text + '\n';
  else if (e.type === 'reply') out.textContent += `seq ${e.seq}  ${e.addr || ''}  ${ms(e.rttMs)}${e.ttl ? '  ttl ' + e.ttl : ''}\n`;
  else if (e.type === 'hop') out.textContent += `${String(e.n).padStart(2)}  ${(e.addr || '*').padEnd(16)} ${e.name ? '(' + e.name + ') ' : ''}${(e.rttMs || []).map(ms).join('  ')}\n`;
  else if (e.type === 'done') { out.textContent += (e.ok ? '\n✓ ' : '\n✗ ') + e.summary + '\n'; S.probeId = null; log(`Probe: ${e.summary}`); }
  out.scrollTop = out.scrollHeight;
}

/* ---------- transfers (E8, E9) ---------- */
function onXferEvent(ev) {
  const e = untag(ev);
  if (e.type === 'job' || e.id) {
    const j = e.type === 'job' ? (e.value || e) : e;
    S.jobs.set(j.id, j);
    if (['done', 'failed'].includes(String(j.state).toLowerCase()) && !S.jobs.get(j.id)?._logged) {
      j._logged = true;
      log(`Transfer ${j.id} ${String(j.state).toLowerCase()}: ${j.filesDone}/${j.filesTotal} files${j.error ? ' — ' + j.error : ''}`);
      if (S.view.type === 'folder') go(S.view, { push: false });
    }
    renderJobs();
  } else if (e.type === 'fileDone') { /* per-file digests go to the log only when asked */ }
}
function renderJobs() {
  const host = $('#xfer-list');
  host.innerHTML = '';
  const jobs = [...S.jobs.values()].sort((a, b) => (b.started || 0) - (a.started || 0));
  const active = jobs.filter(j => ['queued', 'running', 'verifying', 'paused'].includes(String(j.state).toLowerCase())).length;
  const badge = $('#xfer-badge');
  badge.hidden = !active;
  badge.textContent = active;
  if (!jobs.length) { host.append(el('div', { class: 'empty', text: 'Copies and moves show here, with pause, resume and a SHA-256 check.' })); return; }
  for (const j of jobs) {
    const st = String(j.state).toLowerCase();
    const pct = j.bytesTotal ? Math.min(100, (j.bytesDone / j.bytesTotal) * 100) : (st === 'done' ? 100 : 0);
    const btns = el('div', { class: 'btns' });
    const b = (label, cmd) => btns.append(el('button', { text: label, onclick: () => invoke(cmd, { id: j.id }).catch(e => fail(e)) }));
    if (st === 'running' || st === 'queued' || st === 'verifying') b('Pause', 'xfer_pause');
    if (st === 'paused') b('Resume', 'xfer_resume');
    if (st === 'failed' || st === 'cancelled') b('Retry', 'xfer_retry');
    if (!['done', 'cancelled'].includes(st)) b('Cancel', 'xfer_cancel');
    const stateText = { running: 'Copying', verifying: 'Checking SHA-256', paused: 'Paused', queued: 'Waiting', done: 'Done, checked', failed: 'Failed', cancelled: 'Cancelled' }[st] || st;
    const row = el('div', { class: 'xfer' + (st === 'done' ? ' done' : st === 'failed' ? ' failed' : '') },
      el('div', {}, el('b', { text: `${j.op === 'move' || j.op === 'Move' ? 'Move' : 'Copy'} · ${stateText}` }),
        el('div', { class: 'meta mono', text: j.current || '' }),
        el('div', { class: 'meta', text: `${j.filesDone}/${j.filesTotal} files · ${fmtSize(j.bytesDone)} of ${fmtSize(j.bytesTotal)}${st === 'running' && j.speedBps ? ` · ${fmtSize(j.speedBps)}/s · ${fmtEta(j.etaSecs)} left` : ''}` }),
        j.error ? el('div', { class: 'meta bad', text: j.error }) : null,
        (j.mismatches || []).length ? el('div', { class: 'meta bad', text: 'SHA-256 mismatch: ' + j.mismatches.join(', ') }) : null),
      btns, el('div', { class: 'bar' }, el('i', { style: `width:${pct}%` })));
    if (j.current) row.addEventListener('dblclick', () => revealInFolder(j.current));
    host.append(row);
  }
}

/* ---------- phones (PH1–PH5) ---------- */
async function refreshPhones() {
  try { S.phones = await invoke('drop_phones'); S.inbox = await invoke('drop_inbox'); } catch { S.phones = []; S.inbox = []; }
  renderPhones();
  renderSidebar();
}
async function renderPhones() {
  const host = $('#phones');
  host.innerHTML = '';
  const left = el('div');
  const qr = el('div', { class: 'qr' });
  left.append(el('b', { text: 'Join a phone' }), el('p', { class: 'muted', text: 'Scan with the phone camera. No app needed; the code works for 10 minutes.' }), qr);
  const urlSel = el('select', { style: 'width:100%' });
  left.append(urlSel, el('div', { class: 'btn-row' }, el('button', { text: 'New code', onclick: () => newTicket() })));
  const right = el('div');
  right.append(el('b', { text: `Joined phones (${S.phones.length})` }));
  if (!S.phones.length) right.append(el('p', { class: 'muted', text: 'No phones yet.' }));
  for (const p of S.phones) {
    right.append(el('div', { class: 'phone-row' },
      el('span', { text: p.platform === 'ios' ? '' : '🤖' }), el('span', { text: p.name }),
      el('span', { class: 'muted', text: `${p.ip || ''} · seen ${fmtAgo(Date.parse(p.lastSeen) || p.lastSeen)}` }),
      el('span', { class: 'spacer', style: 'flex:1' }),
      el('button', { text: 'Send selected', disabled: !S.sel.size, onclick: () => sendToPhone(p.id, [...S.sel]) }),
      el('button', { text: 'Rename', onclick: async () => { const n = await ask('Rename phone', 'Name', p.name); if (n) { await invoke('drop_rename_phone', { id: p.id, name: n }); refreshPhones(); } } }),
      el('button', { text: 'Forget', onclick: async () => { await invoke('drop_forget_phone', { id: p.id }); refreshPhones(); } })));
  }
  right.append(el('div', { class: 'section-label', text: `Received on this computer (${S.inbox.length})` }));
  for (const f of S.inbox) {
    right.append(el('div', { class: 'phone-row' }, el('span', { text: f.name }), el('span', { class: 'muted', text: `${fmtSize(f.size)} from ${f.from} · SHA-256 ${String(f.sha256).slice(0, 12)}…` }),
      el('span', { style: 'flex:1' }),
      el('button', { text: 'Show in folder', onclick: () => revealInFolder(f.path) }),
      el('button', { text: 'Move here', disabled: S.view.type !== 'folder', onclick: () => startTransfer([f.path], S.view.loc, 'move').then(refreshPhones) })));
  }
  host.append(left, right);
  if (!S.drop) await newTicket(false); else drawTicket();
  async function newTicket(force = true) {
    try {
      S.dropUrls = S.dropUrls || await invoke('drop_urls');
      urlSel.innerHTML = '';
      for (const u of S.dropUrls) urlSel.append(el('option', { value: u, text: u, selected: u === S.dropHost }));
      urlSel.onchange = () => { S.dropHost = urlSel.value; newTicket(); };
      if (force || !S.drop) S.drop = await invoke('drop_ticket', { base: urlSel.value || S.dropUrls[0] || '' });
      drawTicket();
    } catch (e) { qr.textContent = 'The drop page is not running: ' + errText(e); }
  }
  function drawTicket() { qr.innerHTML = S.drop.qrSvg; qr.append(el('div', { class: 'mono muted', style: 'font-size:11px;word-break:break-all', text: S.drop.url })); }
}
function sendToPhoneMenu(locs, x, y) { menu(S.phones.map(p => ({ label: p.name, run: () => sendToPhone(p.id, locs) })), x, y); }
async function sendToPhone(id, locs) {
  for (const loc of locs) {
    try { await invoke('drop_send', { phoneId: id, loc }); toast('Waiting on the phone\'s drop page'); log('Sent to phone: ' + loc); }
    catch (e) { fail(e, 'Send to phone'); }
  }
}
function onDropEvent(ev) {
  const e = untag(ev);
  if (e.type === 'phoneJoined') { toast(`${e.name || 'A phone'} joined`); log('Phone joined: ' + (e.name || '')); S.drop = null; }
  if (e.type === 'fileReceived') { log(`Received ${e.name} from ${e.from} (SHA-256 ${e.sha256})`); if (e.to === 'system') { toast(`Received ${e.name}`); const b = $('#drop-badge'); b.hidden = false; b.textContent = Number(b.textContent || 0) + 1; } }
  if (e.type === 'filePickedUp') log(`Picked up: ${e.name}`);
  refreshPhones();
}

/* ---------- dock ---------- */
// Collapse the bottom dock to just its tab bar, or spring it back open. Persists the choice.
function setDockCollapsed(collapsed) {
  $('#dock').classList.toggle('collapsed', collapsed);
  $('#dock-toggle').innerHTML = collapsed ? '&#9650;' : '&#9662;'; // ▲ to open, ▼ to collapse
  $('#dock-toggle').title = (collapsed ? 'Show' : 'Hide') + ' the dock (Ctrl+`)';
  fitTerms();
  if (S.settings && S.settings.dockCollapsed !== collapsed) { S.settings.dockCollapsed = collapsed; saveSettings(); }
}
// Reveal a dock pane. Does NOT auto-open a terminal, so newTerminal() can call it safely.
function showDock(tab) {
  setDockCollapsed(false);
  for (const b of document.querySelectorAll('.dock-tabs button[data-tab]')) b.classList.toggle('active', b.dataset.tab === tab);
  for (const p of document.querySelectorAll('.dock-pane')) p.classList.toggle('active', p.dataset.pane === tab);
  if (tab === 'phones') { $('#drop-badge').hidden = true; $('#drop-badge').textContent = ''; refreshPhones(); }
}
function openDock(tab) {
  showDock(tab);
  // Opening the terminal pane with no tab yet spawns one; newTerminal() reveals the pane itself.
  if (tab === 'terminal') { if (!S.terms.size) newTerminal(); else activateTerm(S.activeTerm); }
}
function setupDock() {
  for (const b of document.querySelectorAll('.dock-tabs button[data-tab]')) b.addEventListener('click', () => {
    // Click an open pane's own tab to collapse it; click any tab to spring the dock open.
    if (!$('#dock').classList.contains('collapsed') && b.classList.contains('active')) setDockCollapsed(true);
    else openDock(b.dataset.tab);
  });
  $('#dock-toggle').onclick = () => setDockCollapsed(!$('#dock').classList.contains('collapsed'));
  $('#term-new').onclick = () => newTerminal({ cwd: S.view.type === 'folder' && !/^sftp:/i.test(S.view.loc) ? S.view.loc : null });
  $('#probe-kind').onchange = () => ($('#probe-port').hidden = $('#probe-kind').value !== 'port');
  $('#probe-run').onclick = () => runProbe($('#probe-target').value.trim(), $('#probe-kind').value, $('#probe-port').value);
  $('#probe-stop').onclick = () => S.probeId != null && invoke('probe_cancel', { id: S.probeId });
  $('#xfer-pause-all').onclick = () => invoke('xfer_pause_all');
  $('#xfer-resume-all').onclick = () => invoke('xfer_resume_all');
  $('#xfer-clear').onclick = async () => { await invoke('xfer_clear_finished'); for (const [id, j] of S.jobs) if (['done', 'cancelled'].includes(String(j.state).toLowerCase())) S.jobs.delete(id); renderJobs(); };
  const sp = $('#dock-splitter');
  sp.addEventListener('mousedown', ev => {
    ev.preventDefault();
    const startY = ev.clientY, startH = $('#dock').offsetHeight;
    const move = e => { $('#dock').style.height = Math.max(80, Math.min(innerHeight - 200, startH + startY - e.clientY)) + 'px'; fitTerms(); };
    const up = () => { removeEventListener('mousemove', move); removeEventListener('mouseup', up); };
    addEventListener('mousemove', move);
    addEventListener('mouseup', up);
  });
  // Drag the sidebar/tree boundary to resize the sidebar; width is persisted.
  const sbsp = $('#sidebar-splitter');
  sbsp.addEventListener('mousedown', ev => {
    ev.preventDefault();
    const ws = $('#workspace');
    const startX = ev.clientX, startW = $('#sidebar').offsetWidth;
    let w = startW;
    sbsp.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    const move = e => { w = Math.max(120, Math.min(520, startW + e.clientX - startX)); ws.style.setProperty('--sb-w', w + 'px'); };
    const up = () => {
      removeEventListener('mousemove', move); removeEventListener('mouseup', up);
      sbsp.classList.remove('dragging');
      document.body.style.cursor = '';
      if (S.settings.sidebarWidth !== w) { S.settings.sidebarWidth = w; saveSettings(); }
    };
    addEventListener('mousemove', move);
    addEventListener('mouseup', up);
  });
}
function fitTerms() { const t = S.terms.get(S.activeTerm); t && setTimeout(() => t.fit.fit(), 0); }
addEventListener('resize', fitTerms);

/* ---------- settings ---------- */
async function saveSettings() {
  try { await invoke('settings_set', { settings: S.settings }); } catch (e) { fail(e, 'Saving settings'); }
}
function applyTheme() {
  const t = S.settings.theme;
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  $('#workspace').classList.toggle('no-tree', !S.settings.showTree);
  $('#workspace').classList.toggle('no-sidebar', S.settings.showSidebar === false);
  $('#workspace').style.setProperty('--sb-w', (S.settings.sidebarWidth || 210) + 'px');
  $('#btn-sidebar').classList.toggle('on', S.settings.showSidebar !== false);
  $('#btn-tree').classList.toggle('on', !!S.settings.showTree);
  setDockCollapsed(!!S.settings.dockCollapsed);
}
function toggleSidebar() {
  S.settings.showSidebar = S.settings.showSidebar === false; // hidden -> show, visible -> hide
  applyTheme();
  saveSettings();
}
function toggleTree() {
  S.settings.showTree = !S.settings.showTree;
  applyTheme();
  saveSettings();
}
async function openSettings() {
  const s = S.settings;
  const theme = el('select', {}, ...['system', 'light', 'dark'].map(v => el('option', { value: v, text: v, selected: s.theme === v })));
  const shell = el('select', {}, ...S.shells.map(x => el('option', { value: x.id, text: x.name, selected: s.defaultShell === x.id })));
  const hidden = el('input', { type: 'checkbox', checked: s.showHidden });
  const tree = el('input', { type: 'checkbox', checked: s.showTree });
  const verify = el('input', { type: 'checkbox', checked: s.verifyCopies });
  const manifest = el('input', { type: 'checkbox', checked: s.writeManifest });
  const subnets = el('input', { value: (s.extraSubnets || []).join(', '), placeholder: 'e.g. 192.168.50.0/24' });
  const interval = el('input', { type: 'number', min: 0, value: s.scanIntervalMin });
  const pathForm = el('input', { value: s.defaultPathForm, placeholder: 'e.g. UNC path' });
  const dropOn = el('input', { type: 'checkbox', checked: s.dropEnabled });
  const dropPort = el('input', { type: 'number', value: s.dropPort });
  const dropExp = el('input', { type: 'number', value: s.dropExpiryHours });
  const chk = (box, text) => el('p', {}, el('label', { style: 'display:inline;color:inherit' }, box, ' ' + text));
  const body = el('div', {},
    el('label', { text: 'Theme' }), theme, el('label', { text: 'Default shell' }), shell,
    el('label', { text: 'Path form copied by Ctrl+Shift+C' }), pathForm,
    chk(hidden, 'Show hidden files'), chk(tree, 'Show the tree'),
    chk(verify, 'Check every copy with SHA-256'), chk(manifest, 'Write SHA256SUMS files'),
    el('label', { text: 'Extra subnets to scan' }), subnets, el('label', { text: 'Minutes between background scans (0 = only when asked)' }), interval,
    chk(dropOn, 'Run the phone drop page'), el('label', { text: 'Drop page port' }), dropPort, el('label', { text: 'Hours a file waits for a phone' }), dropExp);
  const ok = await modal('Settings', body, [{ label: 'Cancel', value: null }, { label: 'Save', primary: true, value: true }]);
  if (!ok) return;
  Object.assign(s, {
    theme: theme.value, defaultShell: shell.value, showHidden: hidden.checked, showTree: tree.checked, verifyCopies: verify.checked,
    writeManifest: manifest.checked, extraSubnets: subnets.value.split(',').map(x => x.trim()).filter(Boolean),
    scanIntervalMin: Number(interval.value) || 0, defaultPathForm: pathForm.value.trim(), dropEnabled: dropOn.checked,
    dropPort: Number(dropPort.value) || 8765, dropExpiryHours: Number(dropExp.value) || 24,
  });
  await saveSettings();
  applyTheme();
  loadShells();
  render();
}

/* ---------- keyboard ---------- */
function setupKeys() {
  addEventListener('keydown', async e => {
    if (!$('#modal').hidden) return;
    const inField = e.target.closest('input,textarea,select,.xterm');
    const ctrl = e.ctrlKey || e.metaKey;
    if (e.key === 'Escape') { hideMenu(); if (inField && e.target.id === 'address-input') endEdit(); return; }
    if (ctrl && e.key.toLowerCase() === 'l') { e.preventDefault(); startEdit(); return; }
    if (ctrl && e.key === '`') { e.preventDefault(); setDockCollapsed(!$('#dock').classList.contains('collapsed')); return; }
    if (ctrl && !e.shiftKey && e.key.toLowerCase() === 'b') { e.preventDefault(); toggleSidebar(); return; }
    if (ctrl && e.shiftKey && e.key.toLowerCase() === 'b') { e.preventDefault(); toggleTree(); return; }
    if (ctrl && e.shiftKey && e.key.toLowerCase() === 't') { e.preventDefault(); const one = S.sel.size === 1 ? entryByLoc([...S.sel][0]) : null; terminalHere(one && one.isDir ? one.loc : null, one?.loc); return; }
    if (e.key === 'F5') { e.preventDefault(); go(S.view, { push: false }); return; }
    if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); goBack(); return; }
    if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); goFwd(); return; }
    if (e.altKey && e.key === 'ArrowUp') { e.preventDefault(); goUp(); return; }
    if (inField) return;
    const one = S.sel.size === 1 ? entryByLoc([...S.sel][0]) : null;
    if (ctrl && e.shiftKey && e.key.toLowerCase() === 'c' && one) {
      e.preventDefault();
      const forms = await invoke('fs_forms', { loc: one.loc }).catch(() => []);
      const f = forms.find(x => x.label === S.settings.defaultPathForm) || forms[0];
      if (f) copyText(f.value, f.label);
      return;
    }
    if (ctrl && e.shiftKey && e.key.toLowerCase() === 'n') { e.preventDefault(); newFolder(); return; }
    if (ctrl && e.key.toLowerCase() === 'c') { clipSet('copy'); return; }
    if (ctrl && e.key.toLowerCase() === 'x') { clipSet('move'); return; }
    if (ctrl && e.key.toLowerCase() === 'v') { paste(); return; }
    if (ctrl && e.key.toLowerCase() === 'a' && S.view.type !== 'section') { e.preventDefault(); S.sel = new Set(visibleEntries().map(x => x.loc)); paintSel(); showMultiDetails(); return; }
    if (e.key === 'Delete') { const items = selectedEntries(); items.length && deleteEntries(items); return; }
    if (e.key === 'F2' && one) { renameEntry(one); return; }
    if (e.key === 'Enter' && one) { openEntry(one); return; }
    if (e.key === 'Backspace') { goUp(); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (S.view.type === 'section' || S.view.type === 'system') return;
      e.preventDefault();
      const list = visibleEntries();
      if (!list.length) return;
      let i = list.findIndex(x => x.loc === S.anchor);
      i = e.key === 'ArrowDown' ? Math.min(list.length - 1, i + 1) : Math.max(0, i - 1);
      selectRow(list[i], { shiftKey: e.shiftKey }, list);
      document.querySelector(`#content-body tr[data-loc="${CSS.escape(list[i].loc)}"]`)?.scrollIntoView({ block: 'nearest' });
    }
  });
}
function startEdit() { $('#address').classList.add('editing'); const i = $('#address-input'); i.focus(); i.select(); }
function endEdit() { $('#address').classList.remove('editing'); }

/* ---------- startup ---------- */
async function main() {
  try { S.settings = await invoke('settings_get'); } catch (e) { S.settings = {}; fail(e, 'Settings'); }
  applyTheme();
  setupDock();
  setupKeys();
  $('#btn-back').onclick = goBack;
  $('#btn-fwd').onclick = goFwd;
  $('#btn-up').onclick = goUp;
  $('#btn-refresh').onclick = () => go(S.view, { push: false });
  $('#btn-scan').onclick = scan;
  $('#btn-settings').onclick = openSettings;
  $('#btn-sidebar').onclick = toggleSidebar;
  $('#btn-tree').onclick = toggleTree;
  $('#crumbs').onclick = startEdit;
  const ai = $('#address-input');
  ai.addEventListener('keydown', e => { if (e.key === 'Enter') { endEdit(); openTyped(ai.value); } });
  ai.addEventListener('blur', endEdit);
  $('#filter').addEventListener('input', () => {
    if (S.view.type === 'section') showSection(S.view.id); else if (S.view.type === 'folder' || S.view.type === 'roots' || S.view.type === 'favourites') renderListing();
  });
  $('#content-body').addEventListener('contextmenu', e => {
    if (e.target.closest('tr')) return;
    if (S.view.type !== 'folder') return;
    menu([
      S.clip && { label: `Paste ${S.clip.locs.length} item(s)`, key: 'Ctrl+V', run: () => paste() },
      { label: 'New folder', key: 'Ctrl+Shift+N', run: newFolder },
      { label: 'Open terminal here', run: () => terminalHere(S.view.loc) },
      { label: 'Open in system app', run: () => openWithSystem(S.view.loc) },
      { label: 'Refresh', key: 'F5', run: () => go(S.view, { push: false }) },
    ].filter(Boolean), e.clientX, e.clientY);
  });
  $('#content-body').addEventListener('click', e => { if (!e.target.closest('tr') && S.view.type === 'folder') { S.sel.clear(); paintSel(); showFolderDetails(S.view.loc); } });

  await listen('scan://event', onScanEvent);
  await listen('records://update', onRecords);
  await listen('term://data', ({ id, b64 }) => {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const t = S.terms.get(id);
    if (t) { t.term.write(bytes); return; }
    // Output can arrive before newTerminal() registers the tab; buffer it to flush on registration.
    let b = S.termPending.get(id);
    if (!b) { b = []; S.termPending.set(id, b); }
    b.push(bytes);
  });
  await listen('term://exit', ({ id }) => { const t = S.terms.get(id); if (t) t.term.write('\r\n\x1b[2m[process ended]\x1b[0m\r\n'); });
  await listen('probe://event', onProbeEvent);
  await listen('xfer://event', onXferEvent);
  await listen('drop://event', onDropEvent);
  await listen('log://line', log);
  // Files dropped from the OS onto the window are copied into the folder on screen.
  await listen('tauri://drag-drop', p => {
    const paths = p.paths || [];
    if (paths.length && S.view.type === 'folder') startTransfer(paths, S.view.loc, 'copy');
    else if (paths.length) toast('Open a folder first, then drop files onto it.');
  });

  await loadShells();
  try { S.records = await invoke('records_get'); } catch { S.records = []; }
  try { for (const j of await invoke('xfer_jobs')) S.jobs.set(j.id, j); renderJobs(); } catch { /* none yet */ }
  buildTree();
  let startView = '';
  try { startView = await invoke('start_view'); } catch {}
  go({ type: startView || 'roots' }, { push: false });
  refreshPhones();
  if (!S.records.length) scan();
}
main();
