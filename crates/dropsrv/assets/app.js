'use strict';
(function () {
  const $ = (s) => document.querySelector(s);
  const S = { me: null, computer: null, peers: [], chunk: 8 * 1024 * 1024, target: null, inboxSig: '', queue: [], busy: false };

  // ---------- helpers ----------
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids) if (k != null) e.append(k);
    return e;
  }
  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
  }
  function fmtAgo(ms) {
    const s = Math.max(0, (Date.now() - ms) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return new Date(ms).toLocaleDateString();
  }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let toastTimer = 0;
  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
  }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* private mode */ } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (_) { /* private mode */ } }

  async function api(method, url, body) {
    const opts = { method, headers: { 'X-Drop': '1' }, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(url, opts);
    let j = null;
    try { j = await r.json(); } catch (_) { /* empty */ }
    if (!r.ok) {
      const e = new Error((j && j.error) || 'HTTP ' + r.status);
      e.status = r.status;
      e.data = j;
      throw e;
    }
    return j;
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      // Clipboard API needs a secure context; fall back for plain-http LAN pages.
      const t = el('textarea', { readonly: true });
      t.style.position = 'fixed';
      t.style.top = '0';
      t.style.opacity = '0';
      t.value = text;
      document.body.append(t);
      t.select();
      t.setSelectionRange(0, text.length);
      try { document.execCommand('copy'); } catch (_) { /* ignore */ }
      t.remove();
    }
    toast('SHA-256 copied');
  }

  function show(view) {
    for (const v of ['#loading', '#joinView', '#nameView', '#mainView']) $(v).hidden = v !== view;
    $('#settingsBtn').hidden = view !== '#mainView';
  }

  // ---------- recipients ----------
  function renderTargets() {
    const box = $('#targets');
    const list = [{ id: 'system', name: S.computer ? S.computer.name : 'This computer' }].concat(S.peers);
    if (!list.some((t) => t.id === S.target)) S.target = 'system';
    box.replaceChildren(
      ...list.map((t) =>
        el('button', {
          class: 'chip', type: 'button', role: 'radio', 'aria-checked': String(t.id === S.target), title: t.name,
          onclick: () => { S.target = t.id; lsSet('drop.target', t.id); renderTargets(); },
        }, t.name)
      )
    );
  }

  // ---------- uploads ----------
  function putChunk(id, offset, blob, onProgress) {
    return new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open('PUT', '/api/upload/' + encodeURIComponent(id) + '?offset=' + offset);
      x.setRequestHeader('X-Drop', '1');
      x.setRequestHeader('Content-Type', 'application/octet-stream');
      x.upload.onprogress = (e) => onProgress(e.loaded);
      x.onload = () => {
        let j = null;
        try { j = JSON.parse(x.responseText); } catch (_) { /* empty */ }
        if (x.status >= 200 && x.status < 300) resolve(j);
        else {
          const e = new Error((j && j.error) || 'HTTP ' + x.status);
          e.status = x.status;
          e.data = j;
          reject(e);
        }
      };
      x.onerror = () => { const e = new Error('Network error'); e.status = 0; reject(e); };
      x.ontimeout = x.onerror;
      x.send(blob);
    });
  }

  async function uploadFile(file, to, ui) {
    const key = 'drop.up:' + [file.name, file.size, file.lastModified, to].join('|');
    let id = lsGet(key);
    let offset = 0;
    if (id) {
      try { offset = (await api('GET', '/api/upload/' + encodeURIComponent(id))).received; ui.status('Resuming…'); }
      catch (_) { id = null; lsDel(key); }
    }
    if (!id) {
      const r = await api('POST', '/api/upload', { name: file.name, size: file.size, to });
      if (r.done) return r;
      id = r.id;
      lsSet(key, id);
    }
    ui.id = id;
    let tries = 0;
    for (;;) {
      if (ui.cancelled) {
        await api('DELETE', '/api/upload/' + encodeURIComponent(id)).catch(() => {});
        lsDel(key);
        throw new Error('Cancelled');
      }
      const end = Math.min(offset + S.chunk, file.size);
      try {
        const start = offset;
        const r = await putChunk(id, start, file.slice(start, end), (n) => ui.progress(start + n, file.size));
        offset = r.received;
        tries = 0;
        ui.progress(offset, file.size);
        if (r.done) { lsDel(key); return r; }
      } catch (e) {
        if (e.status === 409 && e.data && typeof e.data.received === 'number') { offset = e.data.received; continue; }
        if ([400, 401, 403, 404, 507].includes(e.status) || ++tries > 8) {
          if (e.status === 404) lsDel(key);
          throw e;
        }
        ui.status('Connection lost, retrying…');
        await sleep(Math.min(10000, 800 * tries));
        try { offset = (await api('GET', '/api/upload/' + encodeURIComponent(id))).received; } catch (_) { /* retry */ }
      }
    }
  }

  function addUploads(files) {
    const to = S.target || 'system';
    const toName = to === 'system' ? (S.computer ? S.computer.name : 'computer') : (S.peers.find((p) => p.id === to) || {}).name;
    for (const file of files) {
      const bar = el('progress', { max: '100', value: '0' });
      const st = el('div', { class: 'status' }, 'Waiting…');
      const cancel = el('button', { class: 'btn small danger', type: 'button' }, 'Cancel');
      const li = el('li', {},
        el('div', { class: 'fname' }, file.name),
        el('div', { class: 'meta' }, fmtSize(file.size) + ' → ' + (toName || 'phone')),
        bar, st, el('div', { class: 'actions' }, cancel));
      const ui = {
        cancelled: false,
        progress(done, total) {
          const p = total ? Math.floor((done * 100) / total) : 100;
          bar.value = p;
          st.className = 'status';
          st.textContent = p + '% · ' + fmtSize(done) + ' of ' + fmtSize(total);
        },
        status(t, cls) { st.className = 'status ' + (cls || ''); st.textContent = t; },
      };
      cancel.addEventListener('click', () => { ui.cancelled = true; ui.status('Cancelling…'); if (!ui.started) finish('Cancelled', 'err'); });
      function finish(t, cls) { ui.status(t, cls); cancel.remove(); ui.finished = true; }
      ui.finish = finish;
      $('#uploads').prepend(li);
      S.queue.push({ file, to, ui });
    }
    pump();
  }

  async function pump() {
    if (S.busy) return;
    S.busy = true;
    while (S.queue.length) {
      const job = S.queue.shift();
      if (job.ui.cancelled) continue;
      job.ui.started = true;
      try {
        const r = await uploadFile(job.file, job.to, job.ui);
        job.ui.progress(job.file.size, job.file.size);
        const h = r && r.sha256 ? ' · SHA-256 ' + r.sha256.slice(0, 12) : '';
        job.ui.finish('Sent' + h, 'ok');
      } catch (e) {
        job.ui.finish(e.message === 'Cancelled' ? 'Cancelled' : 'Failed: ' + e.message, 'err');
        if (e.status === 401) { boot(); break; }
      }
    }
    S.busy = false;
  }

  // ---------- inbox ----------
  function renderInbox(files) {
    const sig = JSON.stringify(files.map((f) => f.id));
    $('#inboxEmpty').hidden = files.length > 0;
    if (sig === S.inboxSig) return;
    S.inboxSig = sig;
    $('#inbox').replaceChildren(
      ...files.map((f) => {
        const dl = el('a', { class: 'btn small', href: '/api/files/' + encodeURIComponent(f.id), download: f.name }, 'Download');
        dl.addEventListener('click', () => { dl.textContent = 'Downloading…'; });
        const hash = el('button', { class: 'hash', type: 'button', title: 'Copy full SHA-256: ' + f.sha256, onclick: () => copyText(f.sha256) },
          'SHA-256 ' + f.sha256.slice(0, 12) + ' · copy');
        const del = el('button', {
          class: 'btn small danger', type: 'button',
          onclick: async () => { try { await api('DELETE', '/api/files/' + encodeURIComponent(f.id)); refresh(); } catch (e) { toast(e.message); } },
        }, 'Dismiss');
        return el('li', {},
          el('div', { class: 'fname' }, f.name),
          el('div', { class: 'meta' }, fmtSize(f.size) + ' · from ' + f.fromName + ' · ' + fmtAgo(f.received)),
          el('div', { class: 'actions' }, dl, hash, del));
      })
    );
  }

  // ---------- polling ----------
  let pollTimer = 0;
  async function refresh() {
    clearTimeout(pollTimer);
    try {
      const [me, inbox] = await Promise.all([api('GET', '/api/me'), api('GET', '/api/inbox')]);
      applyMe(me);
      renderInbox(inbox.files || []);
    } catch (e) {
      if (e.status === 401) { boot(); return; }
    }
    pollTimer = setTimeout(refresh, document.hidden ? 15000 : 3000);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.me) refresh(); });

  function applyMe(j) {
    S.me = j.me;
    S.computer = j.computer;
    S.chunk = j.chunkSize || S.chunk;
    const peersSig = JSON.stringify(j.peers);
    if (peersSig !== S.peersSig) { S.peersSig = peersSig; S.peers = j.peers; renderTargets(); }
    $('#meName').textContent = j.me.name;
    $('#title').textContent = 'Drop · ' + j.computer.name;
    document.title = 'Drop · ' + j.computer.name;
  }

  // ---------- views ----------
  async function boot() {
    show('#loading');
    let j;
    try {
      j = await api('GET', '/api/me');
    } catch (e) {
      if (e.status === 401) { show('#joinView'); return; }
      $('#loading').textContent = 'Cannot reach the computer. Make sure you are on the same Wi-Fi, then reload.';
      setTimeout(boot, 5000);
      return;
    }
    S.target = lsGet('drop.target') || 'system';
    applyMe(j);
    renderTargets();
    const params = new URLSearchParams(location.search);
    if (params.has('welcome')) {
      history.replaceState(null, '', '/');
      $('#nameInput').value = j.me.name;
      show('#nameView');
      $('#nameInput').focus();
      return;
    }
    show('#mainView');
    refresh();
  }

  $('#nameForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('POST', '/api/me', { name: $('#nameInput').value });
      show('#mainView');
      refresh();
    } catch (e) { toast(e.message); }
  });
  $('#joinForm').addEventListener('submit', (ev) => {
    const v = $('#codeInput').value.replace(/[^0-9a-z]/gi, '').toUpperCase();
    if (v.length < 8) { ev.preventDefault(); toast('The code has 8 characters'); return; }
    $('#codeInput').value = v;
  });
  $('#fileInput').addEventListener('change', (ev) => {
    const files = Array.from(ev.target.files || []);
    ev.target.value = '';
    if (files.length) addUploads(files);
  });
  $('#settingsBtn').addEventListener('click', () => {
    const s = $('#settings');
    s.hidden = !s.hidden;
    $('#settingsBtn').setAttribute('aria-expanded', String(!s.hidden));
  });
  $('#renameBtn').addEventListener('click', () => {
    $('#nameInput').value = S.me ? S.me.name : '';
    show('#nameView');
    $('#nameInput').focus();
  });
  $('#leaveBtn').addEventListener('click', async () => {
    if (!confirm('Leave this computer? Files waiting for this phone will be deleted.')) return;
    try { await api('POST', '/api/leave'); } catch (_) { /* ignore */ }
    S.me = null;
    show('#joinView');
  });

  boot();
})();
