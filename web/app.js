// MLSChat browser demo. Each Device owns a WebClient (Rust compiled to WASM)
// and its own WebSocket to the delivery service.
import init, { WebClient } from './pkg/web.js';

await init();

const WS_URL = `ws://${location.host}/ws`;
const params = new URLSearchParams(location.search);
const devicesEl = document.getElementById('devices');
const statusEl = document.getElementById('server-status');
const devices = new Map();

class Device {
  constructor(id) {
    this.id = id;
    this.client = new WebClient(id);
    this.group = null;
    this.log = [];
    this.el = this.render();
    devicesEl.appendChild(this.el);
    this.connect();
  }

  connect() {
    this.ws = new WebSocket(WS_URL);
    this.ws.binaryType = 'arraybuffer';
    this.ws.onopen = () => {
      this.client.hello();
      if (!this.published) { this.client.publish_key_packages(2); this.published = true; }
      this.flush();
      statusEl.textContent = 'server: connected';
      this.update();
    };
    this.ws.onmessage = (ev) => { this.client.on_frame(new Uint8Array(ev.data)); this.flush(); };
    this.ws.onclose = () => { this.update(); setTimeout(() => this.connect(), 800); };
  }

  flush() {
    if (this.ws && this.ws.readyState === 1) {
      for (const f of this.client.take_outgoing()) this.ws.send(f);
    }
    for (const e of JSON.parse(this.client.take_events())) this.onEvent(e);
    this.update();
  }

  onEvent(e) {
    if (e.type === 'joined') { this.group = e.group; this.sys(`joined ${e.group}${e.welcome_bytes ? ` (Welcome ${e.welcome_bytes} B)` : ''}`); }
    else if (e.type === 'message') this.log.push({ who: e.from, text: e.text, note: `epoch ${e.epoch}, ${e.bytes} B` });
    else if (e.type === 'sent') this.log.push({ who: 'me', text: e.text, note: `${e.bytes} B` });
    else if (e.type === 'commit') this.sys(`${e.own ? 'my' : e.from + "'s"} commit applied, now epoch ${e.epoch} (${e.bytes} B)`);
    else if (e.type === 'commit_rejected') this.sys(`commit lost the race for this epoch; retrying`);
    else if (e.type === 'removed') { this.sys(`removed from ${e.group} by ${e.by}; can no longer read it`); }
    else if (e.type === 'error') this.log.push({ err: e.error });
  }

  sys(text) { this.log.push({ sys: text }); }

  render() {
    const el = document.createElement('section');
    el.className = 'device';
    el.innerHTML = `
      <h2><span class="dot"></span>${this.id}</h2>
      <div class="meta"></div>
      <div class="row"><input class="gname" placeholder="group name" value="team"><button class="create">Create group</button></div>
      <div class="row"><input class="invitee" placeholder="invite device"><button class="invite">Invite</button><button class="rotate">Rotate keys</button></div>
      <div class="row members"></div>
      <svg class="tree"></svg>
      <div class="legend"><span>&#9679; key held by this device</span><span style="color:#f59e0b">&#9679; re-keyed by last commit</span><span>&#9675; blank</span></div>
      <div class="log"></div>
      <div class="row"><input class="text" placeholder="message"><button class="primary send">Send</button></div>`;
    el.querySelector('.create').onclick = () => { this.client.create_group(el.querySelector('.gname').value); this.flush(); };
    el.querySelector('.invite').onclick = () => { if (this.group) { this.client.invite(this.group, el.querySelector('.invitee').value); this.flush(); } };
    el.querySelector('.rotate').onclick = () => { if (this.group) { this.client.rotate(this.group); this.flush(); } };
    const send = () => { const t = el.querySelector('.text'); if (this.group && t.value) { this.client.send_text(this.group, t.value); t.value = ''; this.flush(); } };
    el.querySelector('.send').onclick = send;
    el.querySelector('.text').onkeydown = (ev) => { if (ev.key === 'Enter') send(); };
    return el;
  }

  update() {
    const el = this.el;
    el.querySelector('.dot').classList.toggle('on', this.ws && this.ws.readyState === 1);
    const st = JSON.parse(this.client.state());
    const g = st.groups.find((x) => x.group === this.group) || st.groups[0];
    const meta = el.querySelector('.meta');
    const members = el.querySelector('.members');
    if (g) {
      this.group = g.group;
      meta.innerHTML = g.removed ? `<b>${g.group}</b>: removed` :
        `<b>${g.group}</b> epoch <b>${g.epoch}</b> · ${g.members.length} members · authenticator <code>${g.epoch_authenticator}</code>`;
      members.innerHTML = '';
      for (const m of g.members) {
        const c = document.createElement('span');
        c.className = 'chip';
        c.textContent = m.id + (m.leaf === g.own_leaf ? ' (me)' : '');
        if (m.leaf !== g.own_leaf && !g.removed) {
          const b = document.createElement('button');
          b.textContent = '×';
          b.title = 'remove';
          b.onclick = () => { this.client.remove(g.group, m.id); this.flush(); };
          c.appendChild(b);
        }
        members.appendChild(c);
      }
      drawTree(el.querySelector('svg.tree'), g);
    } else {
      meta.textContent = 'no group yet';
    }
    const log = el.querySelector('.log');
    log.innerHTML = this.log.slice(-60).map((m) => m.sys ? `<div class="sys">${esc(m.sys)}</div>` :
      m.err ? `<div class="err">${esc(m.err)}</div>` :
      `<div class="msg"><span class="who">${esc(m.who)}</span>: ${esc(m.text)} <span class="sys">${esc(m.note)}</span></div>`).join('');
    log.scrollTop = log.scrollHeight;
  }
}

function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

// Draw the array-based ratchet tree: leaves on the bottom row, parents above at their level.
function drawTree(svg, g) {
  const w = svg.clientWidth || 360, h = 150;
  const n = g.n_leaves;
  const levels = Math.round(Math.log2(n)) + 1;
  const pos = (x) => {
    let lvl = 0; while (((x >> lvl) & 1) === 1) lvl++;
    return { cx: ((x + 1) / (2 * n)) * w, cy: h - 22 - lvl * ((h - 40) / Math.max(levels - 1, 1)) };
  };
  let out = '';
  for (const node of g.nodes) {
    if (node.kind !== 'parent') continue;
    const p = pos(node.index);
    let lvl = 0; while (((node.index >> lvl) & 1) === 1) lvl++;
    for (const c of [node.index - (1 << (lvl - 1)), node.index + (1 << (lvl - 1))]) {
      if (c < g.nodes.length) { const q = pos(c); out += `<line x1="${p.cx}" y1="${p.cy}" x2="${q.cx}" y2="${q.cy}" stroke="#ccd2dc"/>`; }
    }
  }
  for (const node of g.nodes) {
    const p = pos(node.index);
    const fill = !node.filled ? '#fff' : node.rekeyed ? '#f59e0b' : node.known ? '#2f6fde' : '#9aa3b2';
    const stroke = node.known ? '#2f6fde' : '#9aa3b2';
    const r = node.kind === 'leaf' ? 7 : 6;
    out += `<circle cx="${p.cx}" cy="${p.cy}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="1.5"><title>node ${node.index} ${node.label} ${node.key}</title></circle>`;
    if (node.kind === 'leaf' && node.label) out += `<text x="${p.cx}" y="${h - 4}" font-size="10" text-anchor="middle" fill="#6b7385">${esc(node.label.slice(0, 6))}</text>`;
  }
  svg.innerHTML = out;
}

function addDevice(id) {
  if (!id || devices.has(id)) return;
  devices.set(id, new Device(id));
}

document.getElementById('add-device').onclick = () => {
  const i = document.getElementById('new-device');
  addDevice(i.value.trim());
  i.value = '';
};

const initial = (params.get('devices') || 'alice,bob,carol').split(',');
const tag = Math.random().toString(36).slice(2, 6);
for (const d of initial) addDevice(params.has('demo') ? `${d}-${tag}` : d);

// Scripted walkthrough for recording: ?demo=1[&step=N] runs the first N steps.
if (params.has('demo')) {
  const [a, b, c] = [...devices.values()];
  const room = `team-${tag}`;
  const steps = [
    () => { a.el.querySelector('.gname').value = room; a.client.create_group(room); a.flush(); },
    () => { a.client.invite(room, `${b.id},${c.id}`); a.flush(); },
    () => { a.client.send_text(room, 'hi both, this room is end-to-end encrypted'); a.flush(); },
    () => { b.client.send_text(room, 'the server only sees ciphertext'); b.flush(); },
    () => { c.client.send_text(room, 'and every message is signed by its sender'); c.flush(); },
    () => { b.client.rotate(room); b.flush(); },
    () => { a.client.remove(room, c.id); a.flush(); },
    () => { a.client.send_text(room, 'carol is out: a new epoch she has no keys for'); a.flush(); },
    () => { b.client.send_text(room, 'only the path from the removed leaf to the root was re-keyed'); b.flush(); },
  ];
  const upto = Math.min(Number(params.get('step') || steps.length), steps.length);
  const delay = Number(params.get('delay') || 1400);
  let i = 0;
  const tick = () => { if (i < upto) { steps[i++](); setTimeout(tick, delay); } };
  setTimeout(tick, 900);
}
