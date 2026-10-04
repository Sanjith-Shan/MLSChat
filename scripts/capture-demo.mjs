// Record the scripted web demo: drive a headless Chrome over the DevTools
// Protocol and save a screenshot every `interval` ms. Frames go to argv[2].
// Usage: node scripts/capture-demo.mjs <out-dir> [url] [seconds] [interval-ms]
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const out = process.argv[2];
const url = process.argv[3] || 'http://localhost:7070/?demo=1&delay=1600';
const seconds = Number(process.argv[4] || 18);
const interval = Number(process.argv[5] || 400);
mkdirSync(out, { recursive: true });

const chrome = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new', '--disable-gpu', '--hide-scrollbars', '--remote-debugging-port=9333',
  `--user-data-dir=${join(tmpdir(), 'mlschat-cdp')}`, '--window-size=1500,820', 'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch('http://127.0.0.1:9333/json')).json()).find((t) => t.type === 'page'); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0;
const pending = new Map();
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
});
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });

await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1500, height: 820, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url });
const frames = Math.round((seconds * 1000) / interval);
for (let f = 0; f < frames; f++) {
  const t0 = Date.now();
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(out, `frame-${String(f).padStart(4, '0')}.png`), Buffer.from(shot.data, 'base64'));
  await sleep(Math.max(0, interval - (Date.now() - t0)));
}
ws.close();
chrome.kill();
console.log(`${frames} frames written to ${out}`);
