// 통합 테스트: 실제 Cloudflare Workers + Durable Objects 런타임(wrangler dev)을 띄워 검증
// 인증, 보안 헤더, 화이트리스트, 방 생성/조회, WebSocket 시그널링, Origin 차단, 로그인 5회 잠금
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';

const PORT = Number(process.env.TEST_PORT || 18787);
const BASE = `http://127.0.0.1:${PORT}`;
const WS_BASE = `ws://127.0.0.1:${PORT}`;
const persistDir = mkdtempSync(path.join(tmpdir(), 'p2pft-test-'));

const wranglerBin = path.resolve('node_modules/wrangler/bin/wrangler.js');
const child = spawn(
  process.execPath,
  [
    wranglerBin,
    'dev',
    '--ip', '127.0.0.1',
    '--port', String(PORT),
    '--inspector-port', '0',
    '--persist-to', persistDir,
    '--var', 'APP_PASSWORD:test-password-123',
    '--show-interactive-dev-session=false',
    '--log-level', 'error',
  ],
  { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } }
);

let logs = '';
child.stdout.on('data', (d) => { logs += d.toString(); });
child.stderr.on('data', (d) => { logs += d.toString(); });

async function waitForServer(timeoutMs = 25_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (child.exitCode !== null) throw new Error(`wrangler dev 종료됨 (${child.exitCode}):\n${logs}`);
    try {
      const res = await fetch(`${BASE}/login.html`, { redirect: 'manual' });
      if (res.status === 200) return;
    } catch { /* 기동 대기 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`wrangler dev 기동 시간 초과:\n${logs}`);
}

function connectWs(qs, { cookie, origin = BASE } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS_BASE}/ws?${qs}`, {
      headers: cookie ? { cookie } : {},
      origin,
    });
    const inbox = [];
    const waiters = [];
    ws.on('message', (raw) => {
      const text = raw.toString();
      const msg = text === 'pong' ? 'pong' : JSON.parse(text);
      const w = waiters.shift();
      if (w) w(msg); else inbox.push(msg);
    });
    ws.next = () => new Promise((r) => (inbox.length ? r(inbox.shift()) : waiters.push(r)));
    ws.sendJson = (m) => ws.send(JSON.stringify(m));
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}

const login = (password) =>
  fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: BASE },
    body: JSON.stringify({ password }),
  });

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

try {
  await waitForServer();
  let cookie;

  await test('비로그인: / → 로그인 페이지 리다이렉트', async () => {
    const res = await fetch(`${BASE}/?room=ABCDEF`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/login.html?next=%2F%3Froom%3DABCDEF');
  });

  await test('비로그인: app.js, /config, /api/rooms 접근 차단', async () => {
    assert.equal((await fetch(`${BASE}/app.js`)).status, 401);
    assert.equal((await fetch(`${BASE}/config`)).status, 401);
    assert.equal((await fetch(`${BASE}/api/rooms`, { method: 'POST' })).status, 401);
  });

  await test('로그인 페이지 + 보안 헤더', async () => {
    const res = await fetch(`${BASE}/login.html`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  await test('화이트리스트 외 경로 차단', async () => {
    for (const p of ['/wrangler.jsonc', '/..%2fpackage.json', '/.dev.vars', '/src/worker.js']) {
      assert.notEqual((await fetch(`${BASE}${p}`)).status, 200, p);
    }
  });

  await test('비로그인 WebSocket 거부', async () => {
    await assert.rejects(connectWs('room=ABCDEF'), /401/);
  });

  await test('틀린 비밀번호 거부, 맞으면 HttpOnly HMAC 쿠키 발급', async () => {
    assert.equal((await login('wrong')).status, 401);
    const res = await login('test-password-123');
    assert.equal(res.status, 204);
    const setCookie = res.headers.get('set-cookie');
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    cookie = setCookie.split(';')[0];
  });

  await test('로그인 후 세션·페이지·ICE 설정 접근', async () => {
    const ses = await (await fetch(`${BASE}/api/session`, { headers: { cookie } })).json();
    assert.equal(ses.ok, true);
    assert.equal(ses.mode, 'password');
    assert.equal((await fetch(`${BASE}/`, { headers: { cookie } })).status, 200);
    const cfg = await (await fetch(`${BASE}/config`, { headers: { cookie } })).json();
    assert.ok(Array.isArray(cfg.iceServers));
  });

  await test('변조된 세션 쿠키 거부', async () => {
    assert.equal((await fetch(`${BASE}/api/session`, { headers: { cookie: `${cookie}x` } })).status, 401);
  });

  await test('다른 Origin에서의 WebSocket 거부', async () => {
    await assert.rejects(connectWs('room=ABCDEF', { cookie, origin: 'https://evil.example' }), /403/);
  });

  await test('방 생성 → 상태 조회 → 시그널 중계 → ping/pong → 정원 초과 → 퇴장', async () => {
    const createRes = await fetch(`${BASE}/api/rooms`, {
      method: 'POST',
      headers: { cookie, Origin: BASE },
    });
    assert.equal(createRes.status, 201);
    const { room } = await createRes.json();
    assert.match(room, /^[A-Z0-9]{6}$/);

    // 없는 방 조회 → 404
    assert.equal((await fetch(`${BASE}/api/rooms/ZZZZZZ`, { headers: { cookie } })).status, 404);
    // 만든 방 조회 → 200
    assert.equal((await fetch(`${BASE}/api/rooms/${room}`, { headers: { cookie } })).status, 200);

    const a = await connectWs(`room=${room}`, { cookie });
    assert.deepEqual(await a.next(), { type: 'joined', room, peers: 1 });

    // Hibernation 자동 ping/pong 확인
    a.send('ping');
    assert.equal(await a.next(), 'pong');

    const b = await connectWs(`room=${room}`, { cookie });
    assert.deepEqual(await b.next(), { type: 'joined', room, peers: 2 });
    assert.deepEqual(await a.next(), { type: 'peer-joined', rejoin: false });

    // SDP offer 중계
    a.sendJson({ type: 'signal', data: { description: { type: 'offer', sdp: 'v=0' } } });
    assert.deepEqual(await b.next(), { type: 'signal', data: { description: { type: 'offer', sdp: 'v=0' } } });

    // 3번째 참여자 거부 (HTTP 조회 409 + WS 오류 메시지)
    assert.equal((await fetch(`${BASE}/api/rooms/${room}`, { headers: { cookie } })).status, 409);
    const c = await connectWs(`room=${room}`, { cookie });
    assert.equal((await c.next()).message, '이미 두 명이 접속한 방입니다.');

    // 퇴장 알림
    b.close();
    assert.deepEqual(await a.next(), { type: 'peer-left' });

    a.close();
    c.close();
  });

  await test('로그인 5회 실패 시 잠금(429)', async () => {
    for (let i = 0; i < 5; i++) assert.equal((await login(`bad-${i}`)).status, 401);
    assert.equal((await login('test-password-123')).status, 429);
  });

  console.log(`\n✓ ${passed}개 Cloudflare Workers + Durable Objects 테스트 통과`);
} finally {
  child.kill();
  await new Promise((r) => setTimeout(r, 300));
  rmSync(persistDir, { recursive: true, force: true });
}
