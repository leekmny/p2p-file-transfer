// 서버 테스트: 인증, 보안 헤더, 정적 파일 화이트리스트, WebSocket 인증/Origin 검사, 시그널링, 로그인 잠금
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';

const PORT = process.env.TEST_PORT || '3999';
process.env.PORT = PORT;
process.env.HOST = '127.0.0.1';
process.env.APP_PASSWORD = 'test-password-123';
delete process.env.ALLOWED_ORIGINS;
delete process.env.TRUST_PROXY;

const { server, wss } = await import('../server.js');
if (!server.listening) await once(server, 'listening');

const BASE = `http://localhost:${PORT}`;
const WS_URL = `ws://localhost:${PORT}/ws`;
let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

function connect({ cookie, origin = BASE } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_URL, { headers: cookie ? { cookie } : {}, origin });
    const inbox = [];
    const waiters = [];
    ws.on('message', (raw) => {
      const msg = JSON.parse(raw);
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

let cookie;

await test('비로그인: / → 로그인 페이지로 리다이렉트', async () => {
  const res = await fetch(`${BASE}/?room=ABCDEF`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/login.html?next=%2F%3Froom%3DABCDEF');
});

await test('비로그인: app.js, /config 접근 차단', async () => {
  assert.equal((await fetch(`${BASE}/app.js`)).status, 401);
  assert.equal((await fetch(`${BASE}/config`)).status, 401);
});

await test('로그인 페이지 + 보안 헤더', async () => {
  const res = await fetch(`${BASE}/login.html`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
});

await test('화이트리스트 외 파일/경로 조작 차단', async () => {
  for (const p of ['/server.js', '/..%2fserver.js', '/package.json', '/.env']) {
    assert.notEqual((await fetch(`${BASE}${p}`)).status, 200, p);
  }
});

await test('비로그인 WebSocket 거부', async () => {
  await assert.rejects(connect(), /401/);
});

await test('틀린 비밀번호 거부, 맞으면 HttpOnly 쿠키 발급', async () => {
  assert.equal((await login('wrong')).status, 401);
  const res = await login('test-password-123');
  assert.equal(res.status, 204);
  const setCookie = res.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  cookie = setCookie.split(';')[0];
});

await test('로그인 후 페이지/설정 접근', async () => {
  assert.equal((await fetch(`${BASE}/`, { headers: { cookie } })).status, 200);
  const cfg = await (await fetch(`${BASE}/config`, { headers: { cookie } })).json();
  assert.ok(Array.isArray(cfg.iceServers));
});

await test('다른 Origin에서의 WebSocket 거부', async () => {
  await assert.rejects(connect({ cookie, origin: 'https://evil.example' }), /401/);
});

await test('시그널링: 방 생성 → 참여 → 중계 → 정원 초과 → 퇴장', async () => {
  const a = await connect({ cookie });
  a.sendJson({ type: 'create' });
  const created = await a.next();
  assert.equal(created.type, 'created');
  assert.match(created.room, /^[A-Z0-9]{6}$/);

  const b = await connect({ cookie });
  b.sendJson({ type: 'join', room: created.room.toLowerCase() });
  assert.deepEqual(await b.next(), { type: 'joined', room: created.room, peers: 2 });
  assert.deepEqual(await a.next(), { type: 'peer-joined', rejoin: false });

  a.sendJson({ type: 'signal', data: { description: { type: 'offer', sdp: 'x' } } });
  assert.deepEqual(await b.next(), { type: 'signal', data: { description: { type: 'offer', sdp: 'x' } } });

  const c = await connect({ cookie });
  c.sendJson({ type: 'join', room: created.room });
  assert.equal((await c.next()).message, '이미 두 명이 접속한 방입니다.');
  c.sendJson({ type: 'join', room: 'ZZZZZZ' });
  assert.equal((await c.next()).message, '존재하지 않는 방 코드입니다.');

  b.close();
  assert.deepEqual(await a.next(), { type: 'peer-left' });
  a.close();
  c.close();
});

await test('로그아웃하면 세션 무효화 + WebSocket 종료', async () => {
  const s = await connect({ cookie });
  const closed = once(s, 'close');
  const res = await fetch(`${BASE}/api/logout`, { method: 'POST', headers: { cookie, Origin: BASE } });
  assert.equal(res.status, 204);
  const [code] = await closed;
  assert.equal(code, 4401);
  assert.equal((await fetch(`${BASE}/api/session`, { headers: { cookie } })).status, 401);
});

await test('로그인 5회 실패 시 잠금(429)', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await login(`bad-${i}`)).status, 401);
  assert.equal((await login('test-password-123')).status, 429);
});

wss.close();
server.close();
console.log(`\n✓ ${passed}개 테스트 통과`);
