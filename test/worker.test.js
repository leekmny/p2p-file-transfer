// 전체 통합 테스트: 실제 Cloudflare Workers + Durable Objects 런타임(wrangler dev) 검증
// - 비밀번호 로그인 / 보안 헤더 / 화이트리스트 / Origin 검사
// - 이메일 회원가입 + 초대 코드 검증 + 실제 Webhook 인증 메일 발송 + 6자리 코드 인증 + 로그인
// - 관리자 10분 임시 특별 코드(랜덤 생성, 무인증 입장, 1회용, 자동 만료 파기, 즉시 파기, 게스트 권한 격리)
// - AI 관리용 원격 MCP 서버 (/mcp JSON-RPC 2.0) + Bearer Admin REST API
// - WebSocket 시그널링(방 생성, Hibernation ping/pong, SDP 중계, 정원 초과, 퇴장) + 로그인 잠금/해제
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';

const PORT = Number(process.env.TEST_PORT || 18787);
const BASE = `http://127.0.0.1:${PORT}`;
const WS_BASE = `ws://127.0.0.1:${PORT}`;
const ADMIN_API_KEY = 'super-secret-ai-admin-key-32chars!';
const WEBHOOK_SECRET = 'test-webhook-secret';
const INVITE_CODE = 'FRIEND2026';
const persistDir = mkdtempSync(path.join(tmpdir(), 'p2pft-test-'));

// 실제 HTTP 인증 메일 발송을 캡처하는 로컬 테스트 Webhook 서버
const sentEmails = [];
const mailServer = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (req.headers['x-webhook-secret'] !== WEBHOOK_SECRET && body.secret !== WEBHOOK_SECRET) {
      res.writeHead(403);
      return res.end('forbidden');
    }
    sentEmails.push(body);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
});

await new Promise((resolve) => mailServer.listen(0, '127.0.0.1', resolve));
const mailPort = mailServer.address().port;

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
    '--var', `INVITE_CODE:${INVITE_CODE}`,
    '--var', 'ADMIN_EMAILS:admin@example.com',
    '--var', `EMAIL_WEBHOOK_URL:http://127.0.0.1:${mailPort}/send`,
    '--var', `EMAIL_WEBHOOK_SECRET:${WEBHOOK_SECRET}`,
    '--var', `ADMIN_API_KEY:${ADMIN_API_KEY}`,
    '--var', 'ALLOW_SHORT_PASS_TTL:1',
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

const postJson = (p, body, headers = {}) =>
  fetch(`${BASE}${p}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: BASE, ...headers },
    body: JSON.stringify(body),
  });

const mcpCall = (method, params, id = 1, token = ADMIN_API_KEY) =>
  fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

try {
  await waitForServer();
  let adminCookie;
  let userCookie;

  await test('비로그인: 리다이렉트·보안 헤더·화이트리스트·WS 차단', async () => {
    const r = await fetch(`${BASE}/?room=ABCDEF`, { redirect: 'manual' });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/login.html?next=%2F%3Froom%3DABCDEF');

    const loginPage = await fetch(`${BASE}/login.html`);
    assert.equal(loginPage.status, 200);
    assert.match(loginPage.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(loginPage.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(loginPage.headers.get('x-frame-options'), 'DENY');

    assert.equal((await fetch(`${BASE}/app.js`)).status, 401);
    assert.equal((await fetch(`${BASE}/config`)).status, 401);
    assert.notEqual((await fetch(`${BASE}/wrangler.jsonc`)).status, 200);
    await assert.rejects(connectWs('room=ABCDEF'), /401/);

    const methods = await (await fetch(`${BASE}/api/auth/methods`)).json();
    assert.equal(methods.emailAuth, true);
    assert.equal(methods.inviteRequired, true);
    assert.equal(methods.guestPass, true);
  });

  await test('공유 비밀번호 로그인 → 관리자 세션 발급 + 변조 쿠키 거부', async () => {
    assert.equal((await postJson('/api/login', { password: 'wrong' })).status, 401);
    const res = await postJson('/api/login', { password: 'test-password-123' });
    assert.equal(res.status, 204);
    const setCookie = res.headers.get('set-cookie');
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    adminCookie = setCookie.split(';')[0];

    const ses = await (await fetch(`${BASE}/api/session`, { headers: { cookie: adminCookie } })).json();
    assert.equal(ses.ok, true);
    assert.equal(ses.isAdmin, true);

    assert.equal((await fetch(`${BASE}/api/session`, { headers: { cookie: `${adminCookie}x` } })).status, 401);
  });

  await test('이메일 회원가입: 잘못된 초대코드 차단 → 정상 가입 → 인증 메일 수신 → 미인증 로그인 차단 → 6자리 코드 인증', async () => {
    // 잘못된 초대 코드 거부
    assert.equal(
      (await postJson('/api/auth/register', {
        email: 'friend@example.com',
        password: 'friend-password-99',
        inviteCode: 'WRONG',
      })).status,
      403
    );

    // 정상 회원가입 → Webhook으로 6자리 인증 코드 메일 발송
    const reg = await postJson('/api/auth/register', {
      email: 'friend@example.com',
      password: 'friend-password-99',
      inviteCode: INVITE_CODE,
    });
    assert.equal(reg.status, 201);
    assert.equal(sentEmails.length, 1);
    assert.equal(sentEmails[0].to, 'friend@example.com');
    const code = sentEmails[0].code;
    assert.match(code, /^\d{6}$/);

    // 인증 전 로그인 차단 (403 email_not_verified)
    const preLogin = await postJson('/api/auth/login', {
      email: 'friend@example.com',
      password: 'friend-password-99',
    });
    assert.equal(preLogin.status, 403);
    assert.equal((await preLogin.json()).error, 'email_not_verified');

    // 틀린 인증 코드 거부
    assert.equal(
      (await postJson('/api/auth/verify', { email: 'friend@example.com', code: code === '000000' ? '111111' : '000000' })).status,
      400
    );

    // 올바른 6자리 코드로 인증 완료 → 즉시 로그인 쿠키 발급
    const ver = await postJson('/api/auth/verify', { email: 'friend@example.com', code });
    assert.equal(ver.status, 200);
    userCookie = ver.headers.get('set-cookie').split(';')[0];

    const ses = await (await fetch(`${BASE}/api/session`, { headers: { cookie: userCookie } })).json();
    assert.equal(ses.email, 'friend@example.com');
    assert.equal(ses.isAdmin, false);

    // 이미 가입된 이메일 재가입 거부 (409)
    assert.equal(
      (await postJson('/api/auth/register', {
        email: 'friend@example.com',
        password: 'another-password-1',
        inviteCode: INVITE_CODE,
      })).status,
      409
    );

    // 인증 완료 후 이메일 로그인 성공
    assert.equal(
      (await postJson('/api/auth/login', {
        email: 'friend@example.com',
        password: 'friend-password-99',
      })).status,
      204
    );

    // 일반 회원은 관리자 API 접근 불가 (403)
    assert.equal(
      (await postJson('/api/admin/passes', {}, { cookie: userCookie })).status,
      403
    );
  });

  await test('관리자 10분 임시 특별 코드: 발급 → 무인증 입장 → 게스트 권한 격리 → 1회용 파기 → 자동 만료 파기 → 즉시 파기', async () => {
    // 1) 일반 10분 코드 발급
    const createRes = await postJson('/api/admin/passes', { singleUse: false }, { cookie: adminCookie });
    assert.equal(createRes.status, 201);
    const pass = await createRes.json();
    assert.match(pass.code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal(pass.ttlSec, 600);

    // 2) 게스트가 하이픈 없이 소문자로 입력해도 모든 인증 없이 입장
    const redeem = await postJson('/api/auth/pass', { code: pass.code.replace('-', '').toLowerCase() });
    assert.equal(redeem.status, 204);
    const guestCookie = redeem.headers.get('set-cookie').split(';')[0];

    const gSes = await (await fetch(`${BASE}/api/session`, { headers: { cookie: guestCookie } })).json();
    assert.equal(gSes.ok, true);
    assert.equal(gSes.isGuest, true);
    assert.equal(gSes.isAdmin, false);

    // 게스트는 방 생성 가능, 관리자 API는 차단 (403)
    assert.equal((await postJson('/api/rooms', {}, { cookie: guestCookie })).status, 201);
    assert.equal((await postJson('/api/admin/passes', {}, { cookie: guestCookie })).status, 403);

    // 3) 관리자 즉시 파기 후 재사용 불가
    const delRes = await fetch(`${BASE}/api/admin/passes/${pass.id}`, {
      method: 'DELETE',
      headers: { cookie: adminCookie, Origin: BASE },
    });
    assert.equal(delRes.status, 204);
    assert.equal((await postJson('/api/auth/pass', { code: pass.code })).status, 401);

    // 4) 1회용 코드: 1번 성공 후 2번째 즉시 거부
    const oneRes = await postJson('/api/admin/passes', { singleUse: true }, { cookie: adminCookie });
    const onePass = await oneRes.json();
    assert.equal((await postJson('/api/auth/pass', { code: onePass.code })).status, 204);
    assert.equal((await postJson('/api/auth/pass', { code: onePass.code })).status, 401);

    // 5) 만료 시간 경과 후 자동 파기 확인 (테스트용 1초 만료)
    const expRes = await postJson('/api/admin/passes', { ttlMs: 1000 }, { cookie: adminCookie });
    const expPass = await expRes.json();
    await new Promise((r) => setTimeout(r, 1150));
    assert.equal((await postJson('/api/auth/pass', { code: expPass.code })).status, 401);
  });

  await test('AI 관리용 원격 MCP 서버 (/mcp): 인증 거부 → initialize → tools/list → 도구 호출', async () => {
    // 토큰 없음/틀림 거부
    assert.equal((await mcpCall('tools/list', {}, 1, null)).status, 401);
    assert.equal((await mcpCall('tools/list', {}, 1, 'wrong-key')).status, 401);

    // initialize
    const initRes = await (await mcpCall('initialize', {}, 1)).json();
    assert.equal(initRes.result.serverInfo.name, 'p2p-file-transfer-admin');

    // tools/list (9개 도구)
    const listRes = await (await mcpCall('tools/list', {}, 2)).json();
    assert.equal(listRes.result.tools.length, 9);

    // AI가 임시 코드 발급 → 게스트 입장 → 목록 확인 → 파기
    const genRes = await (await mcpCall('tools/call', { name: 'create_guest_pass', arguments: { singleUse: false } }, 3)).json();
    const aiPass = genRes.result.structuredContent;
    assert.match(aiPass.code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal((await postJson('/api/auth/pass', { code: aiPass.code })).status, 204);

    const revRes = await (await mcpCall('tools/call', { name: 'revoke_guest_pass', arguments: { id: aiPass.id } }, 4)).json();
    assert.equal(revRes.result.structuredContent.revoked, true);

    // AI가 회원 목록 조회 & 방 생성 & 상태 조회
    const usersRes = await (await mcpCall('tools/call', { name: 'list_users', arguments: {} }, 5)).json();
    assert.equal(usersRes.result.structuredContent.users[0].email, 'friend@example.com');
    assert.equal('password_hash' in usersRes.result.structuredContent.users[0], false);

    const roomRes = await (await mcpCall('tools/call', { name: 'create_room', arguments: {} }, 6)).json();
    assert.match(roomRes.result.structuredContent.room, /^[A-Z0-9]{6}$/);

    // AI가 회원 삭제
    const delUserRes = await (await mcpCall('tools/call', { name: 'delete_user', arguments: { email: 'friend@example.com' } }, 7)).json();
    assert.equal(delUserRes.result.structuredContent.deleted, true);

    // Admin REST API도 Bearer 키로 동일하게 동작
    const statusRes = await fetch(`${BASE}/api/admin/status`, {
      headers: { Authorization: `Bearer ${ADMIN_API_KEY}` },
    });
    assert.equal(statusRes.status, 200);
    assert.equal((await statusRes.json()).stats.totalUsers, 0);
  });

  await test('시그널링: 방 생성 → Origin 거부 → ping/pong → SDP 중계 → 정원 초과 → 퇴장', async () => {
    await assert.rejects(connectWs('room=ABCDEF', { cookie: adminCookie, origin: 'https://evil.example' }), /403/);

    const { room } = await (await postJson('/api/rooms', {}, { cookie: adminCookie })).json();
    const a = await connectWs(`room=${room}`, { cookie: adminCookie });
    assert.deepEqual(await a.next(), { type: 'joined', room, peers: 1 });

    a.send('ping');
    assert.equal(await a.next(), 'pong');

    const b = await connectWs(`room=${room}`, { cookie: adminCookie });
    assert.deepEqual(await b.next(), { type: 'joined', room, peers: 2 });
    assert.deepEqual(await a.next(), { type: 'peer-joined', rejoin: false });

    a.sendJson({ type: 'signal', data: { description: { type: 'offer', sdp: 'v=0' } } });
    assert.deepEqual(await b.next(), { type: 'signal', data: { description: { type: 'offer', sdp: 'v=0' } } });

    const c = await connectWs(`room=${room}`, { cookie: adminCookie });
    assert.equal((await c.next()).message, '이미 두 명이 접속한 방입니다.');

    b.close();
    assert.deepEqual(await a.next(), { type: 'peer-left' });
    a.close();
    c.close();
  });

  await test('로그인 5회 실패 잠금(429) → AI MCP clear_rate_limits로 즉시 해제', async () => {
    for (let i = 0; i < 5; i++) assert.equal((await postJson('/api/login', { password: `bad-${i}` })).status, 401);
    assert.equal((await postJson('/api/login', { password: 'test-password-123' })).status, 429);

    const clr = await (await mcpCall('tools/call', { name: 'clear_rate_limits', arguments: {} }, 8)).json();
    assert.equal(clr.result.structuredContent.cleared, true);

    assert.equal((await postJson('/api/login', { password: 'test-password-123' })).status, 204);
  });

  console.log(`\n✓ ${passed}개 전체 통합 테스트 통과`);
} finally {
  child.kill();
  mailServer.close();
  await new Promise((r) => setTimeout(r, 300));
  rmSync(persistDir, { recursive: true, force: true });
}
