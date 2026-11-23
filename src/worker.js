// Cloudflare Worker 진입점
// - 정적 파일 화이트리스트 + 보안 헤더 + 통합 인증(이메일 회원가입/인증, 공유 비밀번호, 10분 임시 특별 코드, Cloudflare Access)
// - 관리자 REST API(/api/admin/*) & AI 관리용 원격 MCP 서버(POST /mcp, Bearer ADMIN_API_KEY)
// - WebRTC ICE 설정(/config: STUN, Cloudflare Realtime TURN, coturn HMAC)
// - 방 생성/조회(/api/rooms) 및 WebSocket 시그널링(/ws → SignalingRoom Durable Object)
import {
  allowedEmailsList,
  authenticate,
  authConfig,
  clearSessionCookie,
  constantTimeSecretMatch,
  isAdminEmail,
  issueSessionCookie,
  sha256Hex,
  verifyPassword,
} from './auth.js';
import { sendVerificationEmail } from './email.js';
import { handleMcpRequest } from './mcp.js';

export { SignalingRoom } from './room.js';
export { AccountStore } from './account-store.js';

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const PUBLIC_ASSETS = new Set(['/login.html', '/login.js', '/style.css', '/favicon.svg']);
const PROTECTED_ASSETS = new Set(['/', '/index.html', '/app.js']);

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ROOM_RE = /^[A-Z0-9]{6}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^\d{6}$/;

function list(v) {
  return (v || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function withSecurityHeaders(request, response, extra = {}) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  if (new URL(request.url).protocol === 'https:') {
    headers.set('Strict-Transport-Security', 'max-age=31536000');
  }
  headers.set('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function json(request, status, data, extra = {}) {
  return withSecurityHeaders(
    request,
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    }),
    extra
  );
}

function originAllowed(request, env) {
  const origin = request.headers.get('origin');
  if (!origin) return false;
  let parsed;
  try { parsed = new URL(origin); } catch { return false; }

  const allowed = list(env.ALLOWED_ORIGINS);
  if (allowed.length) return allowed.includes(parsed.origin);

  const reqUrl = new URL(request.url);
  return parsed.host === reqUrl.host;
}

function clientIp(request) {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    'local'
  );
}

function accountsStub(env) {
  return env.ACCOUNTS.get(env.ACCOUNTS.idFromName('global'));
}

async function readJsonBody(request, maxBytes = 8192) {
  const text = await request.text();
  if (text.length > maxBytes) return { error: 'too_large' };
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object') return { error: 'bad_request' };
    return { data };
  } catch {
    return { error: 'bad_request' };
  }
}

function normalizeEmail(raw) {
  const email = String(raw || '').trim().toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email)) return null;
  return email;
}

function generateRoomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
}

async function allocateRoom(env) {
  for (let i = 0; i < 5; i++) {
    const code = generateRoomCode();
    const stub = env.ROOMS.get(env.ROOMS.idFromName(`room:${code}`));
    if (await stub.createRoom()) return code;
  }
  return null;
}

// AI / API 관리용 Bearer 토큰 검증 (ADMIN_API_KEY 16자 이상 필수)
async function verifyAdminBearer(request, env) {
  const configured = typeof env.ADMIN_API_KEY === 'string' ? env.ADMIN_API_KEY.trim() : '';
  if (configured.length < 16) return { configured: false, ok: false };

  const header = request.headers.get('authorization') || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return { configured: true, ok: false, missing: true };

  const store = accountsStub(env);
  const rlKey = `adminapi:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 10))) return { configured: true, ok: false, rateLimited: true };

  const ok = await constantTimeSecretMatch(m[1].trim(), configured);
  if (!ok) {
    await store.recordRateLimit(rlKey);
    return { configured: true, ok: false };
  }
  await store.clearRateLimit(rlKey);
  return { configured: true, ok: true };
}

function buildAdminActions(request, env, actor) {
  const store = accountsStub(env);
  const origin = new URL(request.url).origin;
  return {
    origin,
    async getStatus() {
      const cfg = authConfig(env);
      const stats = await store.getStats();
      return {
        auth: {
          emailAuth: cfg.emailAuth,
          inviteRequired: cfg.inviteRequired,
          sharedPassword: cfg.sharedPassword,
          guestPass: cfg.guestPass,
          access: cfg.access,
          aiMcpEnabled: (env.ADMIN_API_KEY || '').trim().length >= 16,
        },
        stats,
      };
    },
    createGuestPass: (singleUse, ttlMs) => store.createGuestPass(actor, singleUse, ttlMs),
    listGuestPasses: () => store.listGuestPasses(),
    revokeGuestPass: (id) => store.revokeGuestPass(id),
    listUsers: () => store.listUsers(),
    verifyUser: (email) => store.verifyUserByAdmin(email),
    deleteUser: (email) => store.deleteUser(email),
    clearRateLimits: () => store.clearAllRateLimits(),
    async createRoom() {
      const code = await allocateRoom(env);
      if (!code) throw new Error('방 생성에 실패했습니다.');
      return code;
    },
  };
}

async function buildIceServers(env) {
  const servers = [];
  const stuns = env.STUN_URLS === undefined ? ['stun:stun.l.google.com:19302'] : list(env.STUN_URLS);
  if (stuns.length) servers.push({ urls: stuns });

  if (env.CF_TURN_TOKEN_ID && env.CF_TURN_API_TOKEN) {
    try {
      const res = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.CF_TURN_TOKEN_ID)}/credentials/generate-ice-servers`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${env.CF_TURN_API_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ttl: 3600 }),
        }
      );
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.iceServers)) servers.push(...data.iceServers);
      }
    } catch { /* STUN 폴백 */ }
  }

  const turns = list(env.TURN_URLS);
  if (turns.length) {
    if (env.TURN_SECRET) {
      const username = `${Math.floor(Date.now() / 1000) + 3600}:p2pft`;
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        enc.encode(env.TURN_SECRET),
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
      );
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(username)));
      let bin = '';
      for (const b of sig) bin += String.fromCharCode(b);
      servers.push({ urls: turns, username, credential: btoa(bin) });
    } else if (env.TURN_USERNAME) {
      servers.push({ urls: turns, username: env.TURN_USERNAME, credential: env.TURN_CREDENTIAL || '' });
    }
  }

  return servers;
}

// ================================================================ 라우터
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;

    // 0) AI 관리용 원격 MCP 서버 (POST /mcp · Bearer ADMIN_API_KEY)
    if (p === '/mcp') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      const bearer = await verifyAdminBearer(request, env);
      if (!bearer.configured) return json(request, 404, { error: 'AI MCP 관리 기능이 비활성화되어 있습니다. (ADMIN_API_KEY 미설정)' });
      if (bearer.rateLimited) return json(request, 429, { error: 'too_many_attempts' });
      if (!bearer.ok) return json(request, 401, { error: 'unauthorized' }, { 'WWW-Authenticate': 'Bearer' });

      const parsed = await readJsonBody(request, 16_384);
      if (parsed.error) return json(request, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });

      const result = await handleMcpRequest(parsed.data, buildAdminActions(request, env, 'ai-mcp'));
      if (result.status === 202 || result.payload === null) {
        return withSecurityHeaders(request, new Response(null, { status: 202 }));
      }
      return json(request, result.status, result.payload);
    }

    // 1) 인증 API (공개 엔드포인트)
    if (p === '/api/auth/methods' && request.method === 'GET') {
      const cfg = authConfig(env);
      return json(request, 200, {
        emailAuth: cfg.emailAuth,
        inviteRequired: cfg.inviteRequired,
        sharedPassword: cfg.sharedPassword,
        guestPass: cfg.guestPass,
        access: cfg.access,
      });
    }

    if (p === '/api/auth/register') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleRegister(request, env);
    }

    if (p === '/api/auth/verify') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleVerify(request, env);
    }

    if (p === '/api/auth/resend') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleResend(request, env);
    }

    if (p === '/api/auth/login') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleEmailLogin(request, env);
    }

    if (p === '/api/auth/pass') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleGuestPassLogin(request, env);
    }

    if (p === '/api/login') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleSharedPasswordLogin(request, env);
    }

    if (p === '/api/logout') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      if (request.headers.get('origin') && !originAllowed(request, env)) {
        return json(request, 403, { error: 'forbidden' });
      }
      return withSecurityHeaders(request, new Response(null, { status: 204 }), {
        'Set-Cookie': clearSessionCookie(request),
      });
    }

    if (p === '/api/session') {
      const auth = await authenticate(request, env);
      if (auth.misconfigured) return misconfiguredResponse(request);
      if (!auth.ok) return json(request, 401, { ok: false, needAccess: !!auth.needAccess });
      return json(request, 200, {
        ok: true,
        mode: auth.mode,
        email: auth.email,
        isAdmin: auth.isAdmin,
        isGuest: auth.isGuest,
      });
    }

    // 2) 로그인 화면용 공개 정적 파일
    if ((request.method === 'GET' || request.method === 'HEAD') && PUBLIC_ASSETS.has(p)) {
      const asset = await env.ASSETS.fetch(request);
      return withSecurityHeaders(request, asset);
    }

    // 3) 관리자 REST API (/api/admin/* — 브라우저 관리자 세션 또는 Bearer ADMIN_API_KEY 모두 허용)
    if (p.startsWith('/api/admin/')) {
      return handleAdminApi(request, env, p);
    }

    // 4) 이하 모든 경로는 일반 인증 필수
    const auth = await authenticate(request, env);
    if (auth.misconfigured) return misconfiguredResponse(request);
    if (!auth.ok) {
      if (auth.needLogin && (p === '/' || p === '/index.html')) {
        return withSecurityHeaders(request, new Response(null, { status: 302 }), {
          Location: `/login.html?next=${encodeURIComponent(p + url.search)}`,
        });
      }
      return json(request, auth.needAccess ? 403 : 401, { error: 'unauthorized' });
    }

    // 5) 보호된 정적 파일
    if ((request.method === 'GET' || request.method === 'HEAD') && PROTECTED_ASSETS.has(p)) {
      const assetReq = p === '/' ? new Request(new URL('/index.html', request.url), request) : request;
      const asset = await env.ASSETS.fetch(assetReq);
      return withSecurityHeaders(request, asset);
    }

    // 6) ICE 설정
    if (p === '/config' && request.method === 'GET') {
      return json(request, 200, { iceServers: await buildIceServers(env) });
    }

    // 7) 방 생성
    if (p === '/api/rooms' && request.method === 'POST') {
      if (request.headers.get('origin') && !originAllowed(request, env)) {
        return json(request, 403, { error: 'forbidden' });
      }
      const code = await allocateRoom(env);
      if (code) return json(request, 201, { room: code });
      return json(request, 503, { error: '방 생성에 실패했습니다. 다시 시도하세요.' });
    }

    // 8) 방 상태 사전 조회
    if (p.startsWith('/api/rooms/') && request.method === 'GET') {
      const code = p.slice('/api/rooms/'.length).toUpperCase().trim();
      if (!ROOM_RE.test(code)) {
        return json(request, 400, { error: '방 코드는 6자리 영문/숫자입니다.' });
      }
      const stub = env.ROOMS.get(env.ROOMS.idFromName(`room:${code}`));
      const status = await stub.roomStatus();
      if (!status.exists) return json(request, 404, { error: '존재하지 않는 방 코드입니다.' });
      if (status.peers >= 2) return json(request, 409, { error: '이미 두 명이 접속한 방입니다.' });
      return json(request, 200, { room: code, peers: status.peers });
    }

    // 9) WebSocket 시그널링
    if (p === '/ws') {
      if (!originAllowed(request, env)) return json(request, 403, { error: 'forbidden' });
      const code = (url.searchParams.get('room') || '').toUpperCase().trim();
      if (!ROOM_RE.test(code)) return json(request, 400, { error: 'invalid_room' });
      const stub = env.ROOMS.get(env.ROOMS.idFromName(`room:${code}`));
      return stub.fetch(request);
    }

    return withSecurityHeaders(
      request,
      new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
    );
  },
};

// ================================================================ 관리자 REST API
async function handleAdminApi(request, env, p) {
  let actor = null;
  let viaBearer = false;

  if (request.headers.has('authorization')) {
    const bearer = await verifyAdminBearer(request, env);
    if (bearer.rateLimited) return json(request, 429, { error: 'too_many_attempts' });
    if (!bearer.ok) return json(request, 401, { error: 'unauthorized' });
    actor = 'ai-api';
    viaBearer = true;
  } else {
    const auth = await authenticate(request, env);
    if (auth.misconfigured) return misconfiguredResponse(request);
    if (!auth.ok) return json(request, 401, { error: 'unauthorized' });
    if (!auth.isAdmin) return json(request, 403, { error: '관리자만 사용할 수 있습니다.' });
    actor = auth.email || 'admin';
  }

  // 브라우저 세션 요청의 상태 변경 메서드에는 Origin 검증 적용
  if (!viaBearer && request.method !== 'GET' && request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const actions = buildAdminActions(request, env, actor);

  if (p === '/api/admin/status' && request.method === 'GET') {
    return json(request, 200, await actions.getStatus());
  }

  if (p === '/api/admin/passes') {
    if (request.method === 'GET') return json(request, 200, { passes: await actions.listGuestPasses() });
    if (request.method === 'POST') {
      let singleUse = false;
      let ttlMs;
      try {
        const text = await request.text();
        if (text) {
          const body = JSON.parse(text);
          singleUse = !!body?.singleUse;
          if (env.ALLOW_SHORT_PASS_TTL === '1' && Number.isFinite(Number(body?.ttlMs))) {
            ttlMs = Number(body.ttlMs);
          }
        }
      } catch { /* 기본값 사용 */ }
      return json(request, 201, await actions.createGuestPass(singleUse, ttlMs));
    }
    return withSecurityHeaders(request, new Response(null, { status: 405 }));
  }

  if (p.startsWith('/api/admin/passes/') && request.method === 'DELETE') {
    const id = p.slice('/api/admin/passes/'.length).trim();
    if (!/^[a-f0-9]{16}$/.test(id)) return json(request, 400, { error: '잘못된 코드 ID입니다.' });
    await actions.revokeGuestPass(id);
    return withSecurityHeaders(request, new Response(null, { status: 204 }));
  }

  if (p === '/api/admin/users' && request.method === 'GET') {
    return json(request, 200, { users: await actions.listUsers() });
  }

  if (p.startsWith('/api/admin/users/')) {
    const rest = p.slice('/api/admin/users/'.length);
    if (rest.endsWith('/verify') && request.method === 'POST') {
      const email = normalizeEmail(decodeURIComponent(rest.slice(0, -'/verify'.length)));
      if (!email) return json(request, 400, { error: '올바른 이메일이 아닙니다.' });
      const ok = await actions.verifyUser(email);
      return ok ? json(request, 200, { ok: true, email }) : json(request, 404, { error: '회원을 찾을 수 없습니다.' });
    }
    if (request.method === 'DELETE') {
      const email = normalizeEmail(decodeURIComponent(rest));
      if (!email) return json(request, 400, { error: '올바른 이메일이 아닙니다.' });
      const ok = await actions.deleteUser(email);
      return ok ? withSecurityHeaders(request, new Response(null, { status: 204 })) : json(request, 404, { error: '회원을 찾을 수 없습니다.' });
    }
  }

  if (p === '/api/admin/rate-limits/clear' && request.method === 'POST') {
    await actions.clearRateLimits();
    return json(request, 200, { ok: true });
  }

  if (p === '/api/admin/rooms' && request.method === 'POST') {
    const room = await actions.createRoom();
    return json(request, 201, { room, shareUrl: `${actions.origin}/?room=${room}` });
  }

  return json(request, 404, { error: 'not_found' });
}

// ================================================================ 인증 핸들러
async function handleRegister(request, env) {
  const cfg = authConfig(env);
  if (!cfg.emailAuth) return json(request, 404, { error: '이메일 회원가입이 비활성화되어 있습니다.' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `reg:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 5))) {
    return json(request, 429, { error: '요청이 너무 많습니다. 15분 뒤에 다시 시도하세요.' });
  }

  const parsed = await readJsonBody(request);
  if (parsed.error) return json(request, parsed.error === 'too_large' ? 413 : 400, { error: '잘못된 요청입니다.' });

  const email = normalizeEmail(parsed.data.email);
  const password = typeof parsed.data.password === 'string' ? parsed.data.password : '';
  const inviteCode = typeof parsed.data.inviteCode === 'string' ? parsed.data.inviteCode.trim() : '';

  if (!email) return json(request, 400, { error: '올바른 이메일 주소를 입력하세요.' });
  if (password.length < 8 || password.length > 128) {
    return json(request, 400, { error: '비밀번호는 8자 이상 128자 이하로 입력하세요.' });
  }

  if (cfg.inviteRequired) {
    const ok = await constantTimeSecretMatch(inviteCode, env.INVITE_CODE);
    if (!ok) {
      await store.recordRateLimit(rlKey);
      return json(request, 403, { error: '초대 코드가 올바르지 않습니다.' });
    }
  }

  const allowed = allowedEmailsList(env);
  if (allowed.length && !allowed.includes(email)) {
    await store.recordRateLimit(rlKey);
    return json(request, 403, { error: '가입이 허용되지 않은 이메일입니다.' });
  }

  const reg = await store.startRegistration(email, password);
  if (!reg.ok) {
    if (reg.error === 'already_exists') {
      return json(request, 409, { error: '이미 가입된 이메일입니다. 로그인해 주세요.' });
    }
    if (reg.error === 'cooldown') {
      return json(request, 429, { error: `인증 메일은 ${reg.waitSec}초 뒤에 다시 보낼 수 있습니다.` });
    }
    return json(request, 400, { error: '가입 처리에 실패했습니다.' });
  }

  try {
    await sendVerificationEmail(env, { to: email, code: reg.code, origin: new URL(request.url).origin });
  } catch (err) {
    await store.rollbackCode(email);
    console.error('인증 메일 발송 실패:', err);
    return json(request, 502, { error: '인증 메일 발송에 실패했습니다. 잠시 후 다시 시도하세요.' });
  }

  return json(request, 201, { ok: true, email, expiresInSec: reg.expiresInSec });
}

async function handleVerify(request, env) {
  if (!authConfig(env).emailAuth) return json(request, 404, { error: 'disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `ver:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 10))) {
    return json(request, 429, { error: '인증 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.' });
  }

  const parsed = await readJsonBody(request);
  if (parsed.error) return json(request, 400, { error: '잘못된 요청입니다.' });

  const email = normalizeEmail(parsed.data.email);
  const code = String(parsed.data.code || '').replace(/\s+/g, '');
  if (!email || !CODE_RE.test(code)) {
    return json(request, 400, { error: '이메일과 6자리 인증 코드를 입력하세요.' });
  }

  const res = await store.verifyCode(email, code);
  if (!res.ok) {
    await store.recordRateLimit(rlKey);
    const messages = {
      no_code: '인증 코드가 없습니다. 인증 메일을 다시 발송해 주세요.',
      expired: '인증 코드가 만료되었습니다. 재발송 버튼을 눌러 주세요.',
      too_many_attempts: '인증 코드를 5회 틀려 무효화되었습니다. 재발송해 주세요.',
      invalid_code: `인증 코드가 틀렸습니다. (남은 기회 ${res.remaining}회)`,
    };
    return json(request, 400, { error: messages[res.error] || '인증에 실패했습니다.' });
  }

  await store.clearRateLimit(rlKey);
  const role = isAdminEmail(email, env) ? 'admin' : 'user';
  const cookie = await issueSessionCookie(request, env, { email, role });
  return json(request, 200, { ok: true, email }, { 'Set-Cookie': cookie });
}

async function handleResend(request, env) {
  if (!authConfig(env).emailAuth) return json(request, 404, { error: 'disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `resend:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 5))) {
    return json(request, 429, { error: '재발송 요청이 너무 많습니다. 15분 뒤에 다시 시도하세요.' });
  }

  const parsed = await readJsonBody(request);
  if (parsed.error) return json(request, 400, { error: '잘못된 요청입니다.' });

  const email = normalizeEmail(parsed.data.email);
  if (!email) return json(request, 400, { error: '올바른 이메일 주소를 입력하세요.' });

  await store.recordRateLimit(rlKey);
  const res = await store.issueResendCode(email);
  if (!res.ok) {
    if (res.error === 'cooldown') {
      return json(request, 429, { error: `${res.waitSec}초 뒤에 다시 보낼 수 있습니다.` });
    }
    if (res.error === 'already_verified') {
      return json(request, 409, { error: '이미 인증된 이메일입니다. 로그인해 주세요.' });
    }
    return json(request, 404, { error: '가입 대기 중인 이메일을 찾을 수 없습니다.' });
  }

  try {
    await sendVerificationEmail(env, { to: email, code: res.code, origin: new URL(request.url).origin });
  } catch (err) {
    await store.rollbackCode(email);
    console.error('인증 메일 재발송 실패:', err);
    return json(request, 502, { error: '메일 발송에 실패했습니다.' });
  }

  return json(request, 200, { ok: true, expiresInSec: res.expiresInSec });
}

async function handleEmailLogin(request, env) {
  if (!authConfig(env).emailAuth) return json(request, 404, { error: 'disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `elogin:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 5))) {
    return json(request, 429, { error: '로그인 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.' });
  }

  const parsed = await readJsonBody(request);
  if (parsed.error) return json(request, 400, { error: '잘못된 요청입니다.' });

  const email = normalizeEmail(parsed.data.email);
  const password = typeof parsed.data.password === 'string' ? parsed.data.password : '';
  if (!email || !password) return json(request, 400, { error: '이메일과 비밀번호를 입력하세요.' });

  const res = await store.verifyLogin(email, password);
  if (!res.ok) {
    if (res.error === 'not_verified') {
      return json(request, 403, {
        error: 'email_not_verified',
        message: '이메일 인증이 완료되지 않았습니다. 받은 6자리 인증 코드를 입력해 주세요.',
      });
    }
    await store.recordRateLimit(rlKey);
    return json(request, 401, { error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
  }

  await store.clearRateLimit(rlKey);
  const role = isAdminEmail(email, env) ? 'admin' : 'user';
  const cookie = await issueSessionCookie(request, env, { email, role });
  return withSecurityHeaders(request, new Response(null, { status: 204 }), { 'Set-Cookie': cookie });
}

async function handleGuestPassLogin(request, env) {
  if (!authConfig(env).guestPass) return json(request, 404, { error: 'disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `pass:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 5))) {
    return json(request, 429, { error: '시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.' });
  }

  const parsed = await readJsonBody(request, 1024);
  if (parsed.error) return json(request, 400, { error: '잘못된 요청입니다.' });

  const res = await store.redeemGuestPass(parsed.data.code);
  if (!res.ok) {
    await store.recordRateLimit(rlKey);
    return json(request, 401, {
      error: res.error === 'expired' ? '만료된 특별 코드입니다.' : '유효하지 않거나 만료된 특별 코드입니다.',
    });
  }

  await store.clearRateLimit(rlKey);
  const cookie = await issueSessionCookie(request, env, { email: '', role: 'guest', ttlSec: 2 * 3600 });
  return withSecurityHeaders(request, new Response(null, { status: 204 }), { 'Set-Cookie': cookie });
}

async function handleSharedPasswordLogin(request, env) {
  if (!authConfig(env).sharedPassword) return json(request, 404, { error: 'password_auth_disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const store = accountsStub(env);
  const rlKey = `pwlogin:${await sha256Hex(clientIp(request))}`;
  if (!(await store.checkRateLimit(rlKey, 5))) {
    return json(request, 429, { error: 'too_many_attempts' });
  }

  const parsed = await readJsonBody(request, 2048);
  if (parsed.error) return json(request, parsed.error === 'too_large' ? 413 : 400, { error: 'bad_request' });

  const ok = await verifyPassword(parsed.data.password, env.APP_PASSWORD);
  if (!ok) {
    await store.recordRateLimit(rlKey);
    return json(request, 401, { error: 'invalid_password' });
  }

  await store.clearRateLimit(rlKey);
  const cookie = await issueSessionCookie(request, env, { email: '', role: 'admin' });
  return withSecurityHeaders(request, new Response(null, { status: 204 }), { 'Set-Cookie': cookie });
}

function misconfiguredResponse(request) {
  return withSecurityHeaders(
    request,
    new Response(
      '인증 설정이 비어 있어 안전을 위해 차단되었습니다.\n' +
        'APP_PASSWORD, 이메일 회원가입(INVITE_CODE + 메일 발송기), 또는 Cloudflare Access를 설정하세요.',
      { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    )
  );
}
