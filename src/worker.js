// Cloudflare Worker 진입점
// - 정적 파일 화이트리스트 + 보안 헤더 + 인증(Cloudflare Access JWT / 비밀번호 쿠키)
// - WebRTC ICE 설정(/config: STUN, Cloudflare Realtime TURN, coturn HMAC)
// - 방 생성/조회(/api/rooms) 및 WebSocket 시그널링(/ws → SignalingRoom Durable Object)
import {
  authenticate,
  authConfig,
  clearSessionCookie,
  issueSessionCookie,
  sha256Hex,
  verifyPassword,
} from './auth.js';

export { SignalingRoom } from './room.js';

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

// 제공하는 정적 파일 화이트리스트 (경로 조작 원천 차단)
const PUBLIC_ASSETS = new Set(['/login.html', '/login.js', '/style.css', '/favicon.svg']);
const PROTECTED_ASSETS = new Set(['/', '/index.html', '/app.js']);

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 헷갈리는 0/O, 1/I 제외
const ROOM_RE = /^[A-Z0-9]{6}$/;

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

function generateRoomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
}

async function buildIceServers(env) {
  const servers = [];
  const stuns = env.STUN_URLS === undefined ? ['stun:stun.l.google.com:19302'] : list(env.STUN_URLS);
  if (stuns.length) servers.push({ urls: stuns });

  // 방법 1: Cloudflare Realtime TURN (월 1TB 무료, 1시간짜리 임시 자격 증명 발급)
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
    } catch { /* TURN 일시 오류 시 STUN으로 폴백 */ }
  }

  // 방법 2: 직접 운영하는 coturn (HMAC-SHA1 임시 자격 증명)
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

    // 1) 인증 API
    if (p === '/api/login') {
      if (request.method !== 'POST') return withSecurityHeaders(request, new Response(null, { status: 405 }));
      return handleLogin(request, env);
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
      return json(request, 200, { ok: true, mode: auth.mode, email: auth.email });
    }

    // 2) 로그인 화면용 공개 정적 파일
    if ((request.method === 'GET' || request.method === 'HEAD') && PUBLIC_ASSETS.has(p)) {
      const asset = await env.ASSETS.fetch(request);
      return withSecurityHeaders(request, asset);
    }

    // 3) 이하 모든 경로는 인증 필수
    const auth = await authenticate(request, env);
    if (auth.misconfigured) return misconfiguredResponse(request);
    if (!auth.ok) {
      if (auth.needPassword && (p === '/' || p === '/index.html')) {
        return withSecurityHeaders(request, new Response(null, { status: 302 }), {
          Location: `/login.html?next=${encodeURIComponent(p + url.search)}`,
        });
      }
      return json(request, auth.needAccess ? 403 : 401, { error: 'unauthorized' });
    }

    // 4) 보호된 정적 파일
    if ((request.method === 'GET' || request.method === 'HEAD') && PROTECTED_ASSETS.has(p)) {
      const assetReq = p === '/' ? new Request(new URL('/index.html', request.url), request) : request;
      const asset = await env.ASSETS.fetch(assetReq);
      return withSecurityHeaders(request, asset);
    }

    // 5) ICE 설정
    if (p === '/config' && request.method === 'GET') {
      return json(request, 200, { iceServers: await buildIceServers(env) });
    }

    // 6) 방 생성
    if (p === '/api/rooms' && request.method === 'POST') {
      if (request.headers.get('origin') && !originAllowed(request, env)) {
        return json(request, 403, { error: 'forbidden' });
      }
      for (let i = 0; i < 5; i++) {
        const code = generateRoomCode();
        const stub = env.ROOMS.get(env.ROOMS.idFromName(`room:${code}`));
        if (await stub.createRoom()) return json(request, 201, { room: code });
      }
      return json(request, 503, { error: '방 생성에 실패했습니다. 다시 시도하세요.' });
    }

    // 7) 방 상태 사전 조회 (참여 전 에러 메시지 표시용)
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

    // 8) WebSocket 시그널링
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

async function handleLogin(request, env) {
  if (!authConfig(env).password) return json(request, 404, { error: 'password_auth_disabled' });
  if (request.headers.get('origin') && !originAllowed(request, env)) {
    return json(request, 403, { error: 'forbidden' });
  }

  const rlStub = env.ROOMS.get(env.ROOMS.idFromName(`rl:${await sha256Hex(clientIp(request))}`));
  if (!(await rlStub.checkLoginAllowed())) {
    return json(request, 429, { error: 'too_many_attempts' });
  }

  let body;
  try {
    const text = await request.text();
    if (text.length > 2048) return json(request, 413, { error: 'too_large' });
    body = JSON.parse(text);
  } catch {
    return json(request, 400, { error: 'bad_request' });
  }

  const ok = await verifyPassword(body?.password, env.APP_PASSWORD);
  if (!ok) {
    await rlStub.recordLoginFailure();
    return json(request, 401, { error: 'invalid_password' });
  }

  await rlStub.clearLoginFailure();
  const cookie = await issueSessionCookie(request, env);
  return withSecurityHeaders(request, new Response(null, { status: 204 }), { 'Set-Cookie': cookie });
}

function misconfiguredResponse(request) {
  return withSecurityHeaders(
    request,
    new Response(
      '인증 설정이 비어 있어 안전을 위해 차단되었습니다.\n' +
        '로컬: .dev.vars에 APP_PASSWORD(8자 이상) 설정\n' +
        '배포: wrangler secret put APP_PASSWORD 또는 ACCESS_TEAM_DOMAIN + ACCESS_AUD 설정',
      { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    )
  );
}
