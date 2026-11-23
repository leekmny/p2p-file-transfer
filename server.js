// P2P 파일 전송 서버: 정적 파일 + 비밀번호 로그인 + WebRTC 시그널링(WebSocket)
//
// 파일 데이터는 이 서버를 절대 거치지 않습니다. 서버는 로그인한 사용자끼리
// 서로를 찾고 연결 정보(SDP / ICE candidate)를 교환하도록 중개만 합니다.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

// ================================================================ 설정
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
const env = process.env;

const config = {
  port: Number(env.PORT) || 3000,
  host: env.HOST || '127.0.0.1', // 기본은 로컬 전용. 외부 접근은 tailscale serve 등 HTTPS 프록시로
  password: env.APP_PASSWORD || '',
  sessionTtlMs: (Number(env.SESSION_TTL_HOURS) || 12) * 3_600_000,
  trustProxy: env.TRUST_PROXY === '1',
  cookieSecure: env.COOKIE_SECURE === '1',
  allowedOrigins: list(env.ALLOWED_ORIGINS),
  stunUrls: env.STUN_URLS === undefined ? ['stun:stun.l.google.com:19302'] : list(env.STUN_URLS),
  turnUrls: list(env.TURN_URLS),
  turnSecret: env.TURN_SECRET || '',
  turnUsername: env.TURN_USERNAME || '',
  turnCredential: env.TURN_CREDENTIAL || '',
};

if (config.password.length < 8) {
  console.error('❌ APP_PASSWORD(8자 이상)를 설정하세요. .env.example을 .env로 복사해 수정하면 됩니다.');
  process.exit(1);
}

// ================================================================ 공통 응답
const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer', // URL의 방 코드가 외부로 새지 않도록
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

function isSecure(req) {
  return config.cookieSecure || req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
}

function send(req, res, status, body = '', headers = {}) {
  const extra = isSecure(req) ? { 'Strict-Transport-Security': 'max-age=31536000' } : {};
  res.writeHead(status, { ...SECURITY_HEADERS, ...extra, 'Cache-Control': 'no-store', ...headers });
  res.end(req.method === 'HEAD' ? undefined : body);
}

function json(req, res, status, obj) {
  send(req, res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8' });
}

function clientIp(req) {
  if (config.trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// 같은 사이트에서 온 요청인지 확인 (Cross-Site WebSocket Hijacking / CSRF 방지)
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  let o;
  try { o = new URL(origin); } catch { return false; }
  if (config.allowedOrigins.length) return config.allowedOrigins.includes(o.origin);
  const hosts = [req.headers.host, req.headers['x-forwarded-host']]
    .filter(Boolean)
    .flatMap((h) => String(h).split(',').map((s) => s.trim()));
  if (hosts.includes(o.host)) return true;
  console.warn(`⚠️  Origin 거부: ${origin} (프록시 뒤라면 .env에 ALLOWED_ORIGINS=${o.origin} 설정)`);
  return false;
}

// ================================================================ 로그인 / 세션
const COOKIE = 'p2pft_sid';
const sessions = new Map(); // token -> 만료 시각(ms)
const PASSWORD_HASH = crypto.createHash('sha256').update(config.password).digest();

const LOGIN_MAX_FAILS = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;
const loginFailures = new Map(); // ip -> { count, first }

function checkPassword(input) {
  const h = crypto.createHash('sha256').update(String(input)).digest();
  return crypto.timingSafeEqual(h, PASSWORD_HASH); // 타이밍 공격 방지
}

function isLocked(ip) {
  const r = loginFailures.get(ip);
  return !!r && r.count >= LOGIN_MAX_FAILS && Date.now() - r.first < LOGIN_WINDOW_MS;
}

function recordFailure(ip) {
  let r = loginFailures.get(ip);
  if (!r || Date.now() - r.first >= LOGIN_WINDOW_MS) r = { count: 0, first: Date.now() };
  r.count++;
  loginFailures.set(ip, r);
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* 무시 */ }
  }
  return out;
}

function getSession(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (!token) return null;
  const exp = sessions.get(token);
  if (!exp) return null;
  if (exp < Date.now()) { sessions.delete(token); return null; }
  return token;
}

function sessionCookie(req, token, maxAgeSec) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${isSecure(req) ? '; Secure' : ''}`;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function handleLogin(req, res) {
  if (req.headers.origin && !originAllowed(req)) return json(req, res, 403, { error: 'forbidden' });
  const ip = clientIp(req);
  if (isLocked(ip)) return json(req, res, 429, { error: 'too_many_attempts' });

  let body;
  try { body = JSON.parse(await readBody(req, 2048)); } catch { return json(req, res, 400, { error: 'bad_request' }); }

  if (!checkPassword(typeof body?.password === 'string' ? body.password : '')) {
    recordFailure(ip);
    console.warn(`🔐 로그인 실패: ${ip}`);
    await sleep(400 + crypto.randomInt(300)); // 무차별 대입 속도 늦추기
    return json(req, res, 401, { error: 'invalid_password' });
  }

  loginFailures.delete(ip);
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, Date.now() + config.sessionTtlMs);
  send(req, res, 204, '', { 'Set-Cookie': sessionCookie(req, token, Math.floor(config.sessionTtlMs / 1000)) });
}

function handleLogout(req, res) {
  if (req.headers.origin && !originAllowed(req)) return json(req, res, 403, { error: 'forbidden' });
  const token = getSession(req);
  if (token) {
    sessions.delete(token);
    for (const ws of wss.clients) if (ws.session === token) ws.close(4401, 'logged out');
  }
  send(req, res, 204, '', { 'Set-Cookie': sessionCookie(req, '', 0) });
}

// ================================================================ ICE 서버 (STUN/TURN)
function iceServers() {
  const servers = [];
  if (config.stunUrls.length) servers.push({ urls: config.stunUrls });
  if (config.turnUrls.length) {
    if (config.turnSecret) {
      // coturn의 use-auth-secret 방식: 1시간짜리 임시 자격 증명 발급 (비밀키는 클라이언트에 노출되지 않음)
      const username = `${Math.floor(Date.now() / 1000) + 3600}:p2pft`;
      const credential = crypto.createHmac('sha1', config.turnSecret).update(username).digest('base64');
      servers.push({ urls: config.turnUrls, username, credential });
    } else if (config.turnUsername) {
      servers.push({ urls: config.turnUrls, username: config.turnUsername, credential: config.turnCredential });
    }
  }
  return servers;
}

// ================================================================ HTTP
// 제공하는 파일을 화이트리스트로 고정 (경로 조작 원천 차단)
const FILES = {
  '/login.html': { file: 'login.html', public: true },
  '/login.js': { file: 'login.js', public: true },
  '/style.css': { file: 'style.css', public: true },
  '/favicon.svg': { file: 'favicon.svg', public: true },
  '/': { file: 'index.html' },
  '/index.html': { file: 'index.html' },
  '/app.js': { file: 'app.js' },
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

async function serveFile(req, res, entry) {
  const data = await readFile(path.join(PUBLIC_DIR, entry.file));
  send(req, res, 200, data, { 'Content-Type': MIME[path.extname(entry.file)] });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    if (p === '/api/login') {
      return req.method === 'POST' ? await handleLogin(req, res) : send(req, res, 405);
    }
    if (p === '/api/logout') {
      return req.method === 'POST' ? handleLogout(req, res) : send(req, res, 405);
    }
    if (p === '/api/session') {
      const ok = !!getSession(req);
      return json(req, res, ok ? 200 : 401, { ok });
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(req, res, 405);

    const entry = FILES[p];
    if (entry?.public) return await serveFile(req, res, entry);

    if (!getSession(req)) {
      if (p === '/' || p === '/index.html') {
        return send(req, res, 302, '', { Location: `/login.html?next=${encodeURIComponent(p + url.search)}` });
      }
      return json(req, res, 401, { error: 'unauthorized' });
    }

    if (p === '/config') return json(req, res, 200, { iceServers: iceServers() });
    if (entry) return await serveFile(req, res, entry);
    return send(req, res, 404, 'Not found', { 'Content-Type': 'text/plain; charset=utf-8' });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(req, res, 500);
    else res.destroy();
  }
});

// ================================================================ 시그널링 (WebSocket)
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 헷갈리는 0/O, 1/I 제외
const rooms = new Map(); // code -> Set<WebSocket> (방당 최대 2명)
const MAX_CONN_PER_IP = 20;
const MAX_CONN_TOTAL = 200;

const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

function reject(socket, status, text) {
  socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ws') return reject(socket, 404, 'Not Found');

  const session = getSession(req);
  if (!session || !originAllowed(req)) return reject(socket, 401, 'Unauthorized');

  const ip = clientIp(req);
  let perIp = 0;
  for (const c of wss.clients) if (c.ip === ip) perIp++;
  if (perIp >= MAX_CONN_PER_IP || wss.clients.size >= MAX_CONN_TOTAL) {
    return reject(socket, 429, 'Too Many Requests');
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.ip = ip;
    ws.session = session;
    wss.emit('connection', ws, req);
  });
});

function newCode() {
  let code;
  do {
    code = Array.from({ length: 6 }, () => ALPHABET[crypto.randomInt(ALPHABET.length)]).join('');
  } while (rooms.has(code));
  return code;
}

function wsSend(ws, msg) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}

function peerOf(ws) {
  const room = rooms.get(ws.room);
  if (!room) return null;
  for (const p of room) if (p !== ws) return p;
  return null;
}

function leave(ws) {
  if (!ws.room) return;
  const room = rooms.get(ws.room);
  if (room) {
    room.delete(ws);
    for (const p of room) wsSend(p, { type: 'peer-left' });
    if (room.size === 0) rooms.delete(ws.room);
  }
  ws.room = null;
}

// 연결당 메시지 속도 제한 (token bucket: 초당 20개, 최대 100개 몰아서)
function allowMessage(ws) {
  const now = Date.now();
  ws.tokens = Math.min(100, ws.tokens + ((now - ws.lastRefill) / 1000) * 20);
  ws.lastRefill = now;
  if (ws.tokens < 1) return false;
  ws.tokens--;
  return true;
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.room = null;
  ws.tokens = 100;
  ws.lastRefill = Date.now();
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw, isBinary) => {
    if (isBinary) return;
    if (!allowMessage(ws)) return ws.close(1008, 'rate limit');

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object') return;

    switch (msg.type) {
      case 'create': {
        leave(ws);
        const code = newCode();
        rooms.set(code, new Set([ws]));
        ws.room = code;
        wsSend(ws, { type: 'created', room: code });
        break;
      }

      case 'join': {
        const code = String(msg.room || '').toUpperCase().trim();
        if (!/^[A-Z0-9]{6}$/.test(code)) {
          return wsSend(ws, { type: 'error', message: '방 코드는 6자리 영문/숫자입니다.' });
        }
        let room = rooms.get(code);
        // 재접속(rejoin)일 때는 서버 재시작 등으로 방이 사라졌어도 다시 만들어 줌
        if (!room && msg.rejoin) {
          room = new Set();
          rooms.set(code, room);
        }
        if (!room) return wsSend(ws, { type: 'error', message: '존재하지 않는 방 코드입니다.' });
        if (room.has(ws)) return;
        if (room.size >= 2) return wsSend(ws, { type: 'error', message: '이미 두 명이 접속한 방입니다.' });

        leave(ws);
        room.add(ws);
        ws.room = code;
        wsSend(ws, { type: 'joined', room: code, peers: room.size });
        for (const p of room) if (p !== ws) wsSend(p, { type: 'peer-joined', rejoin: !!msg.rejoin });
        break;
      }

      case 'signal': {
        if (!msg.data || typeof msg.data !== 'object') return;
        const peer = peerOf(ws);
        if (peer) wsSend(peer, { type: 'signal', data: msg.data });
        break;
      }

      case 'leave':
        leave(ws);
        break;
    }
  });

  ws.on('close', () => leave(ws));
});

// 30초마다: 죽은 연결 정리 + 만료된 세션의 연결 종료
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    const exp = sessions.get(ws.session);
    if (!exp || exp < Date.now()) { ws.close(4401, 'session expired'); continue; }
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30_000);
heartbeat.unref();

// 10분마다 만료 데이터 정리
setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
  for (const [ip, r] of loginFailures) if (now - r.first >= LOGIN_WINDOW_MS) loginFailures.delete(ip);
}, 10 * 60_000).unref();

wss.on('close', () => clearInterval(heartbeat));

server.listen(config.port, config.host, () => {
  console.log(`📡 P2P 파일 전송 서버: http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`);
  if (!['127.0.0.1', 'localhost', '::1'].includes(config.host)) {
    console.warn('⚠️  로컬 외 인터페이스에 열려 있습니다. 외부에서 쓸 때는 반드시 HTTPS 프록시(tailscale serve 등)를 거치세요.');
  }
});

export { server, wss, config };
