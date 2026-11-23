// 인증 유틸리티 (외부 라이브러리 없이 Web Crypto API만 사용)
// - 비밀번호 로그인: SHA-256 상수 시간 비교 + HMAC-SHA256 서명 세션 쿠키
// - Cloudflare Access: Cf-Access-Jwt-Assertion (RS256) JWKS 서명 검증

const COOKIE_NAME = 'p2pft_sid';
const encoder = new TextEncoder();

// ================================================================ 공통 헬퍼
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch { /* 잘못된 인코딩 무시 */ }
  }
  return out;
}

export async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ================================================================ 비밀번호 / HMAC 세션 쿠키
export async function verifyPassword(input, expected) {
  if (typeof input !== 'string' || typeof expected !== 'string' || expected.length < 8) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(input)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);
  return constantTimeEqual(new Uint8Array(a), new Uint8Array(b));
}

async function sessionKey(env) {
  const material = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`p2pft-session-v1:${env.SESSION_SECRET || env.APP_PASSWORD}`)
  );
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function issueSessionCookie(request, env) {
  const ttlHours = Math.max(1, Number(env.SESSION_TTL_HOURS) || 12);
  const ttlSec = Math.floor(ttlHours * 3600);
  const exp = Date.now() + ttlSec * 1000;
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const payload = `${exp}.${nonce}`;
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await sessionKey(env), encoder.encode(payload)));
  const token = `${payload}.${toBase64Url(sig)}`;
  return buildCookie(request, token, ttlSec);
}

export function clearSessionCookie(request) {
  return buildCookie(request, '', 0);
}

function buildCookie(request, value, maxAgeSec) {
  const secure = new URL(request.url).protocol === 'https:';
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

export async function verifySessionCookie(request, env) {
  const token = parseCookies(request.headers.get('cookie') || '')[COOKIE_NAME];
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [expStr, nonce, sigStr] = parts;
  const exp = Number(expStr);
  if (!Number.isSafeInteger(exp) || exp < Date.now() || !nonce) return false;

  let sigBytes;
  try { sigBytes = fromBase64Url(sigStr); } catch { return false; }

  const payload = `${expStr}.${nonce}`;
  return crypto.subtle.verify('HMAC', await sessionKey(env), sigBytes, encoder.encode(payload));
}

// ================================================================ Cloudflare Access JWT 검증
const jwksCache = new Map(); // domain -> { keys, fetchedAt }
const JWKS_TTL_MS = 10 * 60_000;

async function fetchJwks(teamDomain, force = false) {
  const cached = jwksCache.get(teamDomain);
  if (!force && cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;

  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, {
    cf: { cacheTtl: 600, cacheEverything: true },
  });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const data = await res.json();
  const keys = Array.isArray(data.keys) ? data.keys : [];
  jwksCache.set(teamDomain, { keys, fetchedAt: Date.now() });
  return keys;
}

export async function verifyAccessJwt(request, env) {
  const rawDomain = (env.ACCESS_TEAM_DOMAIN || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const aud = (env.ACCESS_AUD || '').trim();
  if (!rawDomain || !aud) return null;

  const jwt =
    request.headers.get('cf-access-jwt-assertion') ||
    parseCookies(request.headers.get('cookie') || '').CF_Authorization;
  if (!jwt) return null;

  const parts = jwt.split('.');
  if (parts.length !== 3) return null;

  let header, payload, sigBytes;
  try {
    header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1])));
    sigBytes = fromBase64Url(parts[2]);
  } catch {
    return null;
  }

  if (header.alg !== 'RS256' || !header.kid) return null;

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now + 60) return null;
  if (payload.iss !== `https://${rawDomain}`) return null;

  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) return null;

  let keys;
  try {
    keys = await fetchJwks(rawDomain);
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) {
      keys = await fetchJwks(rawDomain, true); // 키 로테이션 대비 1회 재조회
      jwk = keys.find((k) => k.kid === header.kid);
    }
    if (!jwk) return null;

    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      sigBytes,
      encoder.encode(`${parts[0]}.${parts[1]}`)
    );
    if (!valid) return null;
    return { email: payload.email || payload.sub || '' };
  } catch {
    return null;
  }
}

// ================================================================ 통합 인증 판정
export function authConfig(env) {
  const access = !!(env.ACCESS_TEAM_DOMAIN?.trim() && env.ACCESS_AUD?.trim());
  const password = !!(env.APP_PASSWORD && env.APP_PASSWORD.length >= 8);
  return { access, password };
}

export async function authenticate(request, env) {
  const { access, password } = authConfig(env);
  if (!access && !password) return { ok: false, misconfigured: true };

  let email = null;
  if (access) {
    const identity = await verifyAccessJwt(request, env);
    if (!identity) return { ok: false, needAccess: true };
    email = identity.email;
  }

  if (password) {
    const valid = await verifySessionCookie(request, env);
    if (!valid) return { ok: false, needPassword: true, email };
  }

  return {
    ok: true,
    mode: access && password ? 'both' : access ? 'access' : 'password',
    email,
  };
}
