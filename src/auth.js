// 인증 유틸리티 (외부 라이브러리 없이 Web Crypto API만 사용)
// - 공유 비밀번호(APP_PASSWORD), 이메일 계정(AccountStore), 10분 임시 특별 코드(guest) → HMAC-SHA256 세션 쿠키
// - Cloudflare Access: Cf-Access-Jwt-Assertion (RS256) JWKS 서명 검증
import { hasEmailProvider } from './email.js';
import { oauthProviders } from './oauth.js';

const COOKIE_NAME = 'p2pft_sid';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

export async function constantTimeSecretMatch(input, expected) {
  if (typeof input !== 'string' || typeof expected !== 'string' || !expected.length) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(input)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);
  return constantTimeEqual(new Uint8Array(a), new Uint8Array(b));
}

// ================================================================ 비밀번호 / HMAC 세션 쿠키
export async function verifyPassword(input, expected) {
  if (typeof expected !== 'string' || expected.length < 8) return false;
  return constantTimeSecretMatch(input, expected);
}

function sessionSecretSource(env) {
  return (
    env.SESSION_SECRET ||
    env.APP_PASSWORD ||
    env.INVITE_CODE ||
    env.GOOGLE_CLIENT_SECRET ||
    env.GITHUB_CLIENT_SECRET ||
    ''
  );
}

async function sessionKey(env) {
  const secret = sessionSecretSource(env);
  if (secret.length < 8) throw new Error('SESSION_SECRET (or APP_PASSWORD / INVITE_CODE) must be at least 8 chars');
  const material = await crypto.subtle.digest('SHA-256', encoder.encode(`p2pft-session-v3:${secret}`));
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// role: 'admin' | 'user' | 'guest'
export async function issueSessionCookie(request, env, { email = '', role = 'user', ttlSec } = {}) {
  const defaultSec = Math.floor(Math.max(1, Number(env.SESSION_TTL_HOURS) || 12) * 3600);
  const maxAge = Math.max(60, Number(ttlSec) || defaultSec);
  const exp = Date.now() + maxAge * 1000;
  const sub = toBase64Url(encoder.encode(email || ''));
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const payload = `${exp}.${role}.${sub}.${nonce}`;
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await sessionKey(env), encoder.encode(payload)));
  const token = `${payload}.${toBase64Url(sig)}`;
  return buildCookie(request, token, maxAge);
}

export function clearSessionCookie(request) {
  return buildCookie(request, '', 0);
}

function buildCookie(request, value, maxAgeSec) {
  const secure = new URL(request.url).protocol === 'https:';
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

export async function verifySessionCookie(request, env) {
  if (sessionSecretSource(env).length < 8) return null;
  const token = parseCookies(request.headers.get('cookie') || '')[COOKIE_NAME];
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 5) return null;
  const [expStr, role, subStr, nonce, sigStr] = parts;
  const exp = Number(expStr);
  if (!Number.isSafeInteger(exp) || exp < Date.now() || !nonce) return null;
  if (!['admin', 'user', 'guest'].includes(role)) return null;

  let sigBytes;
  let email = '';
  try {
    sigBytes = fromBase64Url(sigStr);
    email = subStr ? decoder.decode(fromBase64Url(subStr)) : '';
  } catch {
    return null;
  }

  const payload = `${expStr}.${role}.${subStr}.${nonce}`;
  const valid = await crypto.subtle.verify('HMAC', await sessionKey(env), sigBytes, encoder.encode(payload));
  if (!valid) return null;
  return { email: email || null, role };
}

// ================================================================ Cloudflare Access JWT 검증
const jwksCache = new Map();
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
    header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
    payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
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

  try {
    let keys = await fetchJwks(rawDomain);
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) {
      keys = await fetchJwks(rawDomain, true);
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
function parseEmailList(raw) {
  return (raw || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function allowedEmailsList(env) {
  return parseEmailList(env.ALLOWED_EMAILS);
}

export function adminEmailsList(env) {
  return parseEmailList(env.ADMIN_EMAILS);
}

export function isAdminEmail(email, env) {
  if (!email) return false;
  return adminEmailsList(env).includes(email.trim().toLowerCase());
}

export function authConfig(env) {
  const access = !!(env.ACCESS_TEAM_DOMAIN?.trim() && env.ACCESS_AUD?.trim());
  const sharedPassword = !!(env.APP_PASSWORD && env.APP_PASSWORD.length >= 8);
  const inviteRequired = !!(env.INVITE_CODE && env.INVITE_CODE.length >= 4);
  const hasAllowedEmails = allowedEmailsList(env).length > 0;
  const hasAdminEmails = adminEmailsList(env).length > 0;
  const openSignup = env.ALLOW_OPEN_SIGNUP === '1';
  const hasSessionSecret = sessionSecretSource(env).length >= 8;

  // 이메일 회원가입은 메일 발송기 + (초대코드 or 허용 이메일 or 명시적 오픈) + 세션키가 있을 때 활성화
  const emailAuth = hasEmailProvider(env) && (inviteRequired || hasAllowedEmails || openSignup) && hasSessionSecret;

  // 소셜 로그인(Google / GitHub): 클라이언트 ID+시크릿 + 접근 제한(허용 이메일/관리자 이메일/초대코드/오픈)
  const oauth = oauthProviders(env);
  const oauthGateReady = inviteRequired || hasAllowedEmails || hasAdminEmails || openSignup;
  const googleOAuth = oauth.google && oauthGateReady && hasSessionSecret;
  const githubOAuth = oauth.github && oauthGateReady && hasSessionSecret;

  const cookieAuth = sharedPassword || emailAuth || googleOAuth || githubOAuth;

  // 임시 특별 코드: 세션 서명 키가 있으면 사용 가능 (관리자가 발급 → 게스트는 모든 인증 없이 입장)
  const guestPass = hasSessionSecret && (cookieAuth || access);

  return {
    access,
    sharedPassword,
    emailAuth,
    googleOAuth,
    githubOAuth,
    inviteRequired,
    guestPass,
    cookieAuth,
  };
}

export async function authenticate(request, env) {
  const cfg = authConfig(env);
  if (!cfg.access && !cfg.cookieAuth) return { ok: false, misconfigured: true };

  // 1) 임시 특별 코드로 발급된 게스트 세션은 모든 인증을 건너뛰고 통과
  const cookieSession = await verifySessionCookie(request, env);
  if (cookieSession?.role === 'guest') {
    return { ok: true, mode: 'guest', email: null, isAdmin: false, isGuest: true };
  }

  let email = null;
  let isAdmin = false;

  if (cfg.access) {
    const identity = await verifyAccessJwt(request, env);
    if (!identity) return { ok: false, needAccess: true };
    email = identity.email;
    if (isAdminEmail(email, env) || !adminEmailsList(env).length) isAdmin = true;
  }

  if (cfg.cookieAuth) {
    if (!cookieSession) return { ok: false, needLogin: true, email };
    if (cookieSession.email) email = cookieSession.email;
    if (cookieSession.role === 'admin' || isAdminEmail(email, env)) isAdmin = true;
  }

  return {
    ok: true,
    mode: cfg.access && cfg.cookieAuth ? 'both' : cfg.access ? 'access' : 'cookie',
    email,
    isAdmin,
    isGuest: false,
  };
}
