// 소셜 로그인 (Google OAuth 2.0 + PKCE, GitHub OAuth 2.0) — 외부 라이브러리 없이 Web Crypto + fetch만 사용
import { parseCookies } from './auth.js';

const STATE_COOKIE = 'p2pft_oauth_state';
const PENDING_COOKIE = 'p2pft_oauth_pending';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

async function oauthHmacKey(env) {
  const secret = env.SESSION_SECRET || env.APP_PASSWORD || env.INVITE_CODE || env.GOOGLE_CLIENT_SECRET || env.GITHUB_CLIENT_SECRET || '';
  if (secret.length < 8) throw new Error('OAuth 서명용 비밀키가 필요합니다.');
  const material = await crypto.subtle.digest('SHA-256', encoder.encode(`p2pft-oauth-v1:${secret}`));
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signPayload(env, obj) {
  const encoded = toBase64Url(encoder.encode(JSON.stringify(obj)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await oauthHmacKey(env), encoder.encode(encoded)));
  return `${encoded}.${toBase64Url(sig)}`;
}

async function verifyPayload(env, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  let sigBytes;
  try { sigBytes = fromBase64Url(parts[1]); } catch { return null; }
  const ok = await crypto.subtle.verify('HMAC', await oauthHmacKey(env), sigBytes, encoder.encode(parts[0]));
  if (!ok) return null;
  try {
    const data = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
    if (!data || typeof data.exp !== 'number' || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

function cookieHeader(request, name, value, maxAgeSec, sameSite = 'Lax') {
  const secure = new URL(request.url).protocol === 'https:';
  return `${name}=${value}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

export function oauthProviders(env) {
  return {
    google: !!(env.GOOGLE_CLIENT_ID?.trim() && env.GOOGLE_CLIENT_SECRET?.trim()),
    github: !!(env.GITHUB_CLIENT_ID?.trim() && env.GITHUB_CLIENT_SECRET?.trim()),
  };
}

export function sanitizeNext(next) {
  const s = String(next || '/');
  return s.startsWith('/') && !s.startsWith('//') && !s.startsWith('/\\') ? s : '/';
}

// ================================================================ 1) OAuth 시작 (리다이렉트 URL + state/PKCE 쿠키 생성)
export async function buildOAuthStart(request, env, provider, next) {
  const origin = new URL(request.url).origin;
  const state = toBase64Url(crypto.getRandomValues(new Uint8Array(24)));
  const verifier = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(verifier))));
  const safeNext = sanitizeNext(next);

  const stateToken = await signPayload(env, {
    provider,
    state,
    verifier,
    next: safeNext,
    exp: Date.now() + 10 * 60_000,
  });

  const redirectUri = `${origin}/api/auth/oauth/${provider}/callback`;
  let authorizeUrl;

  if (provider === 'google') {
    const authBase = (env.OAUTH_GOOGLE_AUTH_URL || 'https://accounts.google.com/o/oauth2/v2/auth').trim();
    const u = new URL(authBase);
    u.searchParams.set('client_id', env.GOOGLE_CLIENT_ID.trim());
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('scope', 'openid email profile');
    u.searchParams.set('state', state);
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    u.searchParams.set('prompt', 'select_account');
    authorizeUrl = u.toString();
  } else if (provider === 'github') {
    const authBase = (env.OAUTH_GITHUB_AUTH_URL || 'https://github.com/login/oauth/authorize').trim();
    const u = new URL(authBase);
    u.searchParams.set('client_id', env.GITHUB_CLIENT_ID.trim());
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('scope', 'read:user user:email');
    u.searchParams.set('state', state);
    authorizeUrl = u.toString();
  } else {
    throw new Error('지원하지 않는 소셜 로그인입니다.');
  }

  return {
    authorizeUrl,
    setCookie: cookieHeader(request, STATE_COOKIE, stateToken, 600, 'Lax'),
  };
}

// ================================================================ 2) OAuth 콜백 검증 & 인증된 이메일 조회
export async function handleOAuthCallback(request, env, provider) {
  const url = new URL(request.url);
  const clearState = cookieHeader(request, STATE_COOKIE, '', 0, 'Lax');

  if (url.searchParams.get('error')) {
    return { ok: false, error: '소셜 로그인이 취소되었습니다.', clearState };
  }

  const code = url.searchParams.get('code') || '';
  const returnedState = url.searchParams.get('state') || '';
  const stateCookie = parseCookies(request.headers.get('cookie') || '')[STATE_COOKIE];
  const saved = await verifyPayload(env, stateCookie);

  if (!code || !saved || saved.provider !== provider || saved.state !== returnedState) {
    return { ok: false, error: '로그인 인증 상태가 만료되었거나 올바르지 않습니다. 다시 시도해 주세요.', clearState };
  }

  const redirectUri = `${url.origin}/api/auth/oauth/${provider}/callback`;

  try {
    if (provider === 'google') {
      const tokenUrl = (env.OAUTH_GOOGLE_TOKEN_URL || 'https://oauth2.googleapis.com/token').trim();
      const tokenRes = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID.trim(),
          client_secret: env.GOOGLE_CLIENT_SECRET.trim(),
          code,
          code_verifier: saved.verifier,
          grant_type: 'authorization_code',
          redirect_uri: redirectUri,
        }),
      });
      if (!tokenRes.ok) throw new Error(`Google 토큰 교환 실패 (${tokenRes.status})`);
      const tokenData = await tokenRes.json();

      const userUrl = (env.OAUTH_GOOGLE_USERINFO_URL || 'https://openidconnect.googleapis.com/v1/userinfo').trim();
      const userRes = await fetch(userUrl, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      if (!userRes.ok) throw new Error(`Google 프로필 조회 실패 (${userRes.status})`);
      const profile = await userRes.json();

      if (!profile.email || profile.email_verified !== true) {
        return { ok: false, error: '이메일이 인증된 Google 계정만 로그인할 수 있습니다.', clearState };
      }

      return { ok: true, email: String(profile.email).trim().toLowerCase(), next: saved.next, clearState };
    }

    if (provider === 'github') {
      const tokenUrl = (env.OAUTH_GITHUB_TOKEN_URL || 'https://github.com/login/oauth/access_token').trim();
      const tokenRes = await fetch(tokenUrl, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID.trim(),
          client_secret: env.GITHUB_CLIENT_SECRET.trim(),
          code,
          redirect_uri: redirectUri,
        }),
      });
      if (!tokenRes.ok) throw new Error(`GitHub 토큰 교환 실패 (${tokenRes.status})`);
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) throw new Error('GitHub 액세스 토큰이 없습니다.');

      const emailsUrl = (env.OAUTH_GITHUB_EMAILS_URL || 'https://api.github.com/user/emails').trim();
      const emailsRes = await fetch(emailsUrl, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'p2p-file-transfer-worker',
        },
      });
      if (!emailsRes.ok) throw new Error(`GitHub 이메일 조회 실패 (${emailsRes.status})`);
      const emails = await emailsRes.json();
      const verified = Array.isArray(emails)
        ? emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified)
        : null;

      if (!verified?.email) {
        return { ok: false, error: '인증된 이메일이 등록된 GitHub 계정만 로그인할 수 있습니다.', clearState };
      }

      return { ok: true, email: String(verified.email).trim().toLowerCase(), next: saved.next, clearState };
    }

    return { ok: false, error: '지원하지 않는 소셜 로그인입니다.', clearState };
  } catch (err) {
    console.error('OAuth 오류:', err);
    return { ok: false, error: '소셜 로그인 처리 중 오류가 발생했습니다.', clearState };
  }
}

// ================================================================ 3) 첫 소셜 로그인 초대코드 대기 티켓 (5분)
export async function issuePendingOAuthCookie(request, env, { email, provider, next }) {
  const token = await signPayload(env, {
    email,
    provider,
    next: sanitizeNext(next),
    exp: Date.now() + 5 * 60_000,
  });
  return cookieHeader(request, PENDING_COOKIE, token, 300, 'Strict');
}

export async function verifyPendingOAuthCookie(request, env) {
  const token = parseCookies(request.headers.get('cookie') || '')[PENDING_COOKIE];
  return verifyPayload(env, token);
}

export function clearPendingOAuthCookie(request) {
  return cookieHeader(request, PENDING_COOKIE, '', 0, 'Strict');
}
