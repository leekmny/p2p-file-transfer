// SQLite 기반 회원·이메일 인증·관리자 10분 임시 특별 코드·속도 제한 Durable Object
// (Workers 무료 플랜 호환)
// - 비밀번호: 16바이트 랜덤 솔트 + PBKDF2-SHA256 (100,000회)
// - 이메일 인증 코드: 6자리 난수 SHA-256 해시 (10분 만료, 5회 오류 시 무효화, 60초 쿨다운)
// - 관리자 임시 특별 코드: 8자리 랜덤 코드 SHA-256 해시 (10분 후 자동 파기, 수동 즉시 파기 지원)
import { DurableObject } from 'cloudflare:workers';

const PBKDF2_ITERATIONS = 100_000; // Cloudflare Workers Web Crypto 최대 지원치
const CODE_TTL_MS = 10 * 60_000;
const CODE_MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_MS = 60_000;
const GUEST_PASS_TTL_MS = 10 * 60_000; // 특별 코드: 10분 후 자동 파기
const RATE_WINDOW_MS = 15 * 60_000;

const PASS_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 헷갈리는 0/O, 1/I 제외 (32종)
const encoder = new TextEncoder();

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return toHex(new Uint8Array(digest));
}

function generateSixDigitCode() {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  let val;
  do {
    crypto.getRandomValues(buf);
    val = buf[0];
  } while (val >= limit);
  return String(val % 1_000_000).padStart(6, '0');
}

function generateGuestPassCode() {
  // 32 = 2^5 이므로 8비트 난수 & 31 은 모듈로 편향 0, 32^8 ≈ 1.1조 가지 조합
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const raw = Array.from(bytes, (b) => PASS_ALPHABET[b & 31]).join('');
  return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}

export class AccountStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS verification_codes (
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        last_sent_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS guest_passes (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        hint TEXT NOT NULL,
        created_by TEXT NOT NULL,
        single_use INTEGER NOT NULL DEFAULT 0,
        uses INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        window_start INTEGER NOT NULL
      );
    `);
  }

  // ---------------------------------------------------------------- 속도 제한
  async checkRateLimit(key, maxCount = 5, windowMs = RATE_WINDOW_MS) {
    const rows = this.ctx.storage.sql
      .exec('SELECT count, window_start FROM rate_limits WHERE key = ?', key)
      .toArray();
    if (!rows.length) return true;
    const { count, window_start } = rows[0];
    if (Date.now() - window_start >= windowMs) {
      this.ctx.storage.sql.exec('DELETE FROM rate_limits WHERE key = ?', key);
      return true;
    }
    return count < maxCount;
  }

  async recordRateLimit(key, windowMs = RATE_WINDOW_MS) {
    const now = Date.now();
    const rows = this.ctx.storage.sql
      .exec('SELECT count, window_start FROM rate_limits WHERE key = ?', key)
      .toArray();
    if (!rows.length || now - rows[0].window_start >= windowMs) {
      this.ctx.storage.sql.exec(
        'INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)',
        key,
        now
      );
    } else {
      this.ctx.storage.sql.exec('UPDATE rate_limits SET count = count + 1 WHERE key = ?', key);
    }
  }

  async clearRateLimit(key) {
    this.ctx.storage.sql.exec('DELETE FROM rate_limits WHERE key = ?', key);
  }

  async clearAllRateLimits() {
    this.ctx.storage.sql.exec('DELETE FROM rate_limits');
  }

  // ---------------------------------------------------------------- 관리자 조회 / 회원 관리
  async listUsers() {
    return this.ctx.storage.sql
      .exec('SELECT email, verified, created_at FROM users ORDER BY created_at DESC')
      .toArray()
      .map((r) => ({ email: r.email, verified: r.verified === 1, createdAt: r.created_at }));
  }

  async verifyUserByAdmin(email) {
    const existing = this.ctx.storage.sql.exec('SELECT email FROM users WHERE email = ?', email).toArray();
    if (!existing.length) return false;
    this.ctx.storage.sql.exec('UPDATE users SET verified = 1 WHERE email = ?', email);
    this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
    return true;
  }

  async deleteUser(email) {
    const existing = this.ctx.storage.sql.exec('SELECT email FROM users WHERE email = ?', email).toArray();
    if (!existing.length) return false;
    this.ctx.storage.sql.exec('DELETE FROM users WHERE email = ?', email);
    this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
    return true;
  }

  async getStats() {
    const now = Date.now();
    this.purgeExpiredPasses(now);
    const u = this.ctx.storage.sql
      .exec('SELECT COUNT(*) AS total, SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) AS verified FROM users')
      .toArray()[0];
    const p = this.ctx.storage.sql.exec('SELECT COUNT(*) AS active FROM guest_passes').toArray()[0];
    const r = this.ctx.storage.sql
      .exec('SELECT COUNT(*) AS locked FROM rate_limits WHERE window_start > ?', now - RATE_WINDOW_MS)
      .toArray()[0];
    return {
      totalUsers: u?.total || 0,
      verifiedUsers: u?.verified || 0,
      pendingUsers: (u?.total || 0) - (u?.verified || 0),
      activePasses: p?.active || 0,
      rateLimitEntries: r?.locked || 0,
    };
  }

  // ---------------------------------------------------------------- 회원가입 & 이메일 인증 코드
  async startRegistration(email, password) {
    const now = Date.now();
    const existing = this.ctx.storage.sql
      .exec('SELECT verified FROM users WHERE email = ?', email)
      .toArray();

    if (existing.length && existing[0].verified === 1) {
      return { ok: false, error: 'already_exists' };
    }

    const prevCode = this.ctx.storage.sql
      .exec('SELECT last_sent_at FROM verification_codes WHERE email = ?', email)
      .toArray();
    if (prevCode.length && now - prevCode[0].last_sent_at < RESEND_COOLDOWN_MS) {
      const waitSec = Math.ceil((RESEND_COOLDOWN_MS - (now - prevCode[0].last_sent_at)) / 1000);
      return { ok: false, error: 'cooldown', waitSec };
    }

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const hashBytes = await hashPassword(password, saltBytes);
    const code = generateSixDigitCode();
    const codeHash = await sha256Hex(`verify-v1:${email}:${code}`);

    this.ctx.storage.sql.exec(
      `INSERT INTO users (email, password_hash, salt, verified, created_at)
       VALUES (?, ?, ?, 0, ?)
       ON CONFLICT(email) DO UPDATE SET
         password_hash = excluded.password_hash,
         salt = excluded.salt,
         created_at = excluded.created_at`,
      email,
      toHex(hashBytes),
      toHex(saltBytes),
      now
    );

    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO verification_codes (email, code_hash, expires_at, attempts, last_sent_at)
       VALUES (?, ?, ?, 0, ?)`,
      email,
      codeHash,
      now + CODE_TTL_MS,
      now
    );

    return { ok: true, code, expiresInSec: Math.floor(CODE_TTL_MS / 1000) };
  }

  async rollbackCode(email) {
    this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
  }

  async issueResendCode(email) {
    const now = Date.now();
    const user = this.ctx.storage.sql
      .exec('SELECT verified FROM users WHERE email = ?', email)
      .toArray();
    if (!user.length) return { ok: false, error: 'not_found' };
    if (user[0].verified === 1) return { ok: false, error: 'already_verified' };

    const prev = this.ctx.storage.sql
      .exec('SELECT last_sent_at FROM verification_codes WHERE email = ?', email)
      .toArray();
    if (prev.length && now - prev[0].last_sent_at < RESEND_COOLDOWN_MS) {
      const waitSec = Math.ceil((RESEND_COOLDOWN_MS - (now - prev[0].last_sent_at)) / 1000);
      return { ok: false, error: 'cooldown', waitSec };
    }

    const code = generateSixDigitCode();
    const codeHash = await sha256Hex(`verify-v1:${email}:${code}`);
    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO verification_codes (email, code_hash, expires_at, attempts, last_sent_at)
       VALUES (?, ?, ?, 0, ?)`,
      email,
      codeHash,
      now + CODE_TTL_MS,
      now
    );

    return { ok: true, code, expiresInSec: Math.floor(CODE_TTL_MS / 1000) };
  }

  async verifyCode(email, code) {
    const now = Date.now();
    const rows = this.ctx.storage.sql
      .exec('SELECT code_hash, expires_at, attempts FROM verification_codes WHERE email = ?', email)
      .toArray();

    if (!rows.length) return { ok: false, error: 'no_code' };
    const rec = rows[0];

    if (rec.expires_at < now) {
      this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
      return { ok: false, error: 'expired' };
    }

    if (rec.attempts >= CODE_MAX_ATTEMPTS) {
      this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
      return { ok: false, error: 'too_many_attempts' };
    }

    const candidateHash = await sha256Hex(`verify-v1:${email}:${code}`);
    if (!constantTimeEqual(fromHex(candidateHash), fromHex(rec.code_hash))) {
      const nextAttempts = rec.attempts + 1;
      if (nextAttempts >= CODE_MAX_ATTEMPTS) {
        this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
        return { ok: false, error: 'too_many_attempts' };
      }
      this.ctx.storage.sql.exec('UPDATE verification_codes SET attempts = ? WHERE email = ?', nextAttempts, email);
      return { ok: false, error: 'invalid_code', remaining: CODE_MAX_ATTEMPTS - nextAttempts };
    }

    this.ctx.storage.sql.exec('UPDATE users SET verified = 1 WHERE email = ?', email);
    this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE email = ?', email);
    return { ok: true };
  }

  async verifyLogin(email, password) {
    const rows = this.ctx.storage.sql
      .exec('SELECT password_hash, salt, verified FROM users WHERE email = ?', email)
      .toArray();
    if (!rows.length) return { ok: false, error: 'invalid_credentials' };

    const { password_hash, salt, verified } = rows[0];
    const derived = await hashPassword(password, fromHex(salt));
    if (!constantTimeEqual(derived, fromHex(password_hash))) {
      return { ok: false, error: 'invalid_credentials' };
    }

    if (verified !== 1) return { ok: false, error: 'not_verified' };
    return { ok: true };
  }

  // ---------------------------------------------------------------- 관리자 임시 특별 코드 (10분 후 자동 파기)
  purgeExpiredPasses(now = Date.now()) {
    this.ctx.storage.sql.exec('DELETE FROM guest_passes WHERE expires_at <= ?', now);
  }

  async scheduleNextPassAlarm() {
    const next = this.ctx.storage.sql
      .exec('SELECT MIN(expires_at) AS next_exp FROM guest_passes')
      .toArray();
    const nextExp = next[0]?.next_exp;
    if (nextExp) await this.ctx.storage.setAlarm(nextExp);
  }

  async createGuestPass(createdBy, singleUse = false, ttlMs = GUEST_PASS_TTL_MS) {
    const now = Date.now();
    this.purgeExpiredPasses(now);

    const safeTtl = Math.max(1000, Math.min(GUEST_PASS_TTL_MS, Number(ttlMs) || GUEST_PASS_TTL_MS));
    const code = generateGuestPassCode();
    const normalized = code.replace(/-/g, '');
    const codeHash = await sha256Hex(`pass-v1:${normalized}`);
    const id = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const hint = `${normalized.slice(0, 2)}••-••${normalized.slice(-2)}`;
    const expiresAt = now + safeTtl;

    this.ctx.storage.sql.exec(
      `INSERT INTO guest_passes (id, code_hash, hint, created_by, single_use, uses, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
      id,
      codeHash,
      hint,
      createdBy || 'admin',
      singleUse ? 1 : 0,
      now,
      expiresAt
    );

    await this.scheduleNextPassAlarm();
    return { id, code, hint, singleUse: !!singleUse, expiresAt, ttlSec: Math.round(safeTtl / 1000) };
  }

  async listGuestPasses() {
    const now = Date.now();
    this.purgeExpiredPasses(now);
    return this.ctx.storage.sql
      .exec('SELECT id, hint, single_use, uses, created_at, expires_at FROM guest_passes ORDER BY created_at DESC')
      .toArray()
      .map((r) => ({
        id: r.id,
        hint: r.hint,
        singleUse: r.single_use === 1,
        uses: r.uses,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      }));
  }

  async revokeGuestPass(id) {
    this.ctx.storage.sql.exec('DELETE FROM guest_passes WHERE id = ?', id);
    await this.scheduleNextPassAlarm();
    return true;
  }

  async redeemGuestPass(rawCode) {
    const now = Date.now();
    this.purgeExpiredPasses(now);

    const normalized = String(rawCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (normalized.length !== 8) return { ok: false, error: 'invalid' };

    const codeHash = await sha256Hex(`pass-v1:${normalized}`);
    const rows = this.ctx.storage.sql
      .exec('SELECT id, single_use, expires_at FROM guest_passes WHERE code_hash = ?', codeHash)
      .toArray();

    if (!rows.length) return { ok: false, error: 'invalid' };
    const pass = rows[0];
    if (pass.expires_at <= now) {
      this.ctx.storage.sql.exec('DELETE FROM guest_passes WHERE id = ?', pass.id);
      return { ok: false, error: 'expired' };
    }

    if (pass.single_use === 1) {
      this.ctx.storage.sql.exec('DELETE FROM guest_passes WHERE id = ?', pass.id);
    } else {
      this.ctx.storage.sql.exec('UPDATE guest_passes SET uses = uses + 1 WHERE id = ?', pass.id);
    }

    return { ok: true, passId: pass.id, passExpiresAt: pass.expires_at };
  }

  // 만료된 임시 코드 및 인증 코드 자동 파기
  async alarm() {
    const now = Date.now();
    this.purgeExpiredPasses(now);
    this.ctx.storage.sql.exec('DELETE FROM verification_codes WHERE expires_at <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM rate_limits WHERE window_start <= ?', now - RATE_WINDOW_MS);
    await this.scheduleNextPassAlarm();
  }
}
