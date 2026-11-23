// 인증 이메일 발송 모듈 (외부 라이브러리 없이 fetch만 사용)
// 지원하는 발송 방식 (우선순위 순):
//  1) Resend: RESEND_API_KEY + EMAIL_FROM (무료 월 3,000통, 본인 도메인 권장)
//  2) Brevo:  BREVO_API_KEY + EMAIL_FROM  (무료 일 300통)
//  3) Custom Webhook: EMAIL_WEBHOOK_URL (+ 선택 EMAIL_WEBHOOK_SECRET)
//     → 도메인 없이 본인 Gmail(Google Apps Script 5줄) 등으로 무료 발송 가능

export function hasEmailProvider(env) {
  return !!(
    (env.RESEND_API_KEY && env.EMAIL_FROM) ||
    (env.BREVO_API_KEY && env.EMAIL_FROM) ||
    env.EMAIL_WEBHOOK_URL
  );
}

function parseFrom(raw) {
  const m = String(raw || '').match(/^(.*?)<([^>]+)>$/);
  if (m) return { name: m[1].trim().replace(/^"|"$/g, '') || 'P2P 파일 전송', email: m[2].trim() };
  return { name: 'P2P 파일 전송', email: String(raw || '').trim() };
}

export async function sendVerificationEmail(env, { to, code, origin }) {
  const subject = `[P2P 파일 전송] 이메일 인증 코드: ${code}`;
  const text = [
    '안녕하세요,',
    '',
    `이메일 인증 코드 6자리: ${code}`,
    '',
    '이 코드는 10분 동안 유효합니다.',
    origin ? `접속 주소: ${origin}` : '',
    '본인이 요청하지 않았다면 이 메일을 무시하세요.',
  ]
    .filter(Boolean)
    .join('\n');

  const html = `
    <div style="font-family:system-ui,-apple-system,'Malgun Gothic',sans-serif;max-width:460px;margin:0 auto;padding:24px;background:#0f1220;color:#e8eaf6;border-radius:12px;">
      <h2 style="margin:0 0 8px;font-size:20px;">📡 P2P 파일 전송 이메일 인증</h2>
      <p style="margin:0 0 20px;color:#9aa0c3;font-size:14px;">아래 6자리 인증 코드를 입력해 회원가입을 완료하세요.</p>
      <div style="font-size:32px;font-weight:800;letter-spacing:0.25em;text-align:center;padding:18px;background:#181c2f;border:1px solid #2a3050;border-radius:10px;color:#3ecf8e;font-family:ui-monospace,Consolas,monospace;">
        ${code}
      </div>
      <p style="margin:18px 0 0;color:#9aa0c3;font-size:12px;">유효 시간: 10분 · 본인이 요청하지 않았다면 무시하세요.</p>
    </div>`;

  // 1) Resend
  if (env.RESEND_API_KEY && env.EMAIL_FROM) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'User-Agent': 'p2p-file-transfer-worker',
      },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, text, html }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`Resend 발송 실패 (${res.status}): ${detail.slice(0, 200)}`);
    }
    return;
  }

  // 2) Brevo
  if (env.BREVO_API_KEY && env.EMAIL_FROM) {
    const sender = parseFrom(env.EMAIL_FROM);
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender,
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html,
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`Brevo 발송 실패 (${res.status}): ${detail.slice(0, 200)}`);
    }
    return;
  }

  // 3) Custom Webhook (예: Google Apps Script로 본인 Gmail 무료 발송)
  if (env.EMAIL_WEBHOOK_URL) {
    const headers = { 'Content-Type': 'application/json' };
    if (env.EMAIL_WEBHOOK_SECRET) headers['X-Webhook-Secret'] = env.EMAIL_WEBHOOK_SECRET;
    const res = await fetch(env.EMAIL_WEBHOOK_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        secret: env.EMAIL_WEBHOOK_SECRET || undefined, // Apps Script는 커스텀 헤더 읽기가 제한돼 body로도 전달
        to,
        subject,
        text,
        html,
        code,
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`메일 Webhook 발송 실패 (${res.status}): ${detail.slice(0, 200)}`);
    }
    return;
  }

  throw new Error('이메일 발송 설정이 비어 있습니다.');
}
