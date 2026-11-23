# 📡 P2P File Transfer (Cloudflare Workers + Durable Objects)

친구·가족 등 초대받은 사람끼리 **브라우저에서 직접(WebRTC DataChannel)** 파일을 주고받는 프라이빗 P2P 파일 전송 웹앱입니다.

- **내 PC를 꺼도 24시간 동작** (Cloudflare Workers 무료 플랜)
- **도메인 없이 완전 무료** (`*.workers.dev` + SQLite Durable Objects)
- **파일은 서버를 절대 거치지 않음** — Cloudflare에는 웹페이지·인증·시그널링만 통과하고, 실제 파일은 브라우저끼리 DTLS 암호화 직통 전송
- **GitHub에 그대로 공개 가능** — 비밀값·API 키가 코드에 전혀 없고 Cloudflare Secret으로만 주입

---

## 주요 기능

- **직접 P2P 전송 (WebRTC DataChannel)**: 64KB 청크 + `bufferedAmountLowThreshold` 백프레셔 + Chrome/Edge **`showSaveFilePicker` 디스크 직접 스트리밍** + 수신 전 수락/거절
- **6자리 보안 확인 코드 (SAS)**: 양쪽 DTLS 인증서 지문으로 계산한 코드로 시그널링 구간 MITM 탐지
- **이메일 회원가입 + 6자리 이메일 인증**:
  - Durable Object SQLite(`AccountStore`)에 PBKDF2-SHA256(100,000회) 해시 저장
  - 외부 가입 차단용 **초대 코드(`INVITE_CODE`)** / **허용 이메일(`ALLOWED_EMAILS`)** 지원
  - **Resend**, **Brevo**, 또는 **Custom Webhook(도메인 없이 본인 Gmail + Google Apps Script 5줄로 무료 발송)** 지원
- **관리자 10분 임시 특별 코드**:
  - 관리자가 랜덤 8자리 코드(`XXXX-XXXX`)를 발급하면 **10분 후 자동 파기** (1회용 옵션 및 수동 즉시 파기 지원)
  - 친구가 코드 또는 바로 입장 링크를 입력하면 **회원가입·이메일 인증 없이 바로 사용 가능**
- **AI 관리 연동 (원격 MCP 서버 `/mcp` + Admin REST API)**:
  - `ADMIN_API_KEY`를 설정하면 Claude / Cursor / Antigravity 등 MCP 지원 AI가 자연어로 **임시 코드 발급·파기, 회원 조회·수동 인증·삭제, 잠금 해제, 방 생성, 상태 점검**을 직접 수행 가능

---

## 1. 로컬 실행 & 테스트

```bash
git clone <이-저장소-URL>
cd p2p-file-transfer
npm install
Copy-Item .dev.vars.example .dev.vars   # macOS/Linux: cp .dev.vars.example .dev.vars
# .dev.vars에 APP_PASSWORD(8자 이상) 입력
npm run dev   # http://127.0.0.1:8787
npm test      # 실제 wrangler dev + Durable Objects 전체 통합 테스트
```

---

## 2. Cloudflare 배포 (무료)

```bash
npx wrangler login
npm run deploy
```

배포 후 아래 중 원하는 인증/관리 기능을 Secret으로 등록합니다 (코드는 수정 불필요).

### A. 기본 비밀번호 로그인 (가장 빠름)
```bash
npx wrangler secret put APP_PASSWORD
```

### B. 이메일 회원가입 + 6자리 이메일 인증 켜기
1. 초대 코드 & 관리자 이메일 등록:
   ```bash
   npx wrangler secret put INVITE_CODE      # 친구에게 알려줄 가입 초대 코드
   npx wrangler secret put ADMIN_EMAILS     # 관리자 이메일 (쉼표 구분, 예: me@gmail.com)
   # (선택) 특정 이메일만 가입 허용하려면:
   npx wrangler secret put ALLOWED_EMAILS   # 예: me@gmail.com,friend@gmail.com
   ```
2. 메일 발송기 연결 (셋 중 하나 선택):
   - **도메인 없이 본인 Gmail로 무료 발송 (Google Apps Script Webhook)**:
     1. [script.google.com](https://script.google.com) → 새 프로젝트 → 아래 코드 붙여넣기:
        ```javascript
        function doPost(e) {
          const data = JSON.parse(e.postData.contents);
          if (data.secret !== '여기에_내가_정한_웹훅비밀키') {
            return ContentService.createTextOutput('forbidden');
          }
          MailApp.sendEmail({
            to: data.to,
            subject: data.subject,
            body: data.text,
            htmlBody: data.html,
          });
          return ContentService.createTextOutput(JSON.stringify({ ok: true }))
            .setMimeType(ContentService.MimeType.JSON);
        }
        ```
     2. **배포 → 새 배포 → 웹 앱** (`실행 주체: 나`, `액세스 권한: 모든 사용자`) → 발급된 URL 복사
     3. Secret 등록:
        ```bash
        npx wrangler secret put EMAIL_WEBHOOK_URL
        npx wrangler secret put EMAIL_WEBHOOK_SECRET
        ```
   - **Resend 사용 시** (월 3,000통 무료, 본인 도메인 권장):
     ```bash
     npx wrangler secret put RESEND_API_KEY
     npx wrangler secret put EMAIL_FROM    # 예: P2P Drop <no-reply@yourdomain.com>
     ```
   - **Brevo 사용 시** (일 300통 무료):
     ```bash
     npx wrangler secret put BREVO_API_KEY
     npx wrangler secret put EMAIL_FROM
     ```

### C. 관리자 10분 임시 특별 코드 사용법
- 관리자 계정(`ADMIN_EMAILS` 또는 `APP_PASSWORD` 로그인)으로 들어가면 상단에 **`🔑 임시 코드`** 버튼이 표시됩니다.
- **새 10분 코드 발급**을 누르면 랜덤 8자리 코드(`XXXX-XXXX`)와 바로 입장 링크가 생성되며, **10분 뒤 자동 파기**됩니다.
- 친구가 로그인 화면의 **특별 코드** 탭에 입력하거나 링크를 클릭하면 별도 인증 없이 바로 파일 전송 화면으로 들어옵니다.

---

## 3. AI 관리 연동 (웹 내장 AI 비서 + 원격 MCP 서버)

### A. 웹 관리자 화면 내장 AI 비서 (`🤖 AI 관리`, 기본 무료 활성화)
- 관리자로 로그인하면 상단에 **`🤖 AI 관리`** 버튼이 나타납니다.
- **기본으로 Cloudflare Workers AI(`@cf/meta/llama-3.3-70b-instruct-fp8-fast`, 무료 플랜 일 10,000 뉴런)**에 연결되어 있어, **별도 API 키 없이 바로** 브라우저에서 자연어로 관리할 수 있습니다.
- OpenAI나 Gemini API를 연동하고 싶다면 Secret만 추가하면 자동으로 전환됩니다:
  ```bash
  npx wrangler secret put AI_API_KEY
  # (선택) 기본은 OpenAI gpt-4o-mini. Gemini 사용 시:
  npx wrangler secret put AI_API_BASE   # https://generativelanguage.googleapis.com/v1beta/openai
  npx wrangler secret put AI_MODEL      # gemini-2.5-flash
  ```

### B. 외부 AI 에이전트용 원격 MCP 서버 (`POST /mcp`)
`ADMIN_API_KEY`(16자 이상, 권장 32자 랜덤 문자열)를 등록하면 **`POST /mcp`** 원격 MCP 서버와 **`/api/admin/*`** REST API가 활성화됩니다.

```bash
npx wrangler secret put ADMIN_API_KEY
```

MCP 클라이언트(Claude Desktop / Cursor / Antigravity / T3 Code 등) 설정 예시:

```json
{
  "mcpServers": {
    "p2p-file-transfer": {
      "url": "https://<내-워커-주소>.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer <ADMIN_API_KEY>"
      }
    }
  }
}
```

### AI가 사용할 수 있는 관리 도구 (10종)
| 도구 | 설명 |
|---|---|
| `get_status` | 인증 설정 상태 및 회원·임시 코드·잠금 통계 조회 |
| `create_guest_pass` | 인증 없이 입장하는 10분 임시 특별 코드 발급 (`singleUse` 선택 가능) |
| `list_guest_passes` | 현재 활성 임시 코드 목록과 남은 시간 조회 |
| `revoke_guest_pass` | 특정 임시 코드 즉시 파기 |
| `revoke_all_guest_passes` | 활성 임시 코드 전체 즉시 파기 |
| `list_users` | 가입 회원 목록 및 인증 여부 조회 (비밀번호 해시 비노출) |
| `verify_user` | 미인증 회원 수동 즉시 인증 |
| `delete_user` | 회원 삭제 |
| `clear_rate_limits` | 오입력 잠금(429) 일괄 해제 |
| `create_room` | 6자리 전송 방 코드 및 공유 링크 미리 생성 |

> AI 관리 권한은 회원·임시 코드·방 생성만 관리하며, 브라우저 간 P2P로 전송되는 파일 내용은 절대 볼 수 없습니다.

---

## 4. (선택) 방화벽/LTE 환경용 무료 TURN 서버

집/와이파이 외 회사 방화벽·LTE 조합에서 P2P 직접 연결이 막힐 때 **Cloudflare Realtime TURN (월 1TB 무료)**을 붙일 수 있습니다.

```bash
npx wrangler secret put CF_TURN_TOKEN_ID
npx wrangler secret put CF_TURN_API_TOKEN
```

---

## 라이선스

[MIT](./LICENSE)
