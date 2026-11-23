// 웹 관리자 화면 내장 AI 관리 비서 (외부 패키지 0개)
// - 기본: Cloudflare Workers AI (@cf/meta/llama-3.3-70b-instruct-fp8-fast, 무료 플랜 일 10,000 뉴런)
// - 선택 연동: AI_API_KEY (+ AI_API_BASE, AI_MODEL) 설정 시 OpenAI / Gemini / Groq / OpenRouter 등 외부 AI API 사용
import { ADMIN_TOOLS, executeAdminTool } from './mcp.js';

const DEFAULT_WORKERS_AI_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
const DEFAULT_OPENAI_BASE = 'https://api.openai.com/v1';
const DEFAULT_OPENAI_MODEL = 'gpt-4o-mini';
const MAX_TOOL_ROUNDS = 4;

const SYSTEM_PROMPT = `당신은 프라이빗 WebRTC P2P 파일 전송 서비스의 AI 관리자 비서입니다.
관리자의 요청을 이해하고, 제공된 관리 도구를 호출해 작업을 처리한 뒤 결과를 간결하고 친절한 한국어로 보고하세요.

규칙:
- 상태 조회, 임시 코드 발급/목록/파기, 회원 목록/인증/삭제, 잠금 해제, 방 생성이 필요할 때는 추측하지 말고 반드시 해당 도구를 호출하세요.
- 임시 특별 코드를 발급했으면 코드(XXXX-XXXX), 바로 입장 링크(loginUrl), 그리고 10분 뒤 자동 파기된다는 점을 함께 안내하세요.
- 방을 만들었으면 방 코드와 공유 링크(shareUrl)를 안내하세요.
- 파일 내용은 브라우저 간 P2P 암호화 직통 전송이므로 서버와 AI가 볼 수 없음을 필요시 안내하세요.`;

export function aiProviderInfo(env) {
  if (env.AI_API_KEY?.trim()) {
    const base = (env.AI_API_BASE || DEFAULT_OPENAI_BASE).trim().replace(/\/+$/, '');
    const model = (env.AI_MODEL || DEFAULT_OPENAI_MODEL).trim();
    return { enabled: true, provider: 'external', label: `외부 AI (${model})`, model, base };
  }
  if (env.AI) {
    const model = (env.WORKERS_AI_MODEL || DEFAULT_WORKERS_AI_MODEL).trim();
    return { enabled: true, provider: 'workers-ai', label: 'Cloudflare Workers AI (무료)', model };
  }
  return { enabled: false, provider: null, label: '미연결', model: null };
}

function openAiTools() {
  return ADMIN_TOOLS.map((t) => ({
    type: 'function',
    function: {
      name: t.name,
      description: t.description,
      parameters: t.inputSchema,
    },
  }));
}

function workersAiTools() {
  return ADMIN_TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: t.inputSchema,
  }));
}

function parseArgs(raw) {
  if (!raw) return {};
  if (typeof raw === 'object') return raw;
  try { return JSON.parse(String(raw)); } catch { return {}; }
}

async function callExternalApi(info, env, messages) {
  const res = await fetch(`${info.base}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.AI_API_KEY.trim()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: info.model,
      messages,
      tools: openAiTools(),
      tool_choice: 'auto',
      temperature: 0.2,
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`외부 AI API 오류 (${res.status}): ${detail.slice(0, 200)}`);
  }

  const data = await res.json();
  const msg = data.choices?.[0]?.message || {};
  const toolCalls = Array.isArray(msg.tool_calls)
    ? msg.tool_calls.map((tc, i) => ({
        id: tc.id || `call_${i}`,
        name: tc.function?.name || tc.name,
        args: parseArgs(tc.function?.arguments ?? tc.arguments),
      }))
    : [];

  return {
    content: typeof msg.content === 'string' ? msg.content : '',
    toolCalls,
    rawAssistantMessage: msg,
  };
}

async function callWorkersAi(info, env, messages) {
  const res = await env.AI.run(info.model, {
    messages,
    tools: workersAiTools(),
  });

  // Workers AI 모델별 응답 포맷 정규화 (native tool_calls 또는 OpenAI choices 호환)
  const choiceMsg = res?.choices?.[0]?.message;
  const rawCalls = Array.isArray(res?.tool_calls)
    ? res.tool_calls
    : Array.isArray(choiceMsg?.tool_calls)
      ? choiceMsg.tool_calls
      : [];

  const toolCalls = rawCalls
    .filter((tc) => tc && (tc.name || tc.function?.name))
    .map((tc, i) => ({
      id: tc.id || `call_${i}`,
      name: tc.function?.name || tc.name,
      args: parseArgs(tc.function?.arguments ?? tc.arguments),
    }));

  const content =
    typeof res?.response === 'string'
      ? res.response
      : typeof choiceMsg?.content === 'string'
        ? choiceMsg.content
        : '';

  return { content, toolCalls };
}

export async function runAdminAiChat(env, { message, history = [] }, actions) {
  const info = aiProviderInfo(env);
  if (!info.enabled) {
    throw new Error('연결된 AI 엔진이 없습니다.');
  }

  const safeHistory = Array.isArray(history)
    ? history
        .slice(-8)
        .filter((h) => h && (h.role === 'user' || h.role === 'assistant') && typeof h.content === 'string')
        .map((h) => ({ role: h.role, content: h.content.slice(0, 1000) }))
    : [];

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...safeHistory,
    { role: 'user', content: message },
  ];

  const executed = [];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const turn =
      info.provider === 'external'
        ? await callExternalApi(info, env, messages)
        : await callWorkersAi(info, env, messages);

    if (!turn.toolCalls.length) {
      return {
        reply: turn.content.trim() || summarizeFallback(executed),
        provider: info.provider,
        label: info.label,
        model: info.model,
        executed,
      };
    }

    // assistant의 tool_calls 메시지를 대화 이력에 기록
    messages.push({
      role: 'assistant',
      content: turn.content || '',
      tool_calls: turn.toolCalls.map((tc) => ({
        id: tc.id,
        type: 'function',
        function: { name: tc.name, arguments: JSON.stringify(tc.args) },
      })),
    });

    for (const tc of turn.toolCalls) {
      let result;
      try {
        result = await executeAdminTool(tc.name, tc.args, actions);
      } catch (err) {
        result = { ok: false, error: err?.message || '도구 실행 오류' };
      }

      executed.push({
        tool: tc.name,
        args: tc.args,
        ok: result.ok,
        result: result.ok ? result.data : { error: result.error },
      });

      messages.push({
        role: 'tool',
        tool_call_id: tc.id,
        name: tc.name,
        content: JSON.stringify(result.ok ? result.data : { error: result.error }),
      });
    }
  }

  return {
    reply: summarizeFallback(executed),
    provider: info.provider,
    label: info.label,
    model: info.model,
    executed,
  };
}

function summarizeFallback(executed) {
  if (!executed.length) return '요청을 처리했습니다.';
  return executed
    .map((e) => (e.ok ? `✓ ${e.tool}: ${JSON.stringify(e.result)}` : `✕ ${e.tool}: ${e.result.error}`))
    .join('\n');
}
