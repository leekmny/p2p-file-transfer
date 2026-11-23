// AI 관리용 공용 도구 정의 + 원격 MCP 서버 (Streamable HTTP · JSON-RPC 2.0, 외부 의존성 없음)
// - 원격 MCP 엔드포인트(POST /mcp)와 웹 내장 AI 관리 비서(POST /api/admin/ai/chat)가 동일한 10개 도구를 공유

const PROTOCOL_VERSION = '2025-03-26';

export const ADMIN_TOOLS = [
  {
    name: 'get_status',
    description: '현재 P2P 파일 전송 서비스의 인증 설정과 회원/임시 코드/잠금 통계를 조회합니다.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'create_guest_pass',
    description: '모든 인증 없이 바로 입장할 수 있는 랜덤 임시 특별 코드를 발급합니다. (10분 후 자동 파기)',
    inputSchema: {
      type: 'object',
      properties: {
        singleUse: {
          type: 'boolean',
          description: 'true면 1회 사용 즉시 파기, false(기본)면 10분 동안 유효',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'list_guest_passes',
    description: '현재 만료되지 않은 임시 특별 코드 목록을 조회합니다.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'revoke_guest_pass',
    description: '지정한 ID의 임시 특별 코드를 즉시 파기합니다.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'list_guest_passes에서 확인한 코드 ID (16자리 hex)' },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    name: 'revoke_all_guest_passes',
    description: '현재 활성화된 모든 임시 특별 코드를 한 번에 즉시 파기합니다.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_users',
    description: '가입된 이메일 회원 목록과 인증 상태를 조회합니다. (비밀번호 해시는 절대 반환하지 않음)',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'verify_user',
    description: '미인증 상태의 이메일 회원을 관리자 권한으로 즉시 인증 완료 처리합니다.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: '인증할 회원 이메일 주소' },
      },
      required: ['email'],
      additionalProperties: false,
    },
  },
  {
    name: 'delete_user',
    description: '지정한 이메일 회원을 삭제합니다.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: '삭제할 회원 이메일 주소' },
      },
      required: ['email'],
      additionalProperties: false,
    },
  },
  {
    name: 'clear_rate_limits',
    description: '비밀번호/코드 오입력으로 잠긴 IP 속도 제한을 모두 초기화합니다.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'create_room',
    description: '파일 전송용 6자리 방 코드와 공유 링크를 미리 생성합니다.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

export async function executeAdminTool(name, args, actions) {
  const safeArgs = args && typeof args === 'object' ? args : {};
  switch (name) {
    case 'get_status':
      return { ok: true, data: await actions.getStatus() };

    case 'create_guest_pass': {
      const pass = await actions.createGuestPass(!!safeArgs.singleUse);
      return {
        ok: true,
        data: {
          ...pass,
          loginUrl: `${actions.origin}/login.html?pass=${encodeURIComponent(pass.code)}`,
          note: '10분 후 자동으로 파기됩니다.',
        },
      };
    }

    case 'list_guest_passes':
      return { ok: true, data: { passes: await actions.listGuestPasses() } };

    case 'revoke_guest_pass': {
      const id = String(safeArgs.id || '').trim();
      if (!/^[a-f0-9]{16}$/.test(id)) return { ok: false, error: '유효한 16자리 hex 코드 ID가 필요합니다.' };
      await actions.revokeGuestPass(id);
      return { ok: true, data: { revoked: true, id } };
    }

    case 'revoke_all_guest_passes': {
      const count = await actions.revokeAllGuestPasses();
      return { ok: true, data: { revokedCount: count } };
    }

    case 'list_users':
      return { ok: true, data: { users: await actions.listUsers() } };

    case 'verify_user': {
      const email = String(safeArgs.email || '').trim().toLowerCase();
      if (!email) return { ok: false, error: '이메일 주소가 필요합니다.' };
      const ok = await actions.verifyUser(email);
      if (!ok) return { ok: false, error: `회원을 찾을 수 없습니다: ${email}` };
      return { ok: true, data: { verified: true, email } };
    }

    case 'delete_user': {
      const email = String(safeArgs.email || '').trim().toLowerCase();
      if (!email) return { ok: false, error: '이메일 주소가 필요합니다.' };
      const ok = await actions.deleteUser(email);
      if (!ok) return { ok: false, error: `회원을 찾을 수 없습니다: ${email}` };
      return { ok: true, data: { deleted: true, email } };
    }

    case 'clear_rate_limits':
      await actions.clearRateLimits();
      return { ok: true, data: { cleared: true } };

    case 'create_room': {
      const room = await actions.createRoom();
      return { ok: true, data: { room, shareUrl: `${actions.origin}/?room=${room}` } };
    }

    default:
      return { ok: false, error: `알 수 없는 도구입니다: ${name}` };
  }
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export async function handleMcpRequest(body, actions) {
  if (!body || typeof body !== 'object' || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return { status: 400, payload: rpcError(null, -32600, 'Invalid JSON-RPC 2.0 request') };
  }

  const { id, method, params } = body;
  if (id === undefined) return { status: 202, payload: null };

  switch (method) {
    case 'initialize':
      return {
        status: 200,
        payload: rpcResult(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'p2p-file-transfer-admin', version: '2.1.0' },
        }),
      };

    case 'ping':
      return { status: 200, payload: rpcResult(id, {}) };

    case 'tools/list':
      return { status: 200, payload: rpcResult(id, { tools: ADMIN_TOOLS }) };

    case 'tools/call': {
      const name = params?.name;
      const args = params?.arguments && typeof params.arguments === 'object' ? params.arguments : {};
      try {
        const res = await executeAdminTool(name, args, actions);
        if (!res.ok) {
          return {
            status: 200,
            payload: rpcResult(id, { isError: true, content: [{ type: 'text', text: res.error }] }),
          };
        }
        return {
          status: 200,
          payload: rpcResult(id, {
            content: [{ type: 'text', text: JSON.stringify(res.data, null, 2) }],
            structuredContent: res.data,
          }),
        };
      } catch (err) {
        return {
          status: 200,
          payload: rpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: err?.message || '도구 실행 중 오류 발생' }],
          }),
        };
      }
    }

    default:
      return { status: 200, payload: rpcError(id, -32601, `Method not found: ${method}`) };
  }
}
