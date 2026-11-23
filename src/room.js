// 방별 시그널링 + E2EE 서버 중계 Durable Object (WebSocket Hibernation API 사용)
// - 각 방 코드(6자리)마다 독립 인스턴스로 동작하며, 유휴 시 자동 절전(hibernation)
// - JSON 제어/암호화 메시지(e2ee, relay, signal, reconnect)와 바이너리 암호화 청크(최대 768KB)를
//   디스크에 저장하지 않고 메모리에서 상대방 WebSocket으로 즉시 스트리밍 중계
import { DurableObject } from 'cloudflare:workers';

const ROOM_TTL_MS = 60 * 60_000;       // 빈 방 유지 시간 (1시간)
const MAX_TEXT_BYTES = 64 * 1024;      // 텍스트 메시지 최대 크기 (64KB)
const MAX_BINARY_BYTES = 768 * 1024;   // 바이너리 청크 최대 크기 (768KB < DO 1MiB 제한)
const RELAY_TYPES = new Set(['signal', 'e2ee', 'relay']);

export class SignalingRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // 'ping'이 오면 DO를 깨우지 않고 런타임이 바로 'pong' 응답
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async createRoom() {
    const sockets = this.ctx.getWebSockets();
    const createdAt = await this.ctx.storage.get('createdAt');
    if (sockets.length > 0 || (createdAt && Date.now() - createdAt < ROOM_TTL_MS)) {
      return false;
    }
    await this.ctx.storage.put('createdAt', Date.now());
    await this.ctx.storage.setAlarm(Date.now() + ROOM_TTL_MS);
    return true;
  }

  async roomStatus() {
    const sockets = this.ctx.getWebSockets();
    const createdAt = await this.ctx.storage.get('createdAt');
    const exists = sockets.length > 0 || (!!createdAt && Date.now() - createdAt < ROOM_TTL_MS);
    return { exists, peers: sockets.length };
  }

  async fetch(request) {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const url = new URL(request.url);
    const code = (url.searchParams.get('room') || '').toUpperCase();
    const rejoin = url.searchParams.get('rejoin') === '1';

    const sockets = this.ctx.getWebSockets();
    const createdAt = await this.ctx.storage.get('createdAt');
    const exists = sockets.length > 0 || (!!createdAt && Date.now() - createdAt < ROOM_TTL_MS);

    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);

    if (!exists && !rejoin) {
      server.send(JSON.stringify({ type: 'error', message: '존재하지 않는 방 코드입니다.' }));
      server.close(4404, 'room not found');
      return new Response(null, { status: 101, webSocket: client });
    }

    if (sockets.length >= 2) {
      server.send(JSON.stringify({ type: 'error', message: '이미 두 명이 접속한 방입니다.' }));
      server.close(4409, 'room full');
      return new Response(null, { status: 101, webSocket: client });
    }

    if (!createdAt) await this.ctx.storage.put('createdAt', Date.now());
    server.serializeAttachment({ tokens: 200, lastRefill: Date.now() });

    const peers = sockets.length + 1;
    server.send(JSON.stringify({ type: 'joined', room: code, peers }));
    for (const peer of sockets) {
      this.safeSend(peer, { type: 'peer-joined', rejoin });
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  consumeToken(ws) {
    // 초당 80개, 버스트 200개 (256KB 청크 기준 최대 ~20MB/s 중계 허용, 스팸 차단)
    const state = ws.deserializeAttachment() || { tokens: 200, lastRefill: Date.now() };
    const now = Date.now();
    state.tokens = Math.min(200, state.tokens + ((now - state.lastRefill) / 1000) * 80);
    state.lastRefill = now;
    if (state.tokens < 1) {
      ws.close(1008, 'rate limit');
      return false;
    }
    state.tokens -= 1;
    ws.serializeAttachment(state);
    return true;
  }

  async webSocketMessage(ws, raw) {
    // 1) 바이너리 프레임: E2EE 암호화된 파일 청크를 저장 없이 상대에게 즉시 전달
    if (raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) {
      const byteLength = raw.byteLength;
      if (byteLength > MAX_BINARY_BYTES) {
        ws.close(1009, 'chunk too large');
        return;
      }
      if (!this.consumeToken(ws)) return;
      for (const peer of this.ctx.getWebSockets()) {
        if (peer !== ws) {
          try { peer.send(raw); } catch { /* 닫힌 소켓 무시 */ }
        }
      }
      return;
    }

    // 2) 텍스트 프레임: JSON 제어/암호화/시그널링 메시지
    if (typeof raw !== 'string') return;
    if (raw.length > MAX_TEXT_BYTES) {
      ws.close(1009, 'message too large');
      return;
    }
    if (!this.consumeToken(ws)) return;

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object') return;

    if (RELAY_TYPES.has(msg.type) && msg.data && typeof msg.data === 'object') {
      for (const peer of this.ctx.getWebSockets()) {
        if (peer !== ws) this.safeSend(peer, { type: msg.type, data: msg.data });
      }
    } else if (msg.type === 'reconnect') {
      for (const peer of this.ctx.getWebSockets()) {
        if (peer !== ws) this.safeSend(peer, { type: 'peer-joined', rejoin: false });
      }
    } else if (msg.type === 'leave') {
      this.notifyPeerLeft(ws);
      ws.close(1000, 'left');
    }
  }

  async webSocketClose(ws) {
    this.notifyPeerLeft(ws);
    if (this.ctx.getWebSockets().filter((s) => s !== ws).length === 0) {
      await this.ctx.storage.setAlarm(Date.now() + 5 * 60_000);
    }
  }

  async webSocketError(ws) {
    this.notifyPeerLeft(ws);
    try { ws.close(1011, 'error'); } catch { /* 이미 닫힘 */ }
  }

  async alarm() {
    if (this.ctx.getWebSockets().length === 0) {
      await this.ctx.storage.delete('createdAt');
    }
  }

  notifyPeerLeft(leaving) {
    for (const peer of this.ctx.getWebSockets()) {
      if (peer !== leaving) this.safeSend(peer, { type: 'peer-left' });
    }
  }

  safeSend(ws, obj) {
    try { ws.send(JSON.stringify(obj)); } catch { /* 이미 닫힌 소켓 무시 */ }
  }
}
