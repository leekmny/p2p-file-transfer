// 방별 시그널링 Durable Object (WebSocket Hibernation API 사용)
// - 각 방 코드(6자리)마다 독립 인스턴스로 동작하며, 유휴 시 자동 절전(hibernation)
import { DurableObject } from 'cloudflare:workers';

const ROOM_TTL_MS = 60 * 60_000;      // 빈 방 유지 시간 (1시간)
const MAX_MESSAGE_BYTES = 64 * 1024;  // 시그널 메시지 최대 크기

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
    server.serializeAttachment({ tokens: 100, lastRefill: Date.now() });

    const peers = sockets.length + 1;
    server.send(JSON.stringify({ type: 'joined', room: code, peers }));
    for (const peer of sockets) {
      this.safeSend(peer, { type: 'peer-joined', rejoin });
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== 'string') return;
    if (raw.length > MAX_MESSAGE_BYTES) {
      ws.close(1009, 'message too large');
      return;
    }

    const state = ws.deserializeAttachment() || { tokens: 100, lastRefill: Date.now() };
    const now = Date.now();
    state.tokens = Math.min(100, state.tokens + ((now - state.lastRefill) / 1000) * 20);
    state.lastRefill = now;
    if (state.tokens < 1) {
      ws.close(1008, 'rate limit');
      return;
    }
    state.tokens -= 1;
    ws.serializeAttachment(state);

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === 'signal' && msg.data && typeof msg.data === 'object') {
      for (const peer of this.ctx.getWebSockets()) {
        if (peer !== ws) this.safeSend(peer, { type: 'signal', data: msg.data });
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
