// 방별 시그널링 Durable Object (WebSocket Hibernation API 사용)
// - 각 방 코드(6자리)마다 독립 인스턴스로 동작하며, 유휴 시 자동 절전(hibernation)되어 무료 한도를 거의 쓰지 않음
// - 로그인 실패 횟수 제한(IP별)도 같은 SQLite 스토리지 기반으로 안전하게 유지
import { DurableObject } from 'cloudflare:workers';

const ROOM_TTL_MS = 60 * 60_000;      // 빈 방 유지 시간 (1시간)
const MAX_MESSAGE_BYTES = 64 * 1024;  // 시그널 메시지 최대 크기
const LOGIN_MAX_FAILS = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;

export class SignalingRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // 'ping'이 오면 DO를 깨우지 않고 런타임이 바로 'pong' 응답
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  // ---------------------------------------------------------------- 방 관리 RPC
  async createRoom() {
    const sockets = this.ctx.getWebSockets();
    const createdAt = await this.ctx.storage.get('createdAt');
    if (sockets.length > 0 || (createdAt && Date.now() - createdAt < ROOM_TTL_MS)) {
      return false; // 이미 사용 중인 코드
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

  // ---------------------------------------------------------------- 로그인 속도 제한 RPC
  async checkLoginAllowed() {
    const rec = await this.ctx.storage.get('rl');
    if (!rec) return true;
    if (Date.now() - rec.first >= LOGIN_WINDOW_MS) {
      await this.ctx.storage.delete('rl');
      return true;
    }
    return rec.count < LOGIN_MAX_FAILS;
  }

  async recordLoginFailure() {
    let rec = await this.ctx.storage.get('rl');
    const now = Date.now();
    if (!rec || now - rec.first >= LOGIN_WINDOW_MS) rec = { count: 0, first: now };
    rec.count += 1;
    await this.ctx.storage.put('rl', rec);
    await this.ctx.storage.setAlarm(rec.first + LOGIN_WINDOW_MS);
  }

  async clearLoginFailure() {
    await this.ctx.storage.delete('rl');
  }

  // ---------------------------------------------------------------- WebSocket 업그레이드
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

  // ---------------------------------------------------------------- Hibernation 이벤트
  async webSocketMessage(ws, raw) {
    if (typeof raw !== 'string') return;
    if (raw.length > MAX_MESSAGE_BYTES) {
      ws.close(1009, 'message too large');
      return;
    }

    // 토큰 버킷 속도 제한 (초당 20개, 최대 100개 버스트)
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
    const rec = await this.ctx.storage.get('rl');
    if (rec && Date.now() - rec.first >= LOGIN_WINDOW_MS) {
      await this.ctx.storage.delete('rl');
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
