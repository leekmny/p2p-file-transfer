// 암호화 파일 전송 & 채팅 클라이언트 (Cloudflare E2EE 서버 중계 기본 + 선택 WebRTC P2P 직통 전환)
//  1) 방에 두 사람이 들어오면 Cloudflare WebSocket(443)을 통해 즉시 ECDH(P-256) 키 교환 → AES-256-GCM 종단간 암호화 연결
//     → 방화벽·대칭형 NAT·모바일 LTE/5G 환경에서도 TURN 서버 없이 100% 즉시 연결, 서버도 내용 해독 불가
//  2) 원하면 '⚡ P2P 직통 전환'으로 WebRTC DataChannel 직통 연결 시도 (실패해도 서버 중계 연결 유지!)
//     - WebRTC 개선: 조기 ICE Candidate 큐잉, 오래된 PC 참조 차단, ICE 서버 주기적 갱신, 자동 ICE Restart, 경로 진단
//  3) 파일 전송: offer-file → accept/decline → 암호화 청크(서버 중계 256KB 슬라이딩 윈도우 / P2P 64KB 백프레셔) → end → ack
//  4) 채팅: 종단간 암호화 실시간 대화 (입력 중 표시, 백그라운드 탭 알림, 서버 미저장)

const $ = (s) => document.querySelector(s);

const P2P_CHUNK_SIZE = 64 * 1024;
const P2P_HIGH_WATER = 4 * 1024 * 1024;
const P2P_LOW_WATER = 512 * 1024;

const RELAY_CHUNK_SIZE = 256 * 1024;   // 256KB 청크 (DO 1MiB 제한 대비 여유, 100MB당 약 400요청)
const RELAY_WINDOW_CHUNKS = 8;         // 수신 확인 없이 최대 8청크(2MB) 전송 후 ack 대기 (흐름 제어)
const RELAY_ACK_EVERY = 4;             // 4청크마다 수신 확인 전송
const BLOB_WARN_SIZE = 1024 ** 3;
const canStreamToDisk = typeof window.showSaveFilePicker === 'function';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// 시그널링 & 중계 WebSocket
let ws = null;
let pingTimer = null;
let reconnectTimer = null;
let roomCode = null;
let authMode = 'cookie';
let isAdmin = false;
let myName = '';
let peerName = '상대방';
let unreadChat = 0;
let typingHideTimer = null;
let lastTypingSent = 0;

// E2EE 서버 중계 상태 (ECDH P-256 + AES-256-GCM)
let myKeyPair = null;
let myPubRaw = null;
let myPubJwk = null;
let e2eeChain = Promise.resolve();
let relayKey = null;
let relaySas = '--- ---';
let relayReady = false;
let relayDecryptChain = Promise.resolve();
let peerPresent = false;

// 선택적 WebRTC P2P 직통 상태
let pc = null;
let channel = null;
let chatChannel = null;
let iceServers = [];
let hasTurn = false;
let turnError = null;
let iceFetchedAt = 0;
let signalChain = Promise.resolve();
let pendingCandidates = [];
let iceRestarted = false;
let candStats = { local: { host: 0, srflx: 0, relay: 0 }, remote: { host: 0, srflx: 0, relay: 0 } };

// 관리자 UI 상태
let issuedPassExpiresAt = 0;
let passCountdownTimer = null;
let activePasses = [];
const aiHistory = [];
let aiBusy = false;

// 파일 전송 상태
const sendQueue = [];
let sending = false;
const waiters = new Map();             // id -> { resolve, reject }
const replies = new Map();             // id -> msg
const chunkAckWaiters = new Map();     // id -> { targetSeq, resolve, reject }
const chunkAckHighest = new Map();     // id -> highest acked seq
let pendingOffer = null;
let incoming = null;

// ================================================================ 초기화
init();

async function init() {
  if (!(await checkSession())) return;
  refreshIceConfig(true).catch(() => {});
  bindUI();

  const codeFromUrl = new URLSearchParams(location.search).get('room');
  if (codeFromUrl) joinRoom(codeFromUrl.trim().toUpperCase());
}

async function refreshIceConfig(force = false) {
  // TURN 임시 자격 증명(1시간 만료)을 신선하게 유지하기 위해 20분마다 갱신
  if (!force && iceServers.length && Date.now() - iceFetchedAt < 20 * 60_000) return;
  try {
    const res = await fetch('/config', { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      iceServers = Array.isArray(data.iceServers) ? data.iceServers : [];
      hasTurn = !!data.hasTurn;
      turnError = data.turnError || null;
      iceFetchedAt = Date.now();
    }
  } catch { /* 기본값 유지 */ }
}

async function checkSession() {
  try {
    const res = await fetch('/api/session', { cache: 'no-store' });
    if (res.status === 401) {
      const data = await res.json().catch(() => ({}));
      if (!data.needAccess) goLogin();
      return false;
    }
    if (res.ok) {
      const data = await res.json();
      authMode = data.mode || 'cookie';
      isAdmin = !!data.isAdmin;
      const badge = $('#userBadge');
      if (data.email) {
        myName = data.email.split('@')[0].slice(0, 30);
        badge.textContent = data.email;
        badge.hidden = false;
      } else if (data.isGuest) {
        myName = '게스트';
        badge.textContent = '임시 게스트';
        badge.hidden = false;
      } else if (isAdmin) {
        myName = '관리자';
      }
      $('#adminPassToggle').hidden = !isAdmin;
      $('#aiToggle').hidden = !isAdmin;
    }
  } catch { /* 네트워크 일시 중단 */ }
  return true;
}

function goLogin() {
  location.href = `/login.html?next=${encodeURIComponent(location.pathname + location.search)}`;
}

function bindUI() {
  $('#createBtn').addEventListener('click', createRoom);

  $('#joinForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const code = $('#codeInput').value.trim().toUpperCase();
    if (code.length !== 6) return showError('방 코드 6자리를 입력하세요.');
    joinRoom(code);
  });

  $('#leaveBtn').addEventListener('click', () => leaveRoom(true));
  $('#copyBtn').addEventListener('click', () => copyText($('#shareLink').value, $('#copyBtn'), '링크 복사'));
  $('#reconnectBtn').addEventListener('click', () => {
    hideDiag();
    if (!roomCode) return;
    if (ws && ws.readyState === WebSocket.OPEN) {
      wsSend({ type: 'reconnect' });
      initE2eeRelay().catch(onPeerError);
    } else {
      connectRoomSocket(roomCode, true);
    }
  });
  $('#p2pBoostBtn').addEventListener('click', () => {
    if (!peerPresent) return;
    if (isP2pConnected()) return;
    hideDiag();
    $('#p2pBoostBtn').disabled = true;
    $('#p2pBoostBtn').textContent = 'P2P 연결 시도 중…';
    startPeer(true).catch((err) => {
      onPeerError(err);
      updateTransportUI();
    });
  });

  $('#logoutBtn').addEventListener('click', async () => {
    if (authMode !== 'access') {
      try { await fetch('/api/logout', { method: 'POST' }); } catch { /* 무시 */ }
    }
    if (authMode === 'access' || authMode === 'both') {
      location.href = '/cdn-cgi/access/logout';
    } else {
      location.href = '/login.html';
    }
  });

  // 관리자 임시 특별 코드 UI
  $('#adminPassToggle').addEventListener('click', () => {
    const panel = $('#adminPanel');
    panel.hidden = !panel.hidden;
    if (!panel.hidden) refreshPasses();
  });
  $('#closeAdminBtn').addEventListener('click', () => { $('#adminPanel').hidden = true; });
  $('#issuePassBtn').addEventListener('click', issueGuestPass);
  $('#copyPassCodeBtn').addEventListener('click', () =>
    copyText($('#issuedCode').textContent, $('#copyPassCodeBtn'), '코드 복사')
  );
  $('#copyPassLinkBtn').addEventListener('click', () =>
    copyText($('#issuedLink').value, $('#copyPassLinkBtn'), '링크 복사')
  );

  // 관리자 AI 비서 UI
  $('#aiToggle').addEventListener('click', () => {
    const panel = $('#aiPanel');
    panel.hidden = !panel.hidden;
    if (!panel.hidden) {
      loadAiInfo();
      $('#aiInput').focus();
    }
  });
  $('#closeAiBtn').addEventListener('click', () => { $('#aiPanel').hidden = true; });
  $('#aiChips').addEventListener('click', (e) => {
    const prompt = e.target.closest('button[data-prompt]')?.dataset.prompt;
    if (prompt) sendAiMessage(prompt);
  });
  $('#aiForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = $('#aiInput').value.trim();
    if (text) sendAiMessage(text);
  });

  // 파일 드래그 & 선택
  const drop = $('#dropZone');
  const input = $('#fileInput');
  input.addEventListener('change', () => {
    enqueueFiles(input.files);
    input.value = '';
  });
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    if (e.dataTransfer?.files?.length) enqueueFiles(e.dataTransfer.files);
  });

  window.addEventListener('beforeunload', (e) => {
    if (sending || incoming || sendQueue.length) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  // 채팅 UI
  const chatInput = $('#chatInput');
  $('#chatForm').addEventListener('submit', (e) => {
    e.preventDefault();
    sendChatMessage();
  });
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      sendChatMessage();
    }
  });
  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = `${Math.min(chatInput.scrollHeight, 110)}px`;
    if (isTransportReady() && Date.now() - lastTypingSent > 1500) {
      lastTypingSent = Date.now();
      sendChatPayload({ type: 'typing' }).catch(() => {});
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && unreadChat > 0) {
      unreadChat = 0;
      document.title = 'P2P 파일 전송';
    }
  });
}

// ================================================================ 관리자 임시 특별 코드
async function issueGuestPass() {
  const errEl = $('#adminError');
  errEl.hidden = true;
  const btn = $('#issuePassBtn');
  btn.disabled = true;
  try {
    const singleUse = $('#passSingleUse').checked;
    const res = await fetch('/api/admin/passes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ singleUse }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      errEl.textContent = data.error || '코드 발급에 실패했습니다.';
      errEl.hidden = false;
      return;
    }
    issuedPassExpiresAt = data.expiresAt;
    $('#issuedCode').textContent = data.code;
    $('#issuedLink').value = `${location.origin}/login.html?pass=${encodeURIComponent(data.code)}`;
    $('#issuedPassBox').hidden = false;
    startPassTicker();
    await refreshPasses();
  } catch {
    errEl.textContent = '서버에 연결할 수 없습니다.';
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function refreshPasses() {
  if (!isAdmin) return;
  try {
    const res = await fetch('/api/admin/passes', { cache: 'no-store' });
    if (!res.ok) return;
    const data = await res.json();
    activePasses = Array.isArray(data.passes) ? data.passes : [];
    renderPassList();
    if (activePasses.length || issuedPassExpiresAt > Date.now()) startPassTicker();
  } catch { /* 무시 */ }
}

async function revokePass(id) {
  try {
    await fetch(`/api/admin/passes/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await refreshPasses();
  } catch { /* 무시 */ }
}

function formatCountdown(ms) {
  const sec = Math.max(0, Math.ceil(ms / 1000));
  return `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
}

function renderPassList() {
  const ul = $('#passList');
  const now = Date.now();
  const valid = activePasses.filter((p) => p.expiresAt > now);
  ul.replaceChildren();
  for (const p of valid) {
    const li = document.createElement('li');
    li.className = 'pass-item';
    const info = document.createElement('span');
    const mode = p.singleUse ? '1회용' : `사용 ${p.uses}회`;
    info.textContent = `${p.hint} · ${mode} · ${formatCountdown(p.expiresAt - now)} 남음`;
    const del = makeButton('즉시 파기', 'small ghost');
    del.addEventListener('click', () => revokePass(p.id));
    li.append(info, del);
    ul.append(li);
  }
}

function startPassTicker() {
  if (passCountdownTimer) return;
  const tick = () => {
    const now = Date.now();
    if (issuedPassExpiresAt) {
      const rem = issuedPassExpiresAt - now;
      const timerEl = $('#issuedTimer');
      if (rem > 0) {
        timerEl.textContent = `${formatCountdown(rem)} 남음`;
        timerEl.className = 'badge ok';
      } else {
        timerEl.textContent = '만료 파기됨';
        timerEl.className = 'badge err';
        issuedPassExpiresAt = 0;
      }
    }
    renderPassList();
    if (!issuedPassExpiresAt && !activePasses.some((p) => p.expiresAt > now)) {
      clearInterval(passCountdownTimer);
      passCountdownTimer = null;
    }
  };
  tick();
  passCountdownTimer = setInterval(tick, 1000);
}

// ================================================================ 관리자 AI 비서
async function loadAiInfo() {
  if (!isAdmin) return;
  try {
    const res = await fetch('/api/admin/ai/info', { cache: 'no-store' });
    if (!res.ok) return;
    const info = await res.json();
    const badge = $('#aiEngineBadge');
    badge.textContent = info.enabled ? info.label : 'AI 미연결';
    badge.className = `badge ${info.enabled ? 'ok' : 'err'}`;
  } catch { /* 무시 */ }
}

async function sendAiMessage(text) {
  if (aiBusy) return;
  aiBusy = true;
  const errEl = $('#aiError');
  const input = $('#aiInput');
  const submitBtn = $('#aiForm button[type="submit"]');
  errEl.hidden = true;
  input.value = '';
  input.disabled = submitBtn.disabled = true;

  appendAiMessage('user', text);
  const pending = appendAiMessage('assistant', '생각 및 작업 실행 중…');

  try {
    const res = await fetch('/api/admin/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, history: aiHistory }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      pending.remove();
      errEl.textContent = data.error || `AI 호출 실패 (${res.status})`;
      errEl.hidden = false;
      return;
    }

    pending.remove();
    appendAiMessage('assistant', data.reply, data.executed || []);
    aiHistory.push({ role: 'user', content: text }, { role: 'assistant', content: data.reply });
    if (aiHistory.length > 10) aiHistory.splice(0, aiHistory.length - 10);

    if ((data.executed || []).some((e) => e.tool.includes('guest_pass'))) {
      refreshPasses();
    }
  } catch {
    pending.remove();
    errEl.textContent = '서버에 연결할 수 없습니다.';
    errEl.hidden = false;
  } finally {
    aiBusy = false;
    input.disabled = submitBtn.disabled = false;
    input.focus();
  }
}

function appendAiMessage(role, text, executed = []) {
  const log = $('#aiLog');
  const box = document.createElement('div');
  box.className = `ai-msg ${role}`;

  if (executed.length) {
    const toolsWrap = document.createElement('div');
    toolsWrap.className = 'ai-tools';
    for (const ex of executed) {
      const chip = document.createElement('div');
      chip.className = `ai-tool ${ex.ok ? 'ok' : 'err'}`;
      const label = document.createElement('span');
      label.textContent = `${ex.ok ? '✓' : '✕'} ${ex.tool}`;
      chip.append(label);

      const copyUrl = ex.result?.loginUrl || ex.result?.shareUrl;
      if (ex.ok && copyUrl) {
        const copyBtn = makeButton(ex.result.code ? `${ex.result.code} 링크 복사` : `${ex.result.room} 링크 복사`, 'small ghost');
        copyBtn.addEventListener('click', () => copyText(copyUrl, copyBtn, copyBtn.textContent));
        chip.append(copyBtn);
      }
      toolsWrap.append(chip);
    }
    box.append(toolsWrap);
  }

  const body = document.createElement('div');
  body.className = 'ai-text';
  body.textContent = text;
  box.append(body);

  log.append(box);
  log.scrollTop = log.scrollHeight;
  return box;
}

// ================================================================ 방 생성 / 참여 / 시그널링 & E2EE 중계
async function createRoom() {
  hideError();
  const btn = $('#createBtn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/rooms', { method: 'POST' });
    if (res.status === 401) return goLogin();
    const data = await res.json();
    if (!res.ok) return showError(data.error || '방을 만들지 못했습니다.');
    enterRoom(data.room);
    setStatus('상대방을 기다리는 중… 링크나 코드를 공유하세요.', 'waiting');
    connectRoomSocket(data.room, false);
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
}

async function joinRoom(code) {
  hideError();
  try {
    const res = await fetch(`/api/rooms/${encodeURIComponent(code)}`, { cache: 'no-store' });
    if (res.status === 401) return goLogin();
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || '방에 참여할 수 없습니다.');
      if (!roomCode) history.replaceState(null, '', location.pathname);
      return;
    }
    enterRoom(data.room);
    setStatus(data.peers >= 1 ? '상대방과 암호화 연결 중…' : '상대방을 기다리는 중…', 'waiting');
    connectRoomSocket(data.room, false);
  } catch {
    showError('서버에 연결할 수 없습니다.');
  }
}

function connectRoomSocket(code, rejoin) {
  closeSocket();
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const qs = `room=${encodeURIComponent(code)}${rejoin ? '&rejoin=1' : ''}`;
  const sock = new WebSocket(`${proto}://${location.host}/ws?${qs}`);
  sock.binaryType = 'arraybuffer';
  ws = sock;

  sock.onopen = () => {
    pingTimer = setInterval(() => {
      if (sock.readyState === WebSocket.OPEN) sock.send('ping');
    }, 25_000);
  };

  sock.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      // E2EE 암호화된 바이너리 파일 청크 → 순서 보장하며 복호화
      const frame = e.data;
      relayDecryptChain = relayDecryptChain.then(() => onRelayBinaryFrame(frame)).catch(console.error);
      return;
    }
    if (e.data === 'pong') return;
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    handleServerMessage(msg);
  };

  sock.onclose = async (e) => {
    if (ws !== sock) return;
    clearInterval(pingTimer);
    pingTimer = null;
    ws = null;
    resetRelayCrypto(false);

    if (e.code === 4404 || e.code === 4409) {
      leaveRoom(false);
      return;
    }

    if (!roomCode) return;
    if (!isP2pConnected()) {
      failActiveTransfers('연결이 끊어졌습니다.');
      setChatEnabled(false);
      setStatus('서버 연결 끊김 — 재연결 중…', 'error', true);
    }
    if (!(await checkSession())) return;
    reconnectTimer = setTimeout(() => {
      if (roomCode) connectRoomSocket(roomCode, true);
    }, 2000);
  };
}

function closeSocket() {
  clearTimeout(reconnectTimer);
  reconnectTimer = null;
  clearInterval(pingTimer);
  pingTimer = null;
  if (ws) {
    const old = ws;
    ws = null;
    old.onclose = null;
    old.close();
  }
}

function wsSend(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function handleServerMessage(msg) {
  switch (msg.type) {
    case 'joined':
      if (msg.peers > 1) {
        peerPresent = true;
        setStatus('상대방과 암호화 키 교환 중…', 'waiting');
        initE2eeRelay().catch(onPeerError);
      } else if (!isTransportReady()) {
        peerPresent = false;
        setStatus('상대방을 기다리는 중… 링크나 코드를 공유하세요.', 'waiting');
      }
      break;

    case 'peer-joined':
      peerPresent = true;
      hideDiag();
      // 이미 P2P 연결이 살아있고 단순 WS 재접속이면 기존 연결 유지
      if (msg.rejoin && isP2pConnected()) {
        initE2eeRelay().catch(() => {});
        return;
      }
      setStatus('상대방과 암호화 키 교환 중…', 'waiting');
      initE2eeRelay().catch(onPeerError);
      break;

    case 'peer-left':
      peerPresent = false;
      resetRelayCrypto(true);
      if (!isP2pConnected()) {
        closePeer();
        setChatEnabled(false);
        hideDiag();
        $('#peerInfo').hidden = true;
        setStatus('상대방이 나갔습니다. 다시 접속을 기다리는 중…', 'waiting');
      }
      break;

    case 'e2ee':
      e2eeChain = e2eeChain.then(() => handleE2eeSignal(msg.data)).catch(onPeerError);
      break;

    case 'relay':
      relayDecryptChain = relayDecryptChain.then(() => onRelayEncryptedJson(msg.data)).catch(console.error);
      break;

    case 'signal':
      signalChain = signalChain.then(() => handleSignal(msg.data)).catch(onPeerError);
      break;

    case 'error':
      showError(msg.message);
      break;
  }
}

// ================================================================ E2EE 서버 중계 (ECDH P-256 + AES-256-GCM)
function toBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromBase64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function ensureMyKeyPair(fresh = false) {
  if (!fresh && myKeyPair && myPubJwk && myPubRaw) return;
  myKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  myPubJwk = await crypto.subtle.exportKey('jwk', myKeyPair.publicKey);
  myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', myKeyPair.publicKey));
}

function initE2eeRelay() {
  e2eeChain = e2eeChain
    .then(async () => {
      if (!window.crypto?.subtle) {
        setStatus('보안 컨텍스트(HTTPS 또는 localhost)가 필요합니다.', 'error');
        return;
      }
      await ensureMyKeyPair(true);
      relayKey = null;
      relayReady = false;
      wsSend({ type: 'e2ee', data: { pub: myPubJwk, reply: false } });
    })
    .catch(onPeerError);
  return e2eeChain;
}

async function handleE2eeSignal(data) {
  if (!data?.pub || !window.crypto?.subtle) return;
  await ensureMyKeyPair(false);
  if (!data.reply) {
    wsSend({ type: 'e2ee', data: { pub: myPubJwk, reply: true } });
  }

  const peerPub = await crypto.subtle.importKey('jwk', data.pub, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const peerPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', peerPub));

  relayKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPub },
    myKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 양쪽 공개키 정렬 해시 → 6자리 SAS 보안 확인 코드 (중간자 변조 즉시 탐지)
  const sorted = [toBase64(myPubRaw), toBase64(peerPubRaw)].sort().join('|');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(sorted)));
  const num = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) % 1_000_000;
  const s = String(num).padStart(6, '0');
  relaySas = `${s.slice(0, 3)} ${s.slice(3)}`;

  const firstConnect = !relayReady;
  relayReady = true;
  peerPresent = true;
  hideDiag();
  updateTransportUI();
  setChatEnabled(true);

  if (firstConnect) {
    if (myName) sendChatPayload({ type: 'hello', name: myName }).catch(() => {});
    appendChatSystem('종단간 암호화(E2EE) 연결이 완료되었습니다.');
  }
  processQueue();
}

function resetRelayCrypto(failTransfers) {
  relayKey = null;
  relayReady = false;
  myKeyPair = null;
  myPubRaw = null;
  myPubJwk = null;
  if (failTransfers && !isP2pConnected()) failActiveTransfers('상대방이 방을 나갔습니다.');
}

async function sendRelayJson(obj) {
  if (!relayReady || !relayKey || !ws || ws.readyState !== WebSocket.OPEN) {
    throw new Error('중계 연결이 닫혀 있습니다.');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, relayKey, encoder.encode(JSON.stringify(obj)))
  );
  wsSend({ type: 'relay', data: { iv: toBase64(iv), ct: toBase64(ct) } });
}

async function sendRelayBinary(buf) {
  if (!relayReady || !relayKey || !ws || ws.readyState !== WebSocket.OPEN) {
    throw new Error('중계 연결이 닫혀 있습니다.');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, relayKey, buf));
  const frame = new Uint8Array(12 + ct.byteLength);
  frame.set(iv, 0);
  frame.set(ct, 12);
  ws.send(frame);
}

async function onRelayEncryptedJson(data) {
  if (!relayKey || !data?.iv || !data?.ct) return;
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(data.iv) },
    relayKey,
    fromBase64(data.ct)
  );
  const msg = JSON.parse(decoder.decode(plain));
  onAppControlMessage(msg, 'relay');
}

async function onRelayBinaryFrame(frame) {
  if (!relayKey || frame.byteLength <= 28) return; // 12 IV + 16 GCM tag 최소
  const iv = new Uint8Array(frame, 0, 12);
  const ct = new Uint8Array(frame, 12);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, relayKey, ct);
  onChunk(plain, 'relay');
}

// ================================================================ 선택적 WebRTC P2P 직통 (5가지 버그 수정 반영)
async function startPeer(initiator) {
  await refreshIceConfig(false);
  closePeer(false);
  pendingCandidates = [];
  iceRestarted = false;
  candStats = { local: { host: 0, srflx: 0, relay: 0 }, remote: { host: 0, srflx: 0, relay: 0 } };

  const myPc = new RTCPeerConnection({ iceServers });
  pc = myPc;

  myPc.onicecandidate = (e) => {
    if (pc !== myPc) return; // 낡은 PC의 ICE 후보 유출 차단
    if (e.candidate) {
      recordCand('local', e.candidate.candidate);
      wsSend({ type: 'signal', data: { candidate: e.candidate } });
    }
  };

  myPc.onconnectionstatechange = () => {
    if (pc !== myPc) return;
    if (myPc.connectionState === 'connected') {
      iceRestarted = false;
      hideDiag();
      updateTransportUI();
    } else if (myPc.connectionState === 'failed') {
      handleP2pFailure(myPc, initiator);
    }
  };

  myPc.oniceconnectionstatechange = () => {
    if (pc !== myPc) return;
    if (myPc.iceConnectionState === 'failed') {
      handleP2pFailure(myPc, initiator);
    }
  };

  if (initiator) {
    setupChannel(myPc.createDataChannel('files', { ordered: true }));
    setupChatChannel(myPc.createDataChannel('chat', { ordered: true }));
    const offer = await myPc.createOffer();
    await myPc.setLocalDescription(offer);
    wsSend({ type: 'signal', data: { description: myPc.localDescription } });
  } else {
    myPc.ondatachannel = (e) => {
      if (pc !== myPc) return;
      if (e.channel.label === 'chat') setupChatChannel(e.channel);
      else setupChannel(e.channel);
    };
  }
}

async function handleP2pFailure(myPc, initiator) {
  if (pc !== myPc) return;
  // Initiator는 1회 자동 ICE Restart 시도
  if (initiator && !iceRestarted && ws?.readyState === WebSocket.OPEN) {
    iceRestarted = true;
    try {
      const offer = await myPc.createOffer({ iceRestart: true });
      await myPc.setLocalDescription(offer);
      wsSend({ type: 'signal', data: { description: myPc.localDescription } });
      return;
    } catch { /* 재시도 실패 시 중계 유지 */ }
  }

  const diag = buildP2pDiagnostics();
  closePeer(false);
  updateTransportUI();
  showDiag(`P2P 직통 연결 불가 — 암호화 서버 중계(E2EE)로 계속 안전하게 사용 중입니다. (${diag})`);
}

function recordCand(side, sdpLine) {
  const m = String(sdpLine || '').match(/ typ (host|srflx|relay)\b/);
  if (m && candStats[side][m[1]] !== undefined) candStats[side][m[1]] += 1;
}

function buildP2pDiagnostics() {
  const l = candStats.local;
  const r = candStats.remote;
  const summary = `로컬 ${l.host}/${r.host} · 공인 ${l.srflx}/${r.srflx} · TURN중계 ${l.relay}/${r.relay}`;
  if (turnError) return `${summary} · ${turnError}`;
  if (!hasTurn) return `${summary} · 대칭형 NAT/방화벽 환경(TURN 미설정)`;
  return summary;
}

async function handleSignal(data) {
  if (!data) return;
  if (data.description) {
    if (data.description.type === 'offer') {
      // ICE restart offer면 기존 PC 재사용, 아니면 새 PC 생성
      if (!pc || pc.signalingState === 'closed') await startPeer(false);
      await pc.setRemoteDescription(data.description);
      await flushPendingCandidates(pc);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'signal', data: { description: pc.localDescription } });
    } else if (pc) {
      await pc.setRemoteDescription(data.description);
      await flushPendingCandidates(pc);
    }
  } else if (data.candidate) {
    recordCand('remote', data.candidate.candidate);
    // remoteDescription 설정 전에 도착한 후보는 버리지 않고 큐에 보관
    if (!pc || !pc.remoteDescription) {
      if (pendingCandidates.length < 200) pendingCandidates.push(data.candidate);
      return;
    }
    try { await pc.addIceCandidate(data.candidate); } catch (err) { console.warn('ICE candidate 오류', err); }
  }
}

async function flushPendingCandidates(targetPc) {
  const queued = pendingCandidates.splice(0);
  for (const c of queued) {
    if (pc !== targetPc) return;
    try { await targetPc.addIceCandidate(c); } catch (err) { console.warn('보류 ICE 추가 오류', err); }
  }
}

function setupChannel(ch) {
  channel = ch;
  ch.binaryType = 'arraybuffer';
  ch.bufferedAmountLowThreshold = P2P_LOW_WATER;

  ch.onopen = () => {
    if (channel !== ch) return;
    updateTransportUI();
    appendChatSystem('⚡ P2P 직통 연결(WebRTC)로 전환되었습니다.');
    processQueue();
  };
  ch.onclose = () => {
    if (channel !== ch) return;
    closePeer(false);
    updateTransportUI();
  };
  ch.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) return onChunk(e.data, 'p2p');
    if (typeof e.data !== 'string') return;
    try { onAppControlMessage(JSON.parse(e.data), 'p2p'); } catch { /* 무시 */ }
  };
}

function setupChatChannel(ch) {
  chatChannel = ch;
  ch.onopen = () => {
    if (chatChannel !== ch) return;
    setChatEnabled(true);
    if (myName) ch.send(JSON.stringify({ type: 'hello', name: myName }));
  };
  ch.onclose = () => {
    if (chatChannel !== ch) return;
    chatChannel = null;
  };
  ch.onmessage = (e) => {
    if (typeof e.data !== 'string') return;
    try { onChatPayload(JSON.parse(e.data)); } catch { /* 무시 */ }
  };
}

function closePeer(failTransfers = true) {
  pendingCandidates = [];
  if (chatChannel) {
    const ch = chatChannel;
    chatChannel = null;
    ch.onclose = null;
    ch.close();
  }
  if (channel) {
    const ch = channel;
    channel = null;
    ch.onclose = null;
    ch.close();
  }
  if (pc) {
    const old = pc;
    pc = null;
    old.close();
  }
  if (failTransfers && !relayReady) failActiveTransfers('연결이 끊어졌습니다.');
}

function failActiveTransfers(reason) {
  for (const w of waiters.values()) w.reject(new Error(reason));
  waiters.clear();
  replies.clear();
  for (const w of chunkAckWaiters.values()) w.reject(new Error(reason));
  chunkAckWaiters.clear();
  chunkAckHighest.clear();
  if (pendingOffer) {
    pendingOffer.ui.fail(reason);
    pendingOffer = null;
  }
  if (incoming) {
    abortIncoming(incoming, reason);
    incoming = null;
  }
}

function isP2pConnected() {
  return !!channel && channel.readyState === 'open';
}

function isTransportReady() {
  return isP2pConnected() || (relayReady && ws?.readyState === WebSocket.OPEN);
}

function currentTransport() {
  return isP2pConnected() ? 'p2p' : 'relay';
}

async function updateTransportUI() {
  const boostBtn = $('#p2pBoostBtn');
  if (isP2pConnected()) {
    $('#peerInfo').hidden = false;
    $('#sas').textContent = await dtlsSafetyCode(pc);
    $('#route').textContent = await p2pRouteType(pc);
    boostBtn.hidden = true;
    setStatus('연결됨 — P2P 직통으로 파일 전송과 채팅을 할 수 있습니다.', 'ok');
  } else if (relayReady && ws?.readyState === WebSocket.OPEN) {
    $('#peerInfo').hidden = false;
    $('#sas').textContent = relaySas;
    $('#route').textContent = 'Cloudflare 암호화 서버 중계 (E2EE)';
    boostBtn.hidden = false;
    boostBtn.disabled = false;
    boostBtn.textContent = '⚡ P2P 직통 전환';
    setStatus('연결됨 — 종단간 암호화 서버 중계로 파일 전송과 채팅을 할 수 있습니다.', 'ok');
  } else {
    $('#peerInfo').hidden = true;
  }
}

async function dtlsSafetyCode(myPc) {
  if (!myPc || !window.crypto?.subtle) return relaySas;
  const fp = (sdp) => (sdp?.match(/^a=fingerprint:(.+)$/m) || [])[1]?.trim().toUpperCase();
  const mine = fp(myPc.localDescription?.sdp);
  const theirs = fp(myPc.remoteDescription?.sdp);
  if (!mine || !theirs) return relaySas;
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode([mine, theirs].sort().join('|'))));
  const num = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) % 1_000_000;
  const s = String(num).padStart(6, '0');
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

async function p2pRouteType(myPc) {
  try {
    const stats = await myPc.getStats();
    let pair = null;
    stats.forEach((r) => {
      if (r.type === 'transport' && r.selectedCandidatePairId) pair = stats.get(r.selectedCandidatePairId);
    });
    if (!pair) stats.forEach((r) => { if (r.type === 'candidate-pair' && r.selected) pair = r; });
    if (!pair) return 'P2P 직접 연결';
    const local = stats.get(pair.localCandidateId);
    const remote = stats.get(pair.remoteCandidateId);
    const relayed = local?.candidateType === 'relay' || remote?.candidateType === 'relay';
    return relayed ? 'TURN 중계 P2P (암호화됨)' : '직접 연결 (P2P)';
  } catch {
    return 'P2P 직접 연결';
  }
}

function onPeerError(err) {
  console.error(err);
  if (!isTransportReady()) setStatus(`연결 오류: ${err.message || err}`, 'error', true);
}

// ================================================================ 채팅 (P2P 또는 E2EE 서버 중계)
function isChatOpen() {
  return (!!chatChannel && chatChannel.readyState === 'open') || (relayReady && ws?.readyState === WebSocket.OPEN);
}

function setChatEnabled(enabled) {
  $('#chatInput').disabled = !enabled;
  $('#chatSendBtn').disabled = !enabled;
}

async function sendChatPayload(payload) {
  if (chatChannel && chatChannel.readyState === 'open') {
    chatChannel.send(JSON.stringify(payload));
  } else if (relayReady) {
    await sendRelayJson({ ...payload, _ch: 'chat' });
  }
}

function onChatPayload(msg) {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'hello' && typeof msg.name === 'string') {
    peerName = msg.name.trim().slice(0, 30) || '상대방';
  } else if (msg.type === 'typing') {
    showTyping();
  } else if (msg.type === 'chat' && typeof msg.text === 'string') {
    const text = msg.text.slice(0, 4000);
    if (!text.trim()) return;
    hideTyping();
    appendChatMessage('peer', peerName, text, msg.ts);
    if (document.hidden) {
      unreadChat += 1;
      document.title = `(${unreadChat}) 💬 새 메시지 · P2P 파일 전송`;
    }
  }
}

function sendChatMessage() {
  if (!isChatOpen()) return;
  const input = $('#chatInput');
  const text = input.value.trim().slice(0, 4000);
  if (!text) return;
  const ts = Date.now();
  sendChatPayload({ type: 'chat', text, ts }).catch(() => {});
  appendChatMessage('me', '나', text, ts);
  input.value = '';
  input.style.height = 'auto';
  input.focus();
}

function showTyping() {
  const el = $('#chatTyping');
  el.textContent = `${peerName} 입력 중…`;
  el.hidden = false;
  clearTimeout(typingHideTimer);
  typingHideTimer = setTimeout(hideTyping, 2500);
}

function hideTyping() {
  clearTimeout(typingHideTimer);
  typingHideTimer = null;
  $('#chatTyping').hidden = true;
}

function formatClock(ts) {
  const d = new Date(Number.isFinite(ts) ? ts : Date.now());
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function appendChatMessage(side, sender, text, ts) {
  const log = $('#chatLog');
  const item = document.createElement('div');
  item.className = `chat-msg ${side}`;

  const meta = document.createElement('div');
  meta.className = 'chat-meta';
  meta.textContent = `${sender} · ${formatClock(ts)}`;

  const body = document.createElement('div');
  body.className = 'chat-text';
  body.textContent = text; // textContent만 사용 (XSS 방지)

  item.append(meta, body);
  log.append(item);
  log.scrollTop = log.scrollHeight;
}

function appendChatSystem(text) {
  const log = $('#chatLog');
  const el = document.createElement('div');
  el.className = 'chat-sys';
  el.textContent = text;
  log.append(el);
  log.scrollTop = log.scrollHeight;
}

// ================================================================ 파일 송신 (P2P / E2EE 서버 중계 통합)
async function sendCtl(msg, transport = currentTransport()) {
  if (transport === 'p2p') {
    if (!isP2pConnected()) throw new Error('P2P 연결이 끊어졌습니다.');
    channel.send(JSON.stringify(msg));
  } else {
    await sendRelayJson(msg);
  }
}

function enqueueFiles(fileList) {
  for (const file of fileList) {
    const job = { id: makeId(), file, cancelled: false, transport: null };
    job.ui = addTransferUI({ name: file.name, size: file.size, direction: 'send' });
    job.ui.note(isTransportReady() ? '대기 중' : '상대방 연결 대기 중');
    job.ui.setCancel(() => cancelJob(job));
    sendQueue.push(job);
  }
  processQueue();
}

function cancelJob(job) {
  if (job.cancelled) return;
  job.cancelled = true;
  const queued = sendQueue.indexOf(job);
  if (queued >= 0) {
    sendQueue.splice(queued, 1);
  } else {
    if (job.transport) sendCtl({ type: 'cancel', id: job.id }, job.transport).catch(() => {});
    const w = waiters.get(job.id);
    if (w) { waiters.delete(job.id); w.resolve({ type: 'cancelled' }); }
    const cw = chunkAckWaiters.get(job.id);
    if (cw) { chunkAckWaiters.delete(job.id); cw.resolve(); }
  }
  job.ui.fail('취소됨');
}

async function processQueue() {
  if (sending) return;
  sending = true;
  try {
    while (sendQueue.length && isTransportReady()) {
      const job = sendQueue.shift();
      try {
        await sendFile(job);
      } catch (err) {
        if (!job.cancelled) job.ui.fail(`전송 실패: ${err.message}`);
      }
    }
  } finally {
    sending = false;
  }
}

async function sendFile(job) {
  const { id, file, ui } = job;
  const transport = currentTransport();
  job.transport = transport;
  const p2pCh = transport === 'p2p' ? channel : null;

  ui.note('상대방의 수락을 기다리는 중…');
  await sendCtl({ type: 'offer-file', id, name: file.name, size: file.size }, transport);
  const reply = await waitFor(id);
  if (reply.type === 'cancelled') return;
  if (reply.type !== 'accept') {
    ui.fail(reply.reason === 'busy' ? '상대방이 다른 파일을 받는 중입니다.' : '상대방이 거절했습니다.');
    return;
  }

  ui.start();
  const chunkSize = transport === 'p2p' ? P2P_CHUNK_SIZE : RELAY_CHUNK_SIZE;
  chunkAckHighest.set(id, 0);
  let offset = 0;
  let seq = 0;

  try {
    while (offset < file.size) {
      if (job.cancelled) return;
      if (replies.has(id)) break;

      if (transport === 'p2p') {
        if (!p2pCh || p2pCh.readyState !== 'open') throw new Error('연결이 끊어졌습니다.');
        if (p2pCh.bufferedAmount > P2P_HIGH_WATER) await waitForDrain(p2pCh);
        const buf = await file.slice(offset, offset + chunkSize).arrayBuffer();
        if (job.cancelled) return;
        p2pCh.send(buf);
        offset += buf.byteLength;
        ui.progress(Math.max(0, offset - p2pCh.bufferedAmount));
      } else {
        if (!relayReady || !ws || ws.readyState !== WebSocket.OPEN) throw new Error('중계 연결이 끊어졌습니다.');
        // 슬라이딩 윈도우 백프레셔: 수신 확인 없이 최대 RELAY_WINDOW_CHUNKS 개까지만 선전송
        const acked = chunkAckHighest.get(id) || 0;
        if (seq - acked >= RELAY_WINDOW_CHUNKS) {
          await waitForChunkAck(id, seq - RELAY_WINDOW_CHUNKS + 1);
          if (job.cancelled || replies.has(id)) break;
        }
        const buf = await file.slice(offset, offset + chunkSize).arrayBuffer();
        if (job.cancelled) return;
        await sendRelayBinary(buf);
        seq += 1;
        offset += buf.byteLength;
        ui.progress(Math.max(0, offset - (ws.bufferedAmount || 0)));
      }
    }
  } catch (err) {
    sendCtl({ type: 'cancel', id }, transport).catch(() => {});
    throw err;
  } finally {
    chunkAckHighest.delete(id);
    chunkAckWaiters.delete(id);
  }

  if (!replies.has(id)) {
    await sendCtl({ type: 'end', id }, transport);
    ui.setCancel(null);
    ui.progress(file.size, true);
    ui.note('상대방이 저장을 마치기를 기다리는 중…');
  }

  const done = await waitFor(id);
  if (done.type === 'ack') ui.complete('전송 완료 ✓');
  else if (done.type !== 'cancelled') ui.fail(`상대방 저장 실패${done.reason ? `: ${done.reason}` : ''}`);
}

function waitFor(id) {
  if (replies.has(id)) {
    const msg = replies.get(id);
    replies.delete(id);
    return Promise.resolve(msg);
  }
  return new Promise((resolve, reject) => waiters.set(id, { resolve, reject }));
}

function waitForChunkAck(id, targetSeq) {
  if ((chunkAckHighest.get(id) || 0) >= targetSeq) return Promise.resolve();
  return new Promise((resolve, reject) => chunkAckWaiters.set(id, { targetSeq, resolve, reject }));
}

function onReply(msg) {
  const w = waiters.get(msg.id);
  if (w) {
    waiters.delete(msg.id);
    w.resolve(msg);
  } else if (replies.size < 100) {
    replies.set(msg.id, msg);
  }
}

function waitForDrain(ch) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      ch.removeEventListener('bufferedamountlow', onLow);
      ch.removeEventListener('close', onClose);
    };
    const onLow = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error('연결이 끊어졌습니다.')); };
    ch.addEventListener('bufferedamountlow', onLow);
    ch.addEventListener('close', onClose);
  });
}

// ================================================================ 파일 수신
function onAppControlMessage(msg, transport) {
  if (!msg || typeof msg !== 'object') return;
  if (msg._ch === 'chat') return onChatPayload(msg);

  msg.id = String(msg.id ?? '').slice(0, 64);

  switch (msg.type) {
    case 'offer-file':
      return onFileOffer(msg, transport);
    case 'accept':
    case 'decline':
    case 'ack':
    case 'fail':
      return onReply(msg);
    case 'chunk-ack': {
      const seq = Number(msg.seq) || 0;
      const prev = chunkAckHighest.get(msg.id) || 0;
      if (seq > prev) chunkAckHighest.set(msg.id, seq);
      const cw = chunkAckWaiters.get(msg.id);
      if (cw && seq >= cw.targetSeq) {
        chunkAckWaiters.delete(msg.id);
        cw.resolve();
      }
      return;
    }
    case 'end':
      if (incoming && incoming.id === msg.id) finishIncoming();
      return;
    case 'cancel':
      if (pendingOffer?.id === msg.id) {
        pendingOffer.ui.fail('상대방이 취소했습니다.');
        pendingOffer = null;
      } else if (incoming?.id === msg.id) {
        abortIncoming(incoming, '상대방이 전송을 취소했습니다.');
        incoming = null;
      }
      return;
  }
}

function onFileOffer(msg, transport) {
  const size = Number(msg.size);
  if (!msg.id || !Number.isSafeInteger(size) || size < 0) return;
  if (pendingOffer || incoming) {
    sendCtl({ type: 'decline', id: msg.id, reason: 'busy' }, transport).catch(() => {});
    return;
  }

  const name = sanitizeName(msg.name);
  const ui = addTransferUI({ name, size, direction: 'recv' });
  const offer = { id: msg.id, name, size, ui, transport };
  pendingOffer = offer;

  let hint = '받으시겠습니까?';
  if (!canStreamToDisk && size > BLOB_WARN_SIZE) {
    hint += ' (큰 파일: 이 브라우저는 메모리에 모아 저장하므로 실패할 수 있어요. Chrome/Edge 권장)';
  }
  ui.note(hint);
  ui.ask(() => acceptOffer(offer), () => declineOffer(offer));
}

async function acceptOffer(offer) {
  let writable = null;
  if (canStreamToDisk) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: offer.name });
      writable = await handle.createWritable();
    } catch (err) {
      if (err.name === 'AbortError') return false;
      console.warn('디스크 직접 저장 불가, 메모리 방식으로 받습니다.', err);
    }
  }

  if (pendingOffer !== offer || !isTransportReady()) {
    writable?.abort().catch(() => {});
    return true;
  }

  pendingOffer = null;
  incoming = {
    ...offer,
    writable,
    chunks: writable ? null : [],
    received: 0,
    chunkCount: 0,
    writeChain: Promise.resolve(),
    error: null,
  };
  offer.ui.start();
  await sendCtl({ type: 'accept', id: offer.id }, offer.transport).catch(() => {});
  return true;
}

function declineOffer(offer) {
  if (pendingOffer !== offer) return;
  pendingOffer = null;
  sendCtl({ type: 'decline', id: offer.id }, offer.transport).catch(() => {});
  offer.ui.fail('거절함');
}

function onChunk(buf, transport) {
  const f = incoming;
  if (!f || f.transport !== transport) return;

  f.received += buf.byteLength;
  f.chunkCount += 1;
  if (f.received > f.size) {
    incoming = null;
    abortIncoming(f, '데이터 크기가 맞지 않습니다.');
    sendCtl({ type: 'fail', id: f.id, reason: '크기 불일치' }, f.transport).catch(() => {});
    return;
  }

  if (f.writable) {
    const seq = f.chunkCount;
    f.writeChain = f.writeChain
      .then(async () => {
        if (f.error) return;
        await f.writable.write(buf);
        if (f.transport === 'relay' && seq % RELAY_ACK_EVERY === 0) {
          sendCtl({ type: 'chunk-ack', id: f.id, seq }, 'relay').catch(() => {});
        }
      })
      .catch((err) => { f.error ||= err; });
  } else {
    f.chunks.push(buf);
    if (f.transport === 'relay' && f.chunkCount % RELAY_ACK_EVERY === 0) {
      sendCtl({ type: 'chunk-ack', id: f.id, seq: f.chunkCount }, 'relay').catch(() => {});
    }
  }
  f.ui.progress(f.received);
}

async function finishIncoming() {
  const f = incoming;
  incoming = null;

  if (f.received !== f.size) {
    abortIncoming(f, `불완전한 파일 (${formatBytes(f.received)} / ${formatBytes(f.size)})`);
    sendCtl({ type: 'fail', id: f.id, reason: '크기 불일치' }, f.transport).catch(() => {});
    return;
  }

  try {
    if (f.writable) {
      f.ui.note('디스크에 저장 마무리 중…');
      await f.writeChain;
      if (f.error) throw f.error;
      await f.writable.close();
      f.ui.complete('저장 완료 ✓');
    } else {
      const blob = new Blob(f.chunks, { type: 'application/octet-stream' });
      f.chunks = null;
      f.ui.complete('수신 완료 ✓', { url: URL.createObjectURL(blob), name: f.name });
    }
    await sendCtl({ type: 'ack', id: f.id }, f.transport).catch(() => {});
  } catch (err) {
    abortIncoming(f, `저장 실패: ${err.message}`);
    sendCtl({ type: 'fail', id: f.id, reason: '수신 측 저장 실패' }, f.transport).catch(() => {});
  }
}

function abortIncoming(f, reason) {
  f.ui.fail(reason);
  f.chunks = null;
  f.writable?.abort().catch(() => {});
}

function sanitizeName(name) {
  const clean = String(name || 'file')
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f]/g, '_')
    .replace(/^\.+/, '_')
    .slice(0, 200);
  return clean || 'file';
}

// ================================================================ 방 / UI
function enterRoom(code) {
  roomCode = code;
  $('#home').hidden = true;
  $('#room').hidden = false;
  $('#roomCode').textContent = code;
  $('#shareLink').value = `${location.origin}${location.pathname}?room=${code}`;
  history.replaceState(null, '', `?room=${code}`);
}

function leaveRoom(notify = true) {
  if (notify) wsSend({ type: 'leave' });
  closeSocket();
  resetRelayCrypto(false);
  closePeer(true);
  peerPresent = false;
  for (const job of sendQueue) job.ui.fail('취소됨');
  sendQueue.length = 0;
  roomCode = null;
  unreadChat = 0;
  document.title = 'P2P 파일 전송';
  $('#chatLog').replaceChildren();
  $('#chatInput').value = '';
  $('#chatInput').style.height = 'auto';
  setChatEnabled(false);
  hideDiag();
  $('#peerInfo').hidden = true;
  history.replaceState(null, '', location.pathname);
  $('#room').hidden = true;
  $('#home').hidden = false;
  setStatus('연결 준비 중…', 'waiting');
}

async function copyText(text, btn, defaultLabel) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const tmp = document.createElement('textarea');
    tmp.value = text;
    document.body.append(tmp);
    tmp.select();
    document.execCommand('copy');
    tmp.remove();
  }
  btn.textContent = '복사됨!';
  setTimeout(() => { btn.textContent = defaultLabel; }, 1500);
}

function setStatus(text, kind, showReconnect = false) {
  $('#statusText').textContent = text;
  $('#status').className = `status ${kind}`;
  $('#reconnectBtn').hidden = !showReconnect;
}

function showDiag(text) {
  const el = $('#diagText');
  el.textContent = text;
  el.hidden = false;
}

function hideDiag() {
  $('#diagText').hidden = true;
}

function showError(text) {
  const el = $('#homeError');
  el.textContent = text;
  el.hidden = false;
  if (roomCode) setStatus(text, 'error', true);
}

function hideError() {
  $('#homeError').hidden = true;
}

function makeButton(label, className) {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  b.className = className;
  return b;
}

function addTransferUI({ name, size, direction }) {
  const li = document.createElement('li');
  li.className = `transfer ${direction}`;
  li.innerHTML = `
    <div class="row"><span class="dir"></span><span class="name"></span><span class="size"></span></div>
    <div class="bar"><div class="fill"></div></div>
    <div class="row meta"><span class="note"></span><span class="action"></span></div>`;
  li.querySelector('.dir').textContent = direction === 'send' ? '↑' : '↓';
  li.querySelector('.name').textContent = name;
  li.querySelector('.name').title = name;
  li.querySelector('.size').textContent = formatBytes(size);
  $('#transfers').prepend(li);

  const fill = li.querySelector('.fill');
  const noteEl = li.querySelector('.note');
  const actionEl = li.querySelector('.action');
  let startTime = performance.now();
  let lastRender = 0;

  return {
    note(text) { noteEl.textContent = text; },
    start() {
      startTime = performance.now();
      noteEl.textContent = '0%';
    },
    progress(bytes, force = false) {
      const now = performance.now();
      if (!force && now - lastRender < 100 && bytes < size) return;
      lastRender = now;
      const pct = size ? Math.min(100, (bytes / size) * 100) : 100;
      fill.style.width = `${pct}%`;
      const secs = (now - startTime) / 1000;
      const speed = secs > 0 ? bytes / secs : 0;
      noteEl.textContent = `${pct.toFixed(0)}% · ${formatBytes(speed)}/s`;
    },
    complete(text, download) {
      fill.style.width = '100%';
      const secs = (performance.now() - startTime) / 1000;
      noteEl.textContent = `${text} (${secs.toFixed(1)}초)`;
      actionEl.replaceChildren();
      if (download) {
        const a = document.createElement('a');
        a.href = download.url;
        a.download = download.name;
        a.textContent = '저장';
        actionEl.append(a);
      }
    },
    fail(text) {
      li.classList.add('failed');
      noteEl.textContent = text;
      actionEl.replaceChildren();
    },
    ask(onAccept, onDecline) {
      const yes = makeButton('수락', 'small accept');
      const no = makeButton('거절', 'small ghost');
      yes.addEventListener('click', async () => {
        yes.disabled = no.disabled = true;
        const done = await onAccept();
        if (done === false) yes.disabled = no.disabled = false;
        else if (actionEl.contains(yes)) actionEl.replaceChildren();
      });
      no.addEventListener('click', onDecline);
      actionEl.replaceChildren(yes, no);
    },
    setCancel(fn) {
      if (!fn) return actionEl.replaceChildren();
      const b = makeButton('취소', 'small ghost');
      b.addEventListener('click', fn);
      actionEl.replaceChildren(b);
    },
  };
}

function formatBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function makeId() {
  if (window.crypto?.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
