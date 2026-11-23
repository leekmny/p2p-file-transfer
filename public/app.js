// P2P 파일 전송 클라이언트 (Cloudflare Workers + Durable Objects 시그널링)
//  1) 세션 확인(이메일 계정 / 공유 비밀번호 / 10분 임시 특별 코드 / Cloudflare Access)
//  2) 관리자일 경우 10분 임시 특별 코드 발급·조회·파기 패널 제공
//  3) POST /api/rooms 로 방 생성 또는 GET /api/rooms/:code 확인 후 /ws?room=CODE 연결
//  4) 상대가 들어오면 RTCPeerConnection + DataChannel 생성 + 6자리 보안 확인 코드(SAS) 표시
//  5) DataChannel 전송: offer-file → accept/decline → 64KB 청크… → end → ack

const $ = (s) => document.querySelector(s);

const CHUNK_SIZE = 64 * 1024;          // 브라우저 간 호환성이 좋은 청크 크기
const HIGH_WATER = 4 * 1024 * 1024;    // 송신 버퍼가 이 이상이면 대기 (backpressure)
const LOW_WATER = 512 * 1024;          // 이 아래로 내려가면 다시 전송
const BLOB_WARN_SIZE = 1024 ** 3;      // 디스크 직접 저장이 불가한 브라우저에서 경고할 크기
const canStreamToDisk = typeof window.showSaveFilePicker === 'function';

let ws = null;
let pingTimer = null;
let reconnectTimer = null;
let pc = null;
let channel = null;
let roomCode = null;
let authMode = 'cookie';
let isAdmin = false;
let iceServers = [];
let signalChain = Promise.resolve();

let issuedPassExpiresAt = 0;
let passCountdownTimer = null;
let activePasses = [];

const sendQueue = [];
let sending = false;
const waiters = new Map();
const replies = new Map();
let pendingOffer = null;
let incoming = null;

// ================================================================ 초기화
init();

async function init() {
  if (!(await checkSession())) return;
  try {
    const res = await fetch('/config', { cache: 'no-store' });
    if (res.ok) iceServers = (await res.json()).iceServers;
  } catch { /* ICE 서버 없이 시도 */ }

  bindUI();

  const codeFromUrl = new URLSearchParams(location.search).get('room');
  if (codeFromUrl) joinRoom(codeFromUrl.trim().toUpperCase());
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
        badge.textContent = data.email;
        badge.hidden = false;
      } else if (data.isGuest) {
        badge.textContent = '임시 게스트';
        badge.hidden = false;
      }
      $('#adminPassToggle').hidden = !isAdmin;
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

  $('#leaveBtn').addEventListener('click', leaveRoom);
  $('#copyBtn').addEventListener('click', () => copyText($('#shareLink').value, $('#copyBtn'), '링크 복사'));
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
}

// ================================================================ 관리자 임시 특별 코드 (10분 만료)
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
  const m = String(Math.floor(sec / 60)).padStart(2, '0');
  const s = String(sec % 60).padStart(2, '0');
  return `${m}:${s}`;
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

// ================================================================ 방 생성 / 참여 / 시그널링
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
    setStatus(data.peers >= 1 ? '상대방과 연결하는 중…' : '상대방을 기다리는 중…', 'waiting');
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
  ws = sock;

  sock.onopen = () => {
    pingTimer = setInterval(() => {
      if (sock.readyState === WebSocket.OPEN) sock.send('ping');
    }, 25_000);
  };

  sock.onmessage = (e) => {
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

    if (e.code === 4404 || e.code === 4409) {
      leaveRoom(false);
      return;
    }

    if (!roomCode) return;
    if (!isConnected()) setStatus('시그널링 연결 끊김 — 재연결 중…', 'error');
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
      if (!isConnected()) {
        setStatus(msg.peers > 1 ? '상대방과 연결하는 중…' : '상대방을 기다리는 중… 링크나 코드를 공유하세요.', 'waiting');
      }
      break;

    case 'peer-joined':
      if (msg.rejoin && isConnected()) return;
      setStatus('상대방과 연결하는 중…', 'waiting');
      startPeer(true).catch(onPeerError);
      break;

    case 'peer-left':
      if (!isConnected()) {
        closePeer();
        setStatus('상대방이 나갔습니다. 다시 접속을 기다리는 중…', 'waiting');
      }
      break;

    case 'signal':
      signalChain = signalChain.then(() => handleSignal(msg.data)).catch(onPeerError);
      break;

    case 'error':
      showError(msg.message);
      break;
  }
}

// ================================================================ WebRTC
async function startPeer(initiator) {
  closePeer();
  const myPc = new RTCPeerConnection({ iceServers });
  pc = myPc;

  myPc.onicecandidate = (e) => {
    if (e.candidate) wsSend({ type: 'signal', data: { candidate: e.candidate } });
  };

  myPc.onconnectionstatechange = () => {
    if (pc !== myPc) return;
    switch (myPc.connectionState) {
      case 'connected':
        showPeerInfo(myPc).catch(console.warn);
        break;
      case 'disconnected':
        setStatus('연결이 불안정합니다…', 'waiting');
        break;
      case 'failed':
        closePeer();
        setStatus('P2P 연결 실패 — 방화벽/NAT 환경이면 TURN 서버가 필요합니다 (README 참고).', 'error');
        break;
    }
  };

  if (initiator) {
    setupChannel(myPc.createDataChannel('files', { ordered: true }));
    const offer = await myPc.createOffer();
    await myPc.setLocalDescription(offer);
    wsSend({ type: 'signal', data: { description: myPc.localDescription } });
  } else {
    myPc.ondatachannel = (e) => setupChannel(e.channel);
  }
}

async function handleSignal(data) {
  if (!data) return;
  if (data.description) {
    if (data.description.type === 'offer') {
      await startPeer(false);
      await pc.setRemoteDescription(data.description);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'signal', data: { description: pc.localDescription } });
    } else if (pc) {
      await pc.setRemoteDescription(data.description);
    }
  } else if (data.candidate && pc) {
    try { await pc.addIceCandidate(data.candidate); } catch (err) { console.warn('ICE candidate 오류', err); }
  }
}

function setupChannel(ch) {
  channel = ch;
  ch.binaryType = 'arraybuffer';
  ch.bufferedAmountLowThreshold = LOW_WATER;

  ch.onopen = () => {
    setStatus('연결됨 — 보안 확인 코드를 상대방과 비교한 뒤 파일을 보내세요.', 'ok');
    processQueue();
  };
  ch.onclose = () => {
    if (channel !== ch) return;
    closePeer();
    setStatus('상대방과의 연결이 끊어졌습니다. 재접속을 기다리는 중…', 'error');
  };
  ch.onmessage = (e) => onChannelMessage(e.data);
}

function closePeer() {
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
  $('#peerInfo').hidden = true;

  for (const w of waiters.values()) w.reject(new Error('연결이 끊어졌습니다.'));
  waiters.clear();
  replies.clear();
  if (pendingOffer) {
    pendingOffer.ui.fail('연결이 끊어졌습니다.');
    pendingOffer = null;
  }
  if (incoming) {
    abortIncoming(incoming, '수신 중 연결이 끊어졌습니다.');
    incoming = null;
  }
}

function isConnected() {
  return !!channel && channel.readyState === 'open';
}

function onPeerError(err) {
  console.error(err);
  setStatus(`연결 오류: ${err.message || err}`, 'error');
}

async function showPeerInfo(myPc) {
  $('#peerInfo').hidden = false;
  $('#sas').textContent = await safetyCode(myPc);
  $('#route').textContent = await routeType(myPc);
}

async function safetyCode(myPc) {
  if (!window.crypto?.subtle) return 'HTTPS 필요';
  const fingerprint = (sdp) => (sdp?.match(/^a=fingerprint:(.+)$/m) || [])[1]?.trim().toUpperCase();
  const mine = fingerprint(myPc.localDescription?.sdp);
  const theirs = fingerprint(myPc.remoteDescription?.sdp);
  if (!mine || !theirs) return '확인 불가';
  const data = new TextEncoder().encode([mine, theirs].sort().join('|'));
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const num = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) % 1_000_000;
  const s = String(num).padStart(6, '0');
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

async function routeType(myPc) {
  try {
    const stats = await myPc.getStats();
    let pair = null;
    stats.forEach((r) => {
      if (r.type === 'transport' && r.selectedCandidatePairId) pair = stats.get(r.selectedCandidatePairId);
    });
    if (!pair) stats.forEach((r) => { if (r.type === 'candidate-pair' && r.selected) pair = r; });
    if (!pair) return '알 수 없음';
    const local = stats.get(pair.localCandidateId);
    const remote = stats.get(pair.remoteCandidateId);
    const relayed = local?.candidateType === 'relay' || remote?.candidateType === 'relay';
    return relayed ? 'TURN 서버 중계 (내용은 계속 암호화됨)' : '직접 연결 (P2P)';
  } catch {
    return '알 수 없음';
  }
}

// ================================================================ 송신
function enqueueFiles(fileList) {
  for (const file of fileList) {
    const job = { id: makeId(), file, cancelled: false };
    job.ui = addTransferUI({ name: file.name, size: file.size, direction: 'send' });
    job.ui.note(isConnected() ? '대기 중' : '상대방 연결 대기 중');
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
    sendCtl({ type: 'cancel', id: job.id });
    const w = waiters.get(job.id);
    if (w) { waiters.delete(job.id); w.resolve({ type: 'cancelled' }); }
  }
  job.ui.fail('취소됨');
}

async function processQueue() {
  if (sending) return;
  sending = true;
  try {
    while (sendQueue.length && isConnected()) {
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
  const ch = channel;

  ui.note('상대방의 수락을 기다리는 중…');
  ch.send(JSON.stringify({ type: 'offer-file', id, name: file.name, size: file.size }));
  const reply = await waitFor(id);
  if (reply.type === 'cancelled') return;
  if (reply.type !== 'accept') {
    ui.fail(reply.reason === 'busy' ? '상대방이 다른 파일을 받는 중입니다.' : '상대방이 거절했습니다.');
    return;
  }

  ui.start();
  let offset = 0;
  try {
    while (offset < file.size) {
      if (job.cancelled) return;
      if (replies.has(id)) break;
      if (ch.readyState !== 'open') throw new Error('연결이 끊어졌습니다.');
      if (ch.bufferedAmount > HIGH_WATER) await waitForDrain(ch);

      const buf = await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer();
      if (job.cancelled) return;
      ch.send(buf);
      offset += buf.byteLength;
      ui.progress(Math.max(0, offset - ch.bufferedAmount));
    }
  } catch (err) {
    if (ch.readyState === 'open') ch.send(JSON.stringify({ type: 'cancel', id }));
    throw err;
  }

  if (!replies.has(id)) {
    ch.send(JSON.stringify({ type: 'end', id }));
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

function sendCtl(msg) {
  if (isConnected()) channel.send(JSON.stringify(msg));
}

// ================================================================ 수신
function onChannelMessage(data) {
  if (data instanceof ArrayBuffer) return onChunk(data);
  if (typeof data !== 'string') return;

  let msg;
  try { msg = JSON.parse(data); } catch { return; }
  if (!msg || typeof msg !== 'object') return;
  msg.id = String(msg.id ?? '').slice(0, 64);

  switch (msg.type) {
    case 'offer-file':
      return onFileOffer(msg);
    case 'accept':
    case 'decline':
    case 'ack':
    case 'fail':
      return onReply(msg);
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

function onFileOffer(msg) {
  const size = Number(msg.size);
  if (!msg.id || !Number.isSafeInteger(size) || size < 0) return;
  if (pendingOffer || incoming) {
    sendCtl({ type: 'decline', id: msg.id, reason: 'busy' });
    return;
  }

  const name = sanitizeName(msg.name);
  const ui = addTransferUI({ name, size, direction: 'recv' });
  const offer = { id: msg.id, name, size, ui };
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

  if (pendingOffer !== offer || !isConnected()) {
    writable?.abort().catch(() => {});
    return true;
  }

  pendingOffer = null;
  incoming = {
    ...offer,
    writable,
    chunks: writable ? null : [],
    received: 0,
    writeChain: Promise.resolve(),
    error: null,
  };
  offer.ui.start();
  sendCtl({ type: 'accept', id: offer.id });
  return true;
}

function declineOffer(offer) {
  if (pendingOffer !== offer) return;
  pendingOffer = null;
  sendCtl({ type: 'decline', id: offer.id });
  offer.ui.fail('거절함');
}

function onChunk(buf) {
  const f = incoming;
  if (!f) return;

  f.received += buf.byteLength;
  if (f.received > f.size) {
    incoming = null;
    abortIncoming(f, '데이터 크기가 맞지 않습니다.');
    sendCtl({ type: 'fail', id: f.id, reason: '크기 불일치' });
    return;
  }

  if (f.writable) {
    f.writeChain = f.writeChain
      .then(() => (f.error ? undefined : f.writable.write(buf)))
      .catch((err) => { f.error ||= err; });
  } else {
    f.chunks.push(buf);
  }
  f.ui.progress(f.received);
}

async function finishIncoming() {
  const f = incoming;
  incoming = null;

  if (f.received !== f.size) {
    abortIncoming(f, `불완전한 파일 (${formatBytes(f.received)} / ${formatBytes(f.size)})`);
    sendCtl({ type: 'fail', id: f.id, reason: '크기 불일치' });
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
    sendCtl({ type: 'ack', id: f.id });
  } catch (err) {
    abortIncoming(f, `저장 실패: ${err.message}`);
    sendCtl({ type: 'fail', id: f.id, reason: '수신 측 저장 실패' });
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
  closePeer();
  for (const job of sendQueue) job.ui.fail('취소됨');
  sendQueue.length = 0;
  roomCode = null;
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

function setStatus(text, kind) {
  $('#statusText').textContent = text;
  $('#status').className = `status ${kind}`;
}

function showError(text) {
  const el = $('#homeError');
  el.textContent = text;
  el.hidden = false;
  if (roomCode) setStatus(text, 'error');
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
