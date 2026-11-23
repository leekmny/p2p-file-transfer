const $ = (s) => document.querySelector(s);

const errorEl = $('#error');
const infoEl = $('#info');
const tabsEl = $('#tabs');
const adminBtn = $('#adminLoginBtn');
const oauthHintEl = $('#oauthSetupHint');
const googleBtn = $('#googleLoginBtn');
const githubBtn = $('#githubLoginBtn');

const views = {
  social: $('#socialView'),
  oauthInvite: $('#oauthInviteForm'),
  pass: $('#passForm'),
  email: $('#emailLoginForm'),
  register: $('#registerForm'),
  verify: $('#verifyForm'),
  shared: $('#sharedForm'),
};

let methods = {
  emailAuth: false,
  googleOAuth: false,
  githubOAuth: false,
  inviteRequired: false,
  sharedPassword: true,
  guestPass: true,
};
let pendingEmail = '';
let currentView = 'social';

function nextUrl() {
  const next = new URLSearchParams(location.search).get('next') || '/';
  return next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
}

function showError(text) {
  infoEl.hidden = true;
  errorEl.textContent = text;
  errorEl.hidden = false;
}

function showInfo(text) {
  errorEl.hidden = true;
  infoEl.textContent = text;
  infoEl.hidden = false;
}

function clearMessages() {
  errorEl.hidden = true;
  infoEl.hidden = true;
}

function switchView(name) {
  currentView = name;
  clearMessages();

  const isAdminView = name === 'shared';
  const isSubView = isAdminView || name === 'oauthInvite' || name === 'verify';
  tabsEl.hidden = isSubView;

  $('#loginTitle').textContent = isAdminView ? '관리자 로그인' : '로그인';
  $('#loginSub').textContent = isAdminView
    ? '관리자 전용 비밀번호로 입장합니다.'
    : '사용할 로그인 방법을 선택하세요.';

  if (methods.sharedPassword) {
    adminBtn.textContent = isAdminView ? '← 일반 로그인' : '관리자로 로그인';
  }

  for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
  for (const btn of tabsEl.querySelectorAll('button[data-tab]')) {
    btn.classList.toggle('active', btn.dataset.tab === name);
  }

  const focusable = views[name]?.querySelector('input:not([hidden]):not(:disabled)');
  focusable?.focus();
}

async function init() {
  try {
    const res = await fetch('/api/auth/methods', { cache: 'no-store' });
    if (res.ok) methods = await res.json();
  } catch { /* 기본값 사용 */ }

  const next = encodeURIComponent(nextUrl());

  // Google / GitHub 버튼 구성 (연동된 소셜 버튼만 깔끔하게 표시)
  googleBtn.href = `/api/auth/oauth/google?next=${next}`;
  githubBtn.href = `/api/auth/oauth/github?next=${next}`;
  const anySocial = methods.googleOAuth || methods.githubOAuth;
  if (anySocial) {
    googleBtn.hidden = !methods.googleOAuth;
    githubBtn.hidden = !methods.githubOAuth;
  } else {
    googleBtn.hidden = false;
    googleBtn.classList.add('disabled');
    googleBtn.addEventListener('click', (e) => {
      e.preventDefault();
      showError('소셜 로그인이 아직 설정되지 않았습니다. 관리자는 오른쪽 위 "관리자로 로그인"을 이용하세요.');
    });
    githubBtn.hidden = true;
  }
  oauthHintEl.hidden = anySocial;

  // 탭 노출 설정 (비밀번호/이메일 회원가입은 활성화되었을 때만 보조 탭 표시)
  const setTab = (tab, visible) => {
    const b = tabsEl.querySelector(`button[data-tab="${tab}"]`);
    if (b) b.hidden = !visible;
  };
  setTab('pass', methods.guestPass);
  setTab('email', methods.emailAuth);
  setTab('register', methods.emailAuth);

  const inviteInput = $('#regInvite');
  inviteInput.hidden = !methods.inviteRequired;
  inviteInput.required = !!methods.inviteRequired;

  // 오른쪽 위 작은 '관리자로 로그인' 버튼
  adminBtn.hidden = !methods.sharedPassword;
  adminBtn.addEventListener('click', () => {
    switchView(currentView === 'shared' ? 'social' : 'shared');
  });
  $('#backFromAdminBtn').addEventListener('click', () => switchView('social'));
  $('#cancelOAuthInviteBtn').addEventListener('click', () => switchView('social'));

  tabsEl.addEventListener('click', (e) => {
    const tab = e.target.closest('button[data-tab]')?.dataset.tab;
    if (tab) switchView(tab);
  });

  // URL 쿼리 파라미터 처리 (?oauth_error= / ?oauth_invite=1 / ?pass=)
  const params = new URLSearchParams(location.search);
  const oauthError = params.get('oauth_error');
  const oauthInvite = params.get('oauth_invite');
  const oauthEmail = params.get('email');
  const passFromUrl = params.get('pass');

  if (oauthError) {
    params.delete('oauth_error');
    cleanQuery(params);
    switchView('social');
    showError(oauthError);
    return;
  }

  if (oauthInvite === '1') {
    params.delete('oauth_invite');
    params.delete('email');
    cleanQuery(params);
    $('#oauthInviteDesc').textContent = oauthEmail
      ? `${oauthEmail} 계정으로 처음 로그인합니다. 초대 코드를 1회만 입력하면 다음부터 바로 입장할 수 있습니다.`
      : '처음 로그인하는 소셜 계정입니다. 초대 코드를 1회 입력해 주세요.';
    switchView('oauthInvite');
    return;
  }

  if (passFromUrl && methods.guestPass) {
    params.delete('pass');
    cleanQuery(params);
    switchView('pass');
    $('#passCode').value = passFromUrl.toUpperCase();
    await submitPass(passFromUrl);
    return;
  }

  switchView('social');
}

function cleanQuery(params) {
  const qs = params.toString();
  history.replaceState(null, '', qs ? `${location.pathname}?${qs}` : location.pathname);
}

// ---------------------------------------------------------------- 첫 소셜 로그인 초대코드 완료
views.oauthInvite.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = views.oauthInvite.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/oauth/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inviteCode: $('#oauthInviteCode').value.trim() }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { location.replace(data.next || nextUrl()); return; }
    showError(data.error || '초대 코드 확인에 실패했습니다.');
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- 이메일 로그인 (선택 활성화 시)
views.email.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = views.email.querySelector('button[type="submit"]');
  btn.disabled = true;
  const email = $('#loginEmail').value.trim();
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: $('#loginPassword').value }),
    });
    if (res.status === 204) { location.replace(nextUrl()); return; }
    const data = await res.json().catch(() => ({}));
    if (res.status === 403 && data.error === 'email_not_verified') {
      openVerify(email, data.message || '이메일 인증 코드를 입력해 주세요.');
      return;
    }
    showError(data.error || `로그인 실패 (${res.status})`);
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- 이메일 회원가입 (선택 활성화 시)
views.register.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = views.register.querySelector('button[type="submit"]');
  btn.disabled = true;
  const email = $('#regEmail').value.trim();
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password: $('#regPassword').value,
        inviteCode: $('#regInvite').value.trim(),
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 201) {
      openVerify(data.email || email, `${data.email || email} 로 6자리 인증 코드를 보냈습니다. (10분간 유효)`);
      return;
    }
    showError(data.error || `회원가입 실패 (${res.status})`);
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

function openVerify(email, desc) {
  pendingEmail = email;
  $('#verifyDesc').textContent = desc;
  $('#verifyCode').value = '';
  switchView('verify');
}

views.verify.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = views.verify.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingEmail, code: $('#verifyCode').value.trim() }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { location.replace(nextUrl()); return; }
    showError(data.error || '인증에 실패했습니다.');
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

$('#resendBtn').addEventListener('click', async () => {
  clearMessages();
  const btn = $('#resendBtn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/resend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingEmail }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) showInfo('인증 메일을 다시 보냈습니다.');
    else showError(data.error || '재발송에 실패했습니다.');
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

$('#backToLoginBtn').addEventListener('click', () => switchView('email'));

// ---------------------------------------------------------------- 관리자 비밀번호 로그인
views.shared.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = views.shared.querySelector('button[type="submit"]');
  const input = $('#sharedPassword');
  btn.disabled = true;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: input.value }),
    });
    if (res.status === 204) { location.replace(nextUrl()); return; }
    if (res.status === 429) showError('로그인 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.');
    else if (res.status === 401) showError('관리자 비밀번호가 틀렸습니다.');
    else showError(`로그인 실패 (${res.status})`);
    input.select();
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- 특별 코드 (10분 임시 패스)
async function submitPass(code) {
  clearMessages();
  const btn = views.pass.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/pass', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: String(code || '').trim() }),
    });
    if (res.status === 204) { location.replace(nextUrl()); return; }
    const data = await res.json().catch(() => ({}));
    showError(data.error || '유효하지 않거나 만료된 특별 코드입니다.');
    $('#passCode').select();
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    btn.disabled = false;
  }
}

views.pass.addEventListener('submit', (e) => {
  e.preventDefault();
  submitPass($('#passCode').value);
});

init();
