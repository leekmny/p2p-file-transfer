const $ = (s) => document.querySelector(s);

const errorEl = $('#error');
const infoEl = $('#info');
const tabsEl = $('#tabs');

const forms = {
  email: $('#emailLoginForm'),
  register: $('#registerForm'),
  verify: $('#verifyForm'),
  shared: $('#sharedForm'),
  pass: $('#passForm'),
};

let methods = { emailAuth: false, inviteRequired: false, sharedPassword: true, guestPass: true };
let pendingEmail = '';

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

function switchTab(name) {
  clearMessages();
  for (const [k, form] of Object.entries(forms)) form.hidden = k !== name;
  for (const btn of tabsEl.querySelectorAll('button[data-tab]')) {
    btn.classList.toggle('active', btn.dataset.tab === name);
  }
  const focusable = forms[name]?.querySelector('input:not([hidden])');
  focusable?.focus();
}

async function init() {
  try {
    const res = await fetch('/api/auth/methods', { cache: 'no-store' });
    if (res.ok) methods = await res.json();
  } catch { /* 기본값 사용 */ }

  const visibleTabs = [];
  const showBtn = (name) => {
    const b = tabsEl.querySelector(`button[data-tab="${name}"]`);
    if (b) { b.hidden = false; visibleTabs.push(name); }
  };

  if (methods.emailAuth) {
    showBtn('email');
    showBtn('register');
    const inviteInput = $('#regInvite');
    inviteInput.hidden = !methods.inviteRequired;
    inviteInput.required = !!methods.inviteRequired;
  }
  if (methods.sharedPassword) showBtn('shared');
  if (methods.guestPass) showBtn('pass');

  tabsEl.hidden = visibleTabs.length <= 1;
  tabsEl.addEventListener('click', (e) => {
    const tab = e.target.closest('button[data-tab]')?.dataset.tab;
    if (tab) switchTab(tab);
  });

  // ?pass=XXXX-XXXX 링크로 들어온 경우 URL에서 즉시 제거 후 바로 입장 시도
  const params = new URLSearchParams(location.search);
  const passFromUrl = params.get('pass');
  if (passFromUrl && methods.guestPass) {
    params.delete('pass');
    const clean = params.toString();
    history.replaceState(null, '', clean ? `${location.pathname}?${clean}` : location.pathname);
    switchTab('pass');
    $('#passCode').value = passFromUrl.toUpperCase();
    await submitPass(passFromUrl);
    return;
  }

  switchTab(visibleTabs[0] || 'shared');
}

// ---------------------------------------------------------------- 이메일 로그인
forms.email.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = forms.email.querySelector('button[type="submit"]');
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

// ---------------------------------------------------------------- 회원가입
forms.register.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = forms.register.querySelector('button[type="submit"]');
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
  switchTab('verify');
}

// ---------------------------------------------------------------- 이메일 인증 확인
forms.verify.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = forms.verify.querySelector('button[type="submit"]');
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

$('#backToLoginBtn').addEventListener('click', () => switchTab('email'));

// ---------------------------------------------------------------- 공유 비밀번호 로그인
forms.shared.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const btn = forms.shared.querySelector('button[type="submit"]');
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
    else if (res.status === 401) showError('비밀번호가 틀렸습니다.');
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
  const btn = forms.pass.querySelector('button[type="submit"]');
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

forms.pass.addEventListener('submit', (e) => {
  e.preventDefault();
  submitPass($('#passCode').value);
});

init();
