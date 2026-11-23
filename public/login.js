const form = document.querySelector('#loginForm');
const input = document.querySelector('#password');
const errorEl = document.querySelector('#error');

// 로그인 후 돌아갈 주소 (같은 사이트 내부 경로만 허용 — open redirect 방지)
function nextUrl() {
  const next = new URLSearchParams(location.search).get('next') || '/';
  return next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
}

function showError(text) {
  errorEl.textContent = text;
  errorEl.hidden = false;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorEl.hidden = true;
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: input.value }),
    });
    if (res.status === 204) {
      location.replace(nextUrl());
      return;
    }
    if (res.status === 429) showError('로그인 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.');
    else if (res.status === 401) showError('비밀번호가 틀렸습니다.');
    else showError(`로그인 실패 (${res.status})`);
    input.select();
  } catch {
    showError('서버에 연결할 수 없습니다.');
  } finally {
    button.disabled = false;
  }
});
