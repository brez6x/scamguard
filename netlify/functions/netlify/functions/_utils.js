const cookie = require('cookie');

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  };
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sessionCookie(token) {
  return cookie.serialize('sg_session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7, // 7 days
  });
}

function clearSessionCookie() {
  return cookie.serialize('sg_session', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

function getSessionToken(event) {
  const header = event.headers.cookie || event.headers.Cookie || '';
  const parsed = cookie.parse(header);
  return parsed.sg_session || null;
}

module.exports = { json, isValidEmail, sessionCookie, clearSessionCookie, getSessionToken };
