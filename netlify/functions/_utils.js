const cookie = require('cookie');

function json(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
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

function getSessionToken(req) {
  const header = req.headers.get('cookie') || '';
  const parsed = cookie.parse(header);
  return parsed.sg_session || null;
}

async function readJsonBody(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

module.exports = { json, isValidEmail, sessionCookie, clearSessionCookie, getSessionToken, readJsonBody };
