const { json, clearSessionCookie } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  return json(200, { ok: true }, { 'Set-Cookie': clearSessionCookie() });
};
