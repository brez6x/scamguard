const { json, clearSessionCookie } = require('./_utils');

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });
  return json(200, { ok: true }, { 'Set-Cookie': clearSessionCookie() });
};
