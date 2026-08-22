const jwt = require('jsonwebtoken');
const { json, getSessionToken } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method not allowed' });

  const token = getSessionToken(event);
  if (!token || !process.env.JWT_SECRET) return json(200, { user: null });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return json(200, { user: { id: payload.sub, email: payload.email } });
  } catch {
    return json(200, { user: null });
  }
};
