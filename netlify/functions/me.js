const jwt = require('jsonwebtoken');
const { json, getSessionToken } = require('./_utils');

exports.default = async (req) => {
  if (req.method !== 'GET') return json(405, { error: 'Method not allowed' });

  const token = getSessionToken(req);
  if (!token || !process.env.JWT_SECRET) return json(200, { user: null });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return json(200, { user: { id: payload.sub, email: payload.email } });
  } catch {
    return json(200, { user: null });
  }
};
