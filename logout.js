const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, sessionCookie, readJsonBody } = require('./_utils');

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });
  if (!process.env.JWT_SECRET) return json(500, { error: 'Server is not configured (missing JWT_SECRET).' });

  const body = await readJsonBody(req);
  const { token } = body;
  if (!token) return json(400, { error: 'Missing verification token.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    await ensureSchema();
    const pool = getPool();

    const result = await pool.query(
      `select id, user_id, expires_at, used from email_verifications where token_hash = $1`,
      [tokenHash]
    );
    const verification = result.rows[0];

    if (!verification || verification.used || new Date(verification.expires_at) < new Date()) {
      return json(400, { error: 'This confirmation link is invalid or has expired. You can request a new one from the login screen.' });
    }

    const userResult = await pool.query(
      'update users set email_verified = true where id = $1 returning id, email',
      [verification.user_id]
    );
    const user = userResult.rows[0];
    if (!user) return json(400, { error: 'This confirmation link is no longer valid.' });

    await pool.query('update email_verifications set used = true where id = $1', [verification.id]);

    // Verifying also logs the person in — one less step after confirming.
    const sessionToken = jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    return json(200, { user: { id: user.id, email: user.email } }, { 'Set-Cookie': sessionCookie(sessionToken) });
  } catch (err) {
    console.error('verify-email error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
