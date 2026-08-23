const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getPool, ensureSchema } = require('./_db');
const { json, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const { token, newPassword } = body;
  if (!token || !newPassword) return json(400, { error: 'Missing token or new password.' });
  if (newPassword.length < 8) return json(400, { error: 'Password must be at least 8 characters.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `pwreset-confirm:${ip}`,
      15,
      60 * 60,
      'Too many attempts. Please wait a while and try again.'
    );
    if (limited) return limited;

    const result = await pool.query(
      `select id, user_id, expires_at, used from password_resets where token_hash = $1`,
      [tokenHash]
    );
    const reset = result.rows[0];

    if (!reset || reset.used || new Date(reset.expires_at) < new Date()) {
      return json(400, { error: 'This reset link is invalid or has expired.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query('update users set password_hash = $1 where id = $2', [passwordHash, reset.user_id]);
    await pool.query('update password_resets set used = true where id = $1', [reset.id]);

    return json(200, { message: 'Password updated. You can now log in with your new password.' });
  } catch (err) {
    console.error('reset-password error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
