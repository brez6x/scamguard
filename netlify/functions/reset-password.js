const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getPool } = require('./_db');
const { json } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Invalid request body.' }); }

  const { token, newPassword } = body;
  if (!token || !newPassword) return json(400, { error: 'Missing token or new password.' });
  if (newPassword.length < 8) return json(400, { error: 'Password must be at least 8 characters.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const pool = getPool();
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
