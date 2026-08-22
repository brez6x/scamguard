const crypto = require('crypto');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail } = require('./_utils');

// IMPORTANT: this endpoint creates a reset token but does NOT send an email yet —
// no email provider is connected. Wire in an email service (e.g. Resend, SendGrid,
// Postmark) before relying on this in production: send an email containing a link
// like https://yoursite.com/reset?token=<rawToken>&email=<email>, then call
// reset-password.js with that token. Never return the raw token in this response —
// that would let anyone reset anyone's password.

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Invalid request body.' }); }

  const email = (body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return json(400, { error: 'Enter a valid email address.' });

  const genericResponse = { message: 'If an account exists for that email, a reset link has been sent.' };

  try {
    await ensureSchema();
    const pool = getPool();
    const result = await pool.query('select id from users where email = $1', [email]);
    const user = result.rows[0];

    // Always return the same generic response whether or not the account exists,
    // so this endpoint can't be used to check which emails are registered.
    if (!user) return json(200, genericResponse);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    await pool.query(
      'insert into password_resets (user_id, token_hash, expires_at) values ($1, $2, $3)',
      [user.id, tokenHash, expiresAt]
    );

    // TODO: send `rawToken` via email once an email provider is connected.
    // Example: await sendEmail(email, `Reset your ScamGuard password: https://yoursite.com/reset?token=${rawToken}`);
    console.log('Password reset token generated for', email, '(email delivery not yet connected)');

    return json(200, genericResponse);
  } catch (err) {
    console.error('request-password-reset error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
