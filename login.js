const crypto = require('crypto');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');
const { sendEmail, emailShell } = require('./_email');

// SITE_URL should be your live site's URL (e.g. https://scamguard.store) so
// the link in the email points to the right place — falls back to a
// relative-looking placeholder if not set, which still works as long as the
// person opens the email from the same site.
async function sendResetEmail(email, rawToken) {
  const siteUrl = process.env.SITE_URL || 'https://scamguard.store';
  const resetLink = `${siteUrl}/?reset=1&token=${encodeURIComponent(rawToken)}`;

  return sendEmail({
    to: email,
    subject: 'Reset your ScamGuard password',
    html: emailShell('Reset your ScamGuard password', `
      <p>We received a request to reset the password for this email address. This link expires in 30 minutes.</p>
      <p><a href="${resetLink}" style="display:inline-block; background:#3fb8ed; color:#04121A; padding:12px 20px; border-radius:8px; text-decoration:none; font-weight:bold;">Reset Password</a></p>
      <p style="color:#64748b; font-size:13px;">If you didn't request this, you can safely ignore this email — your password won't change.</p>
    `),
  });
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const email = (body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return json(400, { error: 'Enter a valid email address.' });

  const genericResponse = { message: 'If an account exists for that email, a reset link has been sent.' };

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `pwreset-request:${ip}`,
      5,
      60 * 60,
      'Too many password reset requests. Please wait a while and try again.'
    );
    if (limited) return limited;

    const result = await pool.query('select id from users where email = $1', [email]);
    const user = result.rows[0];

    // Always the same response whether or not the account exists — never reveal
    // which emails are registered.
    if (!user) return json(200, genericResponse);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    await pool.query(
      'insert into password_resets (user_id, token_hash, expires_at) values ($1, $2, $3)',
      [user.id, tokenHash, expiresAt]
    );

    await sendResetEmail(email, rawToken);

    return json(200, genericResponse);
  } catch (err) {
    console.error('request-password-reset error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
