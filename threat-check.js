const crypto = require('crypto');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');
const { sendEmail, emailShell } = require('./_email');

async function sendVerificationEmail(email, rawToken) {
  const siteUrl = process.env.SITE_URL || 'https://scamguard.store';
  const verifyLink = `${siteUrl}/?verify=1&token=${encodeURIComponent(rawToken)}`;

  return sendEmail({
    to: email,
    subject: 'Confirm your ScamGuard account',
    html: emailShell('Confirm your email', `
      <p>Here's a new confirmation link for your ScamGuard account. This link expires in 24 hours.</p>
      <p><a href="${verifyLink}" style="display:inline-block; background:#3fb8ed; color:#04121A; padding:12px 20px; border-radius:8px; text-decoration:none; font-weight:bold;">Confirm Email</a></p>
      <p style="color:#64748b; font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
    `),
  });
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const email = (body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return json(400, { error: 'Enter a valid email address.' });

  const genericResponse = { message: 'If that account exists and still needs verifying, a new confirmation link has been sent.' };

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `resend-verify:${ip}`,
      5,
      60 * 60,
      'Too many requests. Please wait a while and try again.'
    );
    if (limited) return limited;

    const result = await pool.query('select id, email_verified from users where email = $1', [email]);
    const user = result.rows[0];

    // Same generic response whether the account doesn't exist or is already
    // verified — never reveal which emails are registered.
    if (!user || user.email_verified) return json(200, genericResponse);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await pool.query(
      'insert into email_verifications (user_id, token_hash, expires_at) values ($1, $2, $3)',
      [user.id, tokenHash, expiresAt]
    );

    await sendVerificationEmail(email, rawToken);

    return json(200, genericResponse);
  } catch (err) {
    console.error('resend-verification error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
