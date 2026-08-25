const crypto = require('crypto');
const bcrypt = require('bcryptjs');
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
      <p>Thanks for signing up for ScamGuard. Click below to confirm this is your email address and activate your account. This link expires in 24 hours.</p>
      <p><a href="${verifyLink}" style="display:inline-block; background:#3fb8ed; color:#04121A; padding:12px 20px; border-radius:8px; text-decoration:none; font-weight:bold;">Confirm Email</a></p>
      <p style="color:#64748b; font-size:13px;">If you didn't create a ScamGuard account, you can safely ignore this email.</p>
    `),
  });
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!isValidEmail(email)) return json(400, { error: 'Enter a valid email address.' });
  if (password.length < 8) return json(400, { error: 'Password must be at least 8 characters.' });
  if (!process.env.JWT_SECRET) return json(500, { error: 'Server is not configured (missing JWT_SECRET).' });

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `signup:${ip}`,
      8,
      60 * 60,
      'Too many signup attempts from this connection. Please wait a while and try again.'
    );
    if (limited) return limited;

    const existing = await pool.query('select id from users where email = $1', [email]);
    if (existing.rows.length) return json(409, { error: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'insert into users (email, password_hash, email_verified) values ($1, $2, false) returning id, email',
      [email, passwordHash]
    );
    const user = result.rows[0];

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await pool.query(
      'insert into email_verifications (user_id, token_hash, expires_at) values ($1, $2, $3)',
      [user.id, tokenHash, expiresAt]
    );

    await sendVerificationEmail(email, rawToken);

    // No session cookie yet — the account isn't active until the email is confirmed.
    return json(200, {
      pendingVerification: true,
      message: 'Almost there — check your email and click the confirmation link to activate your account.',
    });
  } catch (err) {
    console.error('signup error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
