const crypto = require('crypto');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');

// Sends the actual reset email via Resend (https://resend.com). Requires
// RESEND_API_KEY to be set. SITE_URL should be your live site's URL (e.g.
// https://scamguard.store) so the link in the email points to the right place —
// falls back to a relative-looking placeholder if not set, which still works
// as long as the person opens the email from the same site.
async function sendResetEmail(email, rawToken) {
  const siteUrl = process.env.SITE_URL || 'https://scamguard.store';
  const resetLink = `${siteUrl}/?reset=1&token=${encodeURIComponent(rawToken)}`;

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log('RESEND_API_KEY not set — cannot send reset email. Link would have been:', resetLink);
    return { sent: false };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM || 'ScamGuard <noreply@scamguard.store>',
      to: [email],
      subject: 'Reset your ScamGuard password',
      html: `
        <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
          <h2 style="color:#0f172a;">Reset your ScamGuard password</h2>
          <p>We received a request to reset the password for this email address. This link expires in 30 minutes.</p>
          <p><a href="${resetLink}" style="display:inline-block; background:#3fb8ed; color:#04121A; padding:12px 20px; border-radius:8px; text-decoration:none; font-weight:bold;">Reset Password</a></p>
          <p style="color:#64748b; font-size:13px;">If you didn't request this, you can safely ignore this email — your password won't change.</p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    console.error('Resend API error', res.status, errText);
    return { sent: false };
  }
  return { sent: true };
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
