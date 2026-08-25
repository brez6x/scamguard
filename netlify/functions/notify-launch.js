const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');

const VALID_PLANS = new Set(['pro', 'business']);

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const plan = (body.plan || '').trim().toLowerCase();
  const emailRaw = (body.email || '').trim().toLowerCase();

  if (!VALID_PLANS.has(plan)) return json(400, { error: 'Unknown plan.' });
  if (emailRaw && !isValidEmail(emailRaw)) return json(400, { error: 'That email address doesn’t look valid.' });

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `waitlist:${ip}`,
      10,
      60 * 60,
      'Too many requests. Please wait a while and try again.'
    );
    if (limited) return limited;

    await pool.query(
      'insert into waitlist (plan, email) values ($1, $2)',
      [plan, emailRaw || null]
    );

    return json(200, { message: 'Thanks — we\'ll email you when it launches!' });
  } catch (err) {
    console.error('notify-launch error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
