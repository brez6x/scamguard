const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const message = (body.message || '').trim();
  const emailRaw = (body.email || '').trim().toLowerCase();

  if (message.length < 5) return json(400, { error: 'Tell us a bit more — at least a few words.' });
  if (message.length > 2000) return json(400, { error: 'That\'s a bit long (max 2000 characters). Please shorten it.' });
  if (emailRaw && !isValidEmail(emailRaw)) return json(400, { error: 'That email address doesn’t look valid.' });

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `suggestion:${ip}`,
      10,
      60 * 60,
      'Too many suggestions submitted. Please wait a while and try again.'
    );
    if (limited) return limited;

    await pool.query(
      'insert into suggestions (message, contact_email) values ($1, $2)',
      [message, emailRaw || null]
    );

    return json(200, { message: 'Thanks — your suggestion was submitted!' });
  } catch (err) {
    console.error('submit-suggestion error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
