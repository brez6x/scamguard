const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, readJsonBody } = require('./_utils');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');

function normalizeUrl(raw) {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;
  // Let people paste a bare domain like "scam-site.com" without a protocol.
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!u.hostname || !u.hostname.includes('.')) return null;
    return u.href;
  } catch {
    return null;
  }
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const url = normalizeUrl(body.url);
  const reasonRaw = (body.reason || '').trim();
  const emailRaw = (body.email || '').trim().toLowerCase();

  if (!url) return json(400, { error: 'Enter a valid website address to report.' });
  if (reasonRaw.length > 1000) return json(400, { error: 'Reason is too long (max 1000 characters).' });
  if (emailRaw && !isValidEmail(emailRaw)) return json(400, { error: 'That email address doesn’t look valid.' });

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `report:${ip}`,
      10,
      60 * 60,
      'Too many reports submitted. Please wait a while and try again.'
    );
    if (limited) return limited;

    await pool.query(
      'insert into reports (url, reason, reporter_email) values ($1, $2, $3)',
      [url, reasonRaw || null, emailRaw || null]
    );

    return json(200, { message: 'Thanks — your report was submitted and will be reviewed.' });
  } catch (err) {
    console.error('report-website error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
