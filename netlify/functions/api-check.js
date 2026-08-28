const crypto = require('crypto');
const { getPool, ensureSchema } = require('./_db');
const { json, readJsonBody } = require('./_utils');
const { rateLimitOrNull } = require('./_rateLimit');
const { runChecks } = require('./_scan');

/* =====================================================================
   Public API endpoint for developers: POST { "url": "..." } with
   header  Authorization: Bearer sg_live_...
   Runs the exact same checks as the website's own scanner.
   ===================================================================== */

const HOURLY_LIMIT = 60;

function extractKey(req) {
  const header = req.headers.get('authorization') || '';
  const match = header.match(/^Bearer\s+(\S+)/i);
  return match ? match[1] : null;
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed. Use POST.' });

  const rawKey = extractKey(req);
  if (!rawKey) return json(401, { error: 'Missing API key. Send it as: Authorization: Bearer sg_live_...' });

  await ensureSchema();
  const pool = getPool();

  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  let keyRow;
  try {
    const result = await pool.query(
      'select id, user_id, revoked from api_keys where key_hash = $1',
      [keyHash]
    );
    keyRow = result.rows[0];
  } catch (err) {
    console.error('api-check key lookup error', err);
    return json(500, { error: 'Internal error validating API key.' });
  }

  if (!keyRow || keyRow.revoked) {
    return json(401, { error: 'Invalid or revoked API key.' });
  }

  const limited = await rateLimitOrNull(
    pool,
    `api-key:${keyRow.id}`,
    HOURLY_LIMIT,
    60 * 60,
    `Rate limit exceeded (${HOURLY_LIMIT} requests/hour per key).`
  );
  if (limited) return limited;

  const body = await readJsonBody(req);
  const rawUrl = body.url;
  if (!rawUrl || typeof rawUrl !== 'string') return json(400, { error: 'Missing "url" in request body.' });

  pool.query('update api_keys set last_used_at = now() where id = $1', [keyRow.id]).catch(() => {});

  const result = await runChecks(rawUrl);
  if (result.error) return json(400, { error: result.error });

  const { url, ...rest } = result;
  return json(200, { url, ...rest });
};
