const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, getSessionToken, readJsonBody } = require('./_utils');

/* =====================================================================
   Logged-in management of developer API keys. The raw key is only ever
   shown once, right after creation — only its sha256 hash and a short
   display prefix are stored, same pattern as password reset tokens.
   ===================================================================== */

const MAX_KEYS_PER_USER = 5;

function requireUser(req) {
  const token = getSessionToken(req);
  if (!token || !process.env.JWT_SECRET) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

function generateApiKey() {
  const raw = `sg_live_${crypto.randomBytes(24).toString('hex')}`;
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const prefix = raw.slice(0, 14);
  return { raw, hash, prefix };
}

exports.default = async (req) => {
  const user = requireUser(req);
  if (!user) return json(401, { error: 'Not logged in.' });

  await ensureSchema();
  const pool = getPool();

  if (req.method === 'GET') {
    try {
      const result = await pool.query(
        `select id, label, key_prefix, revoked, last_used_at, created_at
         from api_keys where user_id = $1 order by created_at desc`,
        [user.sub]
      );
      return json(200, { keys: result.rows });
    } catch (err) {
      console.error('api-keys GET error', err);
      return json(500, { error: 'Could not load your API keys.' });
    }
  }

  if (req.method === 'POST') {
    const body = await readJsonBody(req);
    const label = (body.label || 'API Key').trim().slice(0, 60) || 'API Key';
    try {
      const countResult = await pool.query('select count(*)::int as n from api_keys where user_id = $1 and revoked = false', [user.sub]);
      if (countResult.rows[0].n >= MAX_KEYS_PER_USER) {
        return json(400, { error: `You can have up to ${MAX_KEYS_PER_USER} active API keys. Revoke one before creating another.` });
      }
      const { raw, hash, prefix } = generateApiKey();
      const result = await pool.query(
        `insert into api_keys (user_id, label, key_hash, key_prefix) values ($1,$2,$3,$4)
         returning id, label, key_prefix, revoked, last_used_at, created_at`,
        [user.sub, label, hash, prefix]
      );
      return json(200, { key: result.rows[0], rawKey: raw });
    } catch (err) {
      console.error('api-keys POST error', err);
      return json(500, { error: 'Could not create an API key.' });
    }
  }

  if (req.method === 'DELETE') {
    const body = await readJsonBody(req);
    if (!body.id) return json(400, { error: 'Missing key id.' });
    try {
      await pool.query('update api_keys set revoked = true where id = $1 and user_id = $2', [body.id, user.sub]);
      return json(200, { ok: true });
    } catch (err) {
      console.error('api-keys DELETE error', err);
      return json(500, { error: 'Could not revoke that key.' });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
