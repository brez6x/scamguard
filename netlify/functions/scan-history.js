const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, getSessionToken } = require('./_utils');

function requireUser(event) {
  const token = getSessionToken(event);
  if (!token || !process.env.JWT_SECRET) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

exports.handler = async (event) => {
  const user = requireUser(event);
  if (!user) return json(401, { error: 'Not logged in.' });

  await ensureSchema();
  const pool = getPool();

  if (event.httpMethod === 'GET') {
    try {
      const result = await pool.query(
        'select id, domain, score, risk_level, warnings, positives, created_at from scans where user_id = $1 order by created_at desc limit 50',
        [user.sub]
      );
      return json(200, { scans: result.rows });
    } catch (err) {
      console.error('scan-history GET error', err);
      return json(500, { error: 'Could not load scan history.' });
    }
  }

  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Invalid request body.' }); }
    const { domain, score, riskLevel, warnings, positives } = body;
    if (!domain || typeof score !== 'number' || !riskLevel) return json(400, { error: 'Missing scan data.' });
    try {
      await pool.query(
        'insert into scans (user_id, domain, score, risk_level, warnings, positives) values ($1,$2,$3,$4,$5,$6)',
        [user.sub, domain, score, riskLevel, warnings || 0, positives || 0]
      );
      return json(200, { ok: true });
    } catch (err) {
      console.error('scan-history POST error', err);
      return json(500, { error: 'Could not save scan.' });
    }
  }

  if (event.httpMethod === 'DELETE') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Invalid request body.' }); }
    if (!body.id) return json(400, { error: 'Missing scan id.' });
    try {
      await pool.query('delete from scans where id = $1 and user_id = $2', [body.id, user.sub]);
      return json(200, { ok: true });
    } catch (err) {
      console.error('scan-history DELETE error', err);
      return json(500, { error: 'Could not delete scan.' });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
