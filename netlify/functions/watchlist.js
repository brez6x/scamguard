const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, getSessionToken, readJsonBody } = require('./_utils');

const MAX_SITES_PER_USER = 10;

function requireUser(req) {
  const token = getSessionToken(req);
  if (!token || !process.env.JWT_SECRET) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

exports.default = async (req) => {
  const user = requireUser(req);
  if (!user) return json(401, { error: 'Not logged in.' });

  await ensureSchema();
  const pool = getPool();

  if (req.method === 'GET') {
    try {
      const result = await pool.query(
        `select id, url, label, last_flagged, last_redirect_domain, last_checked_at, last_check_error, created_at
         from watchlist_sites where user_id = $1 order by created_at desc`,
        [user.sub]
      );
      return json(200, { sites: result.rows });
    } catch (err) {
      console.error('watchlist GET error', err);
      return json(500, { error: 'Could not load your watchlist.' });
    }
  }

  if (req.method === 'POST') {
    const body = await readJsonBody(req);
    const rawUrl = (body.url || '').trim();
    const label = (body.label || '').trim().slice(0, 80);

    let target;
    try {
      target = new URL(rawUrl);
    } catch {
      return json(400, { error: 'Enter a valid URL, including https://' });
    }
    if (!['http:', 'https:'].includes(target.protocol)) {
      return json(400, { error: 'Only http/https URLs are supported.' });
    }

    try {
      const countResult = await pool.query('select count(*)::int as n from watchlist_sites where user_id = $1', [user.sub]);
      if (countResult.rows[0].n >= MAX_SITES_PER_USER) {
        return json(400, { error: `You can watch up to ${MAX_SITES_PER_USER} sites. Remove one before adding another.` });
      }
      const result = await pool.query(
        `insert into watchlist_sites (user_id, url, label) values ($1, $2, $3)
         returning id, url, label, last_flagged, last_redirect_domain, last_checked_at, last_check_error, created_at`,
        [user.sub, target.toString(), label || null]
      );
      return json(200, { site: result.rows[0] });
    } catch (err) {
      console.error('watchlist POST error', err);
      return json(500, { error: 'Could not add that site to your watchlist.' });
    }
  }

  if (req.method === 'DELETE') {
    const body = await readJsonBody(req);
    if (!body.id) return json(400, { error: 'Missing site id.' });
    try {
      await pool.query('delete from watchlist_sites where id = $1 and user_id = $2', [body.id, user.sub]);
      return json(200, { ok: true });
    } catch (err) {
      console.error('watchlist DELETE error', err);
      return json(500, { error: 'Could not remove that site.' });
    }
  }

  return json(405, { error: 'Method not allowed' });
};
