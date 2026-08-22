const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, sessionCookie } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Invalid request body.' }); }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!isValidEmail(email)) return json(400, { error: 'Enter a valid email address.' });
  if (password.length < 8) return json(400, { error: 'Password must be at least 8 characters.' });
  if (!process.env.JWT_SECRET) return json(500, { error: 'Server is not configured (missing JWT_SECRET).' });

  try {
    await ensureSchema();
    const pool = getPool();
    const existing = await pool.query('select id from users where email = $1', [email]);
    if (existing.rows.length) return json(409, { error: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'insert into users (email, password_hash) values ($1, $2) returning id, email, created_at',
      [email, passwordHash]
    );
    const user = result.rows[0];

    const token = jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    return json(200, { user: { id: user.id, email: user.email } }, { 'Set-Cookie': sessionCookie(token) });
  } catch (err) {
    console.error('signup error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
