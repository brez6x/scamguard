const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getPool, ensureSchema } = require('./_db');
const { json, isValidEmail, sessionCookie, readJsonBody } = require('./_utils');

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!isValidEmail(email) || !password) return json(400, { error: 'Enter your email and password.' });
  if (!process.env.JWT_SECRET) return json(500, { error: 'Server is not configured (missing JWT_SECRET).' });

  try {
    await ensureSchema();
    const pool = getPool();
    const result = await pool.query('select id, email, password_hash from users where email = $1', [email]);
    const user = result.rows[0];

    // Same generic error whether the email doesn't exist or the password is wrong —
    // prevents confirming which emails have accounts.
    if (!user) return json(401, { error: 'Incorrect email or password.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return json(401, { error: 'Incorrect email or password.' });

    const token = jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    return json(200, { user: { id: user.id, email: user.email } }, { 'Set-Cookie': sessionCookie(token) });
  } catch (err) {
    console.error('login error', err);
    return json(500, { error: 'Something went wrong. Please try again.' });
  }
};
