const { Pool } = require('pg');

let pool;

// Netlify's built-in Postgres (Neon) sets NETLIFY_DATABASE_URL automatically
// once you add it from Site configuration -> Database. Falls back to a plain
// DATABASE_URL if you're using your own Postgres instead.
function getPool() {
  if (!pool) {
    const connectionString = process.env.NETLIFY_DATABASE_URL || process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error('No database configured. Add Netlify Postgres (Neon) or set DATABASE_URL.');
    }
    pool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
    });
  }
  return pool;
}

module.exports = { getPool };
