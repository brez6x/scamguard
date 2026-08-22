const { Pool } = require('pg');

// Netlify only auto-injects the database connection into Functions when the
// @netlify/database package is present as a dependency (see package.json).
// Its getConnectionString() helper is the most reliable way to read it;
// we fall back to raw env vars in case that package isn't resolvable.
let getConnectionStringHelper = null;
try {
  getConnectionStringHelper = require('@netlify/database').getConnectionString;
} catch (e) {
  getConnectionStringHelper = null;
}

function resolveConnectionString() {
  if (getConnectionStringHelper) {
    try {
      const cs = getConnectionStringHelper();
      if (cs) return cs;
    } catch (e) {
      // fall through to env vars below
    }
  }
  // NETLIFY_DB_URL is the current name Netlify Database sets. NETLIFY_DATABASE_URL
  // is the older/legacy name (Neon extension). DATABASE_URL is for a manually
  // configured Postgres instance.
  return process.env.NETLIFY_DB_URL || process.env.NETLIFY_DATABASE_URL || process.env.DATABASE_URL;
}

let pool;
let schemaReady = null;

function getPool() {
  if (!pool) {
    const connectionString = resolveConnectionString();
    if (!connectionString) {
      throw new Error('No database configured. Add Netlify Database or set DATABASE_URL.');
    }
    pool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
    });
  }
  return pool;
}

// Creates the tables this app needs if they don't already exist. Safe to call
// on every request — CREATE TABLE IF NOT EXISTS is a no-op once tables exist.
// This means you never have to manually run schema.sql through a SQL console;
// the first real signup/login call sets everything up automatically.
function ensureSchema() {
  if (!schemaReady) {
    schemaReady = getPool().query(`
      create extension if not exists pgcrypto;

      create table if not exists users (
        id uuid primary key default gen_random_uuid(),
        email text unique not null,
        password_hash text not null,
        created_at timestamptz not null default now()
      );

      create table if not exists password_resets (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references users(id) on delete cascade,
        token_hash text not null,
        expires_at timestamptz not null,
        used boolean not null default false,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_password_resets_user on password_resets(user_id);

      create table if not exists scans (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references users(id) on delete cascade,
        domain text not null,
        score int not null,
        risk_level text not null,
        warnings int not null default 0,
        positives int not null default 0,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_scans_user on scans(user_id, created_at desc);
    `).catch((err) => {
      schemaReady = null; // allow retry on next request if this failed
      throw err;
    });
  }
  return schemaReady;
}

module.exports = { getPool, ensureSchema };
