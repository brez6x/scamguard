const { Pool } = require('pg');

let pool;
let schemaReady = null;

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
