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

      alter table users add column if not exists email_verified boolean not null default false;

      create table if not exists email_verifications (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references users(id) on delete cascade,
        token_hash text not null,
        expires_at timestamptz not null,
        used boolean not null default false,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_email_verifications_user on email_verifications(user_id);

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

      create table if not exists rate_limits (
        bucket_key text primary key,
        window_start timestamptz not null default now(),
        count int not null default 0
      );

      create table if not exists reports (
        id uuid primary key default gen_random_uuid(),
        url text not null,
        reason text,
        reporter_email text,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_reports_created on reports(created_at desc);

      create table if not exists suggestions (
        id uuid primary key default gen_random_uuid(),
        message text not null,
        contact_email text,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_suggestions_created on suggestions(created_at desc);

      create table if not exists waitlist (
        id uuid primary key default gen_random_uuid(),
        plan text not null,
        email text,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_waitlist_created on waitlist(created_at desc);

      create table if not exists watchlist_sites (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references users(id) on delete cascade,
        url text not null,
        label text,
        last_flagged boolean not null default false,
        last_redirect_domain text,
        last_checked_at timestamptz,
        last_check_error text,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_watchlist_user on watchlist_sites(user_id, created_at desc);

      create table if not exists api_keys (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references users(id) on delete cascade,
        label text not null default 'API Key',
        key_hash text not null unique,
        key_prefix text not null,
        revoked boolean not null default false,
        last_used_at timestamptz,
        created_at timestamptz not null default now()
      );

      create index if not exists idx_api_keys_user on api_keys(user_id, created_at desc);
    `).catch((err) => {
      schemaReady = null; // allow retry on next request if this failed
      throw err;
    });
  }
  return schemaReady;
}

module.exports = { getPool, ensureSchema };
