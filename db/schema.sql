-- ScamGuard auth schema
-- Run this once against your Netlify Postgres (Neon) database.
-- In Netlify: Site configuration -> Database -> Neon -> open the SQL editor and paste this in.

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

