# ScamGuard Auth — Setup Guide

This gives ScamGuard real signup/login/logout/password-reset with hashed
passwords and secure sessions. It needs a **Git-based Netlify deploy**
(not the drag-and-drop Netlify Drop you used before) because it includes
server-side functions and a database.

## 1. Put the site + backend in one folder

Merge these backend files into the same folder as your `index.html`:

```
your-site/
  index.html          <- your ScamGuard frontend
  netlify.toml
  package.json
  netlify/
    functions/
      _db.js
      _utils.js
      signup.js
      login.js
      logout.js
      me.js
      request-password-reset.js
      reset-password.js
  db/
    schema.sql
```

## 2. Push it to GitHub

Create a new repo (e.g. `scamguard`) and push this folder to it. If you're
not familiar with git, GitHub Desktop (desktop.github.com) lets you do this
by dragging the folder in and clicking "Publish."

## 3. Connect it to Netlify

- Netlify dashboard → **Add new site → Import an existing project**
- Pick your GitHub repo. Netlify will detect `netlify.toml` automatically.
- Deploy. Netlify installs the dependencies in `package.json` for you.

## 4. Add the database

- In your Netlify site → **Site configuration → Database**
- Click **Add Neon Postgres** (Netlify's built-in free Postgres). This
  automatically sets a `NETLIFY_DATABASE_URL` environment variable — you
  don't need to copy/paste a connection string yourself.
- Open the Neon SQL editor (linked from that same page) and paste in the
  contents of `db/schema.sql`, then run it once. This creates the `users`
  and `password_resets` tables.

## 5. Add the one secret you do need to set

- Netlify site → **Site configuration → Environment variables**
- Add `JWT_SECRET` = any long random string (e.g. generate one at
  `https://generate-secret.vercel.app/32`, or run
  `openssl rand -hex 32` on your own machine).
- Redeploy the site after adding it (Netlify → Deploys → Trigger deploy).

## 6. Test it

Visit your live Netlify URL, click **Login** in the navbar, switch to the
**Sign Up** tab, and create an account with a real-looking email and an
8+ character password. If it works, the button changes to "Log Out
(yourname)". Refresh the page — you should stay logged in (session cookie).

## What's NOT done yet

- **Password reset emails aren't sent.** `request-password-reset.js`
  generates and stores a real, secure reset token, but nothing emails it
  to the user yet — that needs an email provider (Resend, SendGrid,
  Postmark all have simple APIs and free tiers). Until that's wired up,
  the "Forgot password?" flow safely does nothing visible to an attacker,
  but doesn't yet complete a real reset either.
- **Scan history still lives on-device**, not tied to the logged-in
  account. Moving it to the database is a small follow-up: add a `scans`
  table (see ARCHITECTURE.md) and have the scan-save function include the
  user's id when `me` returns a logged-in user.
- **Plan limits / Stripe aren't tied to accounts yet** — that's the next
  piece once you're ready for it.
- No rate limiting on login/signup yet. Worth adding (e.g. via Netlify's
  edge rate limiting or a service like Upstash) before this handles real
  public traffic, to slow down password-guessing attempts.
