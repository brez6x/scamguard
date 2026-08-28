const { getPool, ensureSchema } = require('./_db');
const { json } = require('./_utils');
const { sendEmail, emailShell } = require('./_email');
const { runChecks, getRegistrableDomain } = require('./_scan');

/* =====================================================================
   Scheduled function — re-checks every watched site once a day and
   emails the site owner if something changed:
     - the site is newly flagged by Google Safe Browsing, or
     - the site's final landing domain (after following redirects) has
       changed since the last check.
   Uses the "new format" schedule config below, so Netlify runs this
   automatically — no netlify.toml entry needed.
   ===================================================================== */

exports.config = { schedule: '@daily' };

const CONCURRENCY = 5;

async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, run);
  await Promise.all(workers);
  return results;
}

function finalUrlFromChain(chain) {
  if (!Array.isArray(chain) || !chain.length) return null;
  const last = chain[chain.length - 1];
  return last && last.url ? last.url : null;
}

async function checkOneSite(pool, site) {
  const result = await runChecks(site.url);

  if (result.error || result.blocked) {
    await pool.query(
      `update watchlist_sites set last_checked_at = now(), last_check_error = $2 where id = $1`,
      [site.id, result.error || result.reason || 'Site could not be checked.']
    );
    return null;
  }

  const flagged = !!(result.safeBrowsing && result.safeBrowsing.configured && Array.isArray(result.safeBrowsing.matches) && result.safeBrowsing.matches.length > 0);

  let redirectDomain = null;
  const finalUrl = finalUrlFromChain(result.redirectChain);
  if (finalUrl) {
    try { redirectDomain = getRegistrableDomain(new URL(finalUrl).hostname); } catch { redirectDomain = null; }
  }

  const wasFlagged = !!site.last_flagged;
  const hadPreviousCheck = !!site.last_checked_at;
  const previousRedirectDomain = site.last_redirect_domain;

  const alerts = [];
  if (flagged && (!hadPreviousCheck || !wasFlagged)) {
    alerts.push('This site is now flagged by Google Safe Browsing as unsafe (malware or phishing).');
  }
  if (hadPreviousCheck && previousRedirectDomain && redirectDomain && redirectDomain !== previousRedirectDomain) {
    alerts.push(`This site's final destination changed from "${previousRedirectDomain}" to "${redirectDomain}".`);
  }

  await pool.query(
    `update watchlist_sites
     set last_flagged = $2, last_redirect_domain = $3, last_checked_at = now(), last_check_error = null
     where id = $1`,
    [site.id, flagged, redirectDomain]
  );

  return alerts.length ? { site, alerts } : null;
}

async function notifyOwner(userEmail, site, alerts) {
  const siteUrl = process.env.SITE_URL || 'https://scamguard.store';
  await sendEmail({
    to: userEmail,
    subject: `ScamGuard watchlist alert — ${site.url}`,
    html: emailShell('Watchlist Alert', `
      <p>Something changed for a site on your ScamGuard watchlist:</p>
      <p style="font-family:monospace; background:#f1f5f9; padding:8px 10px; border-radius:6px;">${site.url}</p>
      <ul>${alerts.map((a) => `<li>${a}</li>`).join('')}</ul>
      <p><a href="${siteUrl}/?nav=watchlist" style="display:inline-block; background:#3fb8ed; color:#04121A; padding:12px 20px; border-radius:8px; text-decoration:none; font-weight:bold;">View your watchlist</a></p>
    `),
  });
}

exports.default = async (req) => {
  try {
    await ensureSchema();
    const pool = getPool();

    const result = await pool.query(
      `select ws.id, ws.url, ws.label, ws.last_flagged, ws.last_redirect_domain, ws.last_checked_at, u.email as owner_email
       from watchlist_sites ws
       join users u on u.id = ws.user_id
       order by ws.last_checked_at asc nulls first
       limit 200`
    );
    const sites = result.rows;

    const outcomes = await mapWithConcurrency(sites, CONCURRENCY, (site) => checkOneSite(pool, site).catch((err) => {
      console.error('watchlist-check site error', site.id, err);
      return null;
    }));

    const toNotify = outcomes.filter(Boolean);
    for (const { site, alerts } of toNotify) {
      try {
        await notifyOwner(site.owner_email, site, alerts);
      } catch (err) {
        console.error('watchlist-check email error', site.id, err);
      }
    }

    return json(200, { checked: sites.length, alertsSent: toNotify.length });
  } catch (err) {
    console.error('watchlist-check error', err);
    return json(500, { error: 'Watchlist check run failed.' });
  }
};
