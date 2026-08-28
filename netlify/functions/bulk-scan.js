const jwt = require('jsonwebtoken');
const { json, getSessionToken, readJsonBody } = require('./_utils');
const { getPool, ensureSchema } = require('./_db');
const { getClientIp, rateLimitOrNull } = require('./_rateLimit');
const { runChecks } = require('./_scan');

/* =====================================================================
   Bulk URL / CSV scanning. Logged-in users only. Runs the same checks
   as the main scanner (via _scan.js) across up to MAX_URLS at once, in
   parallel, so the whole batch finishes inside Netlify's function time
   budget instead of scanning one-by-one.
   ===================================================================== */

const MAX_URLS = 8;

function requireUser(req) {
  const token = getSessionToken(req);
  if (!token || !process.env.JWT_SECRET) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

function summarize(result) {
  if (result.error) return { status: 'error', message: result.error };
  if (result.blocked) return { status: 'blocked', message: result.reason || 'Blocked before checks could run.' };

  const flags = [];
  if (result.safeBrowsing && result.safeBrowsing.configured && Array.isArray(result.safeBrowsing.matches) && result.safeBrowsing.matches.length) {
    flags.push('Flagged by Google Safe Browsing');
  }
  if (result.domainAge && result.domainAge.available && typeof result.domainAge.ageDays === 'number' && result.domainAge.ageDays < 90) {
    flags.push(`Domain registered ${result.domainAge.ageDays} days ago`);
  }
  if (result.sslCertificate && result.sslCertificate.available) {
    if (!result.sslCertificate.valid) flags.push('SSL certificate not valid/trusted');
    else if (typeof result.sslCertificate.daysUntilExpiry === 'number' && result.sslCertificate.daysUntilExpiry < 14) {
      flags.push(`SSL certificate expires in ${result.sslCertificate.daysUntilExpiry} days`);
    }
  }

  return {
    status: flags.length ? 'warning' : 'ok',
    flags,
    domainAgeDays: result.domainAge && result.domainAge.available ? result.domainAge.ageDays : null,
    safeBrowsingConfigured: !!(result.safeBrowsing && result.safeBrowsing.configured),
    sslValid: result.sslCertificate && result.sslCertificate.available ? !!result.sslCertificate.valid : null,
  };
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const user = requireUser(req);
  if (!user) return json(401, { error: 'Bulk scanning requires a free account — log in or sign up first.' });

  const body = await readJsonBody(req);
  const rawUrls = Array.isArray(body.urls) ? body.urls : [];
  const cleaned = rawUrls
    .map((u) => (typeof u === 'string' ? u.trim() : ''))
    .filter(Boolean)
    .slice(0, MAX_URLS);

  if (!cleaned.length) return json(400, { error: 'Provide at least one URL.' });

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const limited = await rateLimitOrNull(
      pool,
      `bulk-scan:${user.sub}:${ip}`,
      10,
      60 * 60,
      'Too many bulk scans. Please wait a while and try again.'
    );
    if (limited) return limited;

    const results = await Promise.all(cleaned.map(async (u) => {
      try {
        const result = await runChecks(u);
        return { url: u, ...summarize(result) };
      } catch (err) {
        return { url: u, status: 'error', message: 'Scan failed unexpectedly.' };
      }
    }));

    return json(200, {
      results,
      truncated: rawUrls.length > MAX_URLS,
      maxUrls: MAX_URLS,
    });
  } catch (err) {
    console.error('bulk-scan error', err);
    return json(500, { error: 'Bulk scan failed. Please try again.' });
  }
};
