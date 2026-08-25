const { getPool, ensureSchema } = require('./_db');
const { getClientIp, checkRateLimit } = require('./_rateLimit');

// A bare-bones, password-protected page for viewing "Notify Me at Launch"
// interest from the pricing page. Same pattern as admin-reports.js /
// admin-suggestions.js — protected by the ADMIN_KEY environment variable
// rather than a login, since it's for the site owner only. Rate-limited by
// IP so the ADMIN_KEY can't be brute-forced.

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function htmlResponse(status, body) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

exports.default = async (req) => {
  const url = new URL(req.url);
  const key = url.searchParams.get('key') || '';

  if (!process.env.ADMIN_KEY) {
    return htmlResponse(500, 'Admin key not configured. Add an ADMIN_KEY environment variable in Netlify (Project configuration → Environment variables), then reload this page with ?key=that-value.');
  }

  try {
    await ensureSchema();
    const pool = getPool();

    const ip = getClientIp(req);
    const attempts = await checkRateLimit(pool, `admin:${ip}`, 60 * 60);
    if (attempts > 30) {
      return htmlResponse(429, 'Too many attempts from this connection. Please wait a while and try again.');
    }

    if (key !== process.env.ADMIN_KEY) {
      return htmlResponse(401, 'Unauthorized. Add ?key=YOUR_ADMIN_KEY to the end of this page\'s URL.');
    }

    const result = await pool.query(
      'select plan, email, created_at from waitlist order by created_at desc limit 500'
    );
    const counts = await pool.query(
      'select plan, count(*)::int as n from waitlist group by plan'
    );
    const countByPlan = Object.fromEntries(counts.rows.map((r) => [r.plan, r.n]));

    const rows = result.rows.map((r) => `
      <tr>
        <td>${escapeHtml(new Date(r.created_at).toLocaleString())}</td>
        <td>${escapeHtml(r.plan)}</td>
        <td>${escapeHtml(r.email || '—')}</td>
      </tr>
    `).join('');

    const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<title>Waitlist — ScamGuard</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#04121A;color:#e2e8f0;padding:24px;max-width:1000px;margin:0 auto;}
  h1{color:#3fb8ed;margin-bottom:4px;}
  p.count{color:#94a3b8;margin-top:0;}
  .nav-link{color:#3fb8ed;font-size:13px;}
  .stat-row{display:flex;gap:16px;margin-top:20px;}
  .stat{background:#0D1420;border:1px solid #1e293b;border-radius:10px;padding:14px 18px;}
  .stat .n{font-size:24px;font-weight:700;color:#3fb8ed;}
  .stat .l{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;}
  table{width:100%;border-collapse:collapse;margin-top:20px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;font-size:14px;vertical-align:top;word-break:break-word;}
  th{color:#94a3b8;text-transform:uppercase;font-size:12px;letter-spacing:0.05em;}
  a{color:#3fb8ed;}
  .empty{color:#64748b;margin-top:24px;}
</style>
</head>
<body>
  <a class="nav-link" href="/.netlify/functions/admin-suggestions?key=${encodeURIComponent(key)}">&larr; View suggestions</a>
  &nbsp;·&nbsp;
  <a class="nav-link" href="/.netlify/functions/admin-reports?key=${encodeURIComponent(key)}">View reported websites</a>
  <h1>Waitlist ("Notify Me at Launch")</h1>
  <p class="count">${result.rows.length} total sign-up${result.rows.length === 1 ? '' : 's'} (most recent 500 shown)</p>
  <div class="stat-row">
    <div class="stat"><div class="n">${countByPlan.pro || 0}</div><div class="l">Pro</div></div>
    <div class="stat"><div class="n">${countByPlan.business || 0}</div><div class="l">Business</div></div>
  </div>
  ${result.rows.length ? `
  <table>
    <thead><tr><th>Date</th><th>Plan</th><th>Email</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>` : '<p class="empty">No sign-ups yet.</p>'}
</body>
</html>`;

    return htmlResponse(200, html);
  } catch (err) {
    console.error('admin-waitlist error', err);
    return htmlResponse(500, 'Something went wrong loading the waitlist.');
  }
};
