const { getPool, ensureSchema } = require('./_db');
const { getClientIp, checkRateLimit } = require('./_rateLimit');

// A bare-bones, password-protected page for viewing submitted suggestions.
// Same pattern as admin-reports.js — protected by the ADMIN_KEY environment
// variable rather than a login, since it's for the site owner only.
// Rate-limited by IP so the ADMIN_KEY can't be brute-forced.

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
      'select message, contact_email, created_at from suggestions order by created_at desc limit 200'
    );

    const rows = result.rows.map((r) => `
      <tr>
        <td>${escapeHtml(new Date(r.created_at).toLocaleString())}</td>
        <td>${escapeHtml(r.message)}</td>
        <td>${escapeHtml(r.contact_email || '—')}</td>
      </tr>
    `).join('');

    const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<title>Suggestions — ScamGuard</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#04121A;color:#e2e8f0;padding:24px;max-width:1000px;margin:0 auto;}
  h1{color:#3fb8ed;margin-bottom:4px;}
  p.count{color:#94a3b8;margin-top:0;}
  .nav-link{color:#3fb8ed;font-size:13px;}
  table{width:100%;border-collapse:collapse;margin-top:20px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;font-size:14px;vertical-align:top;word-break:break-word;white-space:pre-wrap;}
  th{color:#94a3b8;text-transform:uppercase;font-size:12px;letter-spacing:0.05em;}
  a{color:#3fb8ed;}
  .empty{color:#64748b;margin-top:24px;}
</style>
</head>
<body>
  <a class="nav-link" href="/.netlify/functions/admin-reports?key=${encodeURIComponent(key)}">&larr; View reported websites</a>
  <h1>Suggestions</h1>
  <p class="count">${result.rows.length} suggestion${result.rows.length === 1 ? '' : 's'} (most recent 200 shown)</p>
  ${result.rows.length ? `
  <table>
    <thead><tr><th>Date</th><th>Message</th><th>Contact email</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>` : '<p class="empty">No suggestions yet.</p>'}
</body>
</html>`;

    return htmlResponse(200, html);
  } catch (err) {
    console.error('admin-suggestions error', err);
    return htmlResponse(500, 'Something went wrong loading suggestions.');
  }
};
