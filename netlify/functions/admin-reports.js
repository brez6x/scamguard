const { getPool, ensureSchema } = require('./_db');

// A bare-bones, password-protected page for viewing submitted "Report a
// Website" entries. Not a full admin dashboard (that's a bigger, separate
// feature) — just enough to actually see what people report. Protected by
// the ADMIN_KEY environment variable rather than a login, since it's for
// the site owner only.

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
  if (key !== process.env.ADMIN_KEY) {
    return htmlResponse(401, 'Unauthorized. Add ?key=YOUR_ADMIN_KEY to the end of this page\'s URL.');
  }

  try {
    await ensureSchema();
    const pool = getPool();
    const result = await pool.query(
      'select url, reason, reporter_email, created_at from reports order by created_at desc limit 200'
    );

    const rows = result.rows.map((r) => `
      <tr>
        <td>${escapeHtml(new Date(r.created_at).toLocaleString())}</td>
        <td><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.url)}</a></td>
        <td>${escapeHtml(r.reason || '—')}</td>
        <td>${escapeHtml(r.reporter_email || '—')}</td>
      </tr>
    `).join('');

    const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<title>Reported Websites — ScamGuard</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#04121A;color:#e2e8f0;padding:24px;max-width:1000px;margin:0 auto;}
  h1{color:#3fb8ed;margin-bottom:4px;}
  p.count{color:#94a3b8;margin-top:0;}
  table{width:100%;border-collapse:collapse;margin-top:20px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;font-size:14px;vertical-align:top;word-break:break-word;}
  th{color:#94a3b8;text-transform:uppercase;font-size:12px;letter-spacing:0.05em;}
  a{color:#3fb8ed;}
  .empty{color:#64748b;margin-top:24px;}
</style>
</head>
<body>
  <h1>Reported Websites</h1>
  <p class="count">${result.rows.length} report${result.rows.length === 1 ? '' : 's'} (most recent 200 shown)</p>
  ${result.rows.length ? `
  <table>
    <thead><tr><th>Date</th><th>URL</th><th>Reason</th><th>Reporter email</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>` : '<p class="empty">No reports yet.</p>'}
</body>
</html>`;

    return htmlResponse(200, html);
  } catch (err) {
    console.error('admin-reports error', err);
    return htmlResponse(500, 'Something went wrong loading reports.');
  }
};
