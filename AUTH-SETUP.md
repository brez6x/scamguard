const { json } = require('./_utils');

// Netlify sets this header to the visitor's real IP address. It's more
// reliable than x-forwarded-for, which can contain multiple or spoofed
// values depending on the client.
function getClientIp(req) {
  const nfIp = req.headers.get('x-nf-client-connection-ip');
  if (nfIp) return nfIp;
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return 'unknown';
}

// Sliding-window counter backed by Postgres (not in-memory), so it works
// correctly across Netlify's many separate function instances — an
// in-memory counter would reset per instance and give false protection.
// Returns how many requests have been seen for `key` within the current window.
async function checkRateLimit(pool, key, windowSeconds) {
  // Occasionally clean up old rows so this table doesn't grow forever.
  // Cheap random sampling avoids needing a separate scheduled job.
  if (Math.random() < 0.02) {
    pool.query(`delete from rate_limits where window_start < now() - interval '1 day'`).catch(() => {});
  }

  const result = await pool.query(
    `insert into rate_limits (bucket_key, window_start, count)
     values ($1, now(), 1)
     on conflict (bucket_key) do update set
       count = case
         when rate_limits.window_start < now() - ($2 || ' seconds')::interval then 1
         else rate_limits.count + 1
       end,
       window_start = case
         when rate_limits.window_start < now() - ($2 || ' seconds')::interval then now()
         else rate_limits.window_start
       end
     returning count`,
    [key, windowSeconds]
  );
  return result.rows[0].count;
}

// Convenience wrapper for use inside a function handler: checks the limit
// and, if it's been exceeded, returns a ready-to-send 429 Response. Returns
// null if the request is within limits and the caller should proceed.
async function rateLimitOrNull(pool, key, limit, windowSeconds, message) {
  const count = await checkRateLimit(pool, key, windowSeconds);
  if (count > limit) {
    return json(429, { error: message || 'Too many attempts. Please wait a few minutes and try again.' });
  }
  return null;
}

module.exports = { getClientIp, checkRateLimit, rateLimitOrNull };
