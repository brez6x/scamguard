const { json, readJsonBody } = require('./_utils');
const { runChecks } = require('./_scan');

/* =====================================================================
   Single-URL scan endpoint used by the main scanner on the homepage.
   All the actual check logic (Safe Browsing, RDAP domain age, redirect
   chain, SSL certificate) lives in _scan.js so bulk-scan.js and the
   scheduled watchlist-check.js can reuse exactly the same checks.
   ===================================================================== */

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const rawUrl = body.url;
  if (!rawUrl || typeof rawUrl !== 'string') return json(400, { error: 'Missing url.' });

  const result = await runChecks(rawUrl);
  if (result.error) return json(400, { error: result.error });

  const { url, ...rest } = result;
  return json(200, rest);
};
