const dns = require('dns');
const { json, readJsonBody } = require('./_utils');

const dnsLookup = dns.promises.lookup;

/* =====================================================================
   Real, live threat-intelligence checks, run server-side:
     1. Google Safe Browsing v4 — known malware/phishing URL lookup.
        Requires GOOGLE_SAFE_BROWSING_API_KEY. If that env var is not
        set, this check is honestly reported as "not configured" rather
        than silently skipped or faked.
     2. Domain age / registrar via RDAP (the modern WHOIS replacement).
        Uses the free, keyless rdap.org bootstrap redirector — no
        signup required.
     3. Redirect-chain following, done here (not in the browser) so it
        can be SSRF-guarded: every hostname in the chain — including
        the very first one — is DNS-resolved and checked against
        private/internal IP ranges *before* it is ever fetched.
   Every check has its own timeout and failures are reported as
   "not available" with a real reason, never faked.
   ===================================================================== */

const HOP_TIMEOUT_MS = 5000;
const RDAP_TIMEOUT_MS = 5000;
const SAFE_BROWSING_TIMEOUT_MS = 5000;
const MAX_REDIRECT_HOPS = 5;

const COMPOUND_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'ltd.uk', 'me.uk',
  'co.jp', 'ne.jp', 'or.jp',
  'com.au', 'net.au', 'org.au', 'gov.au',
  'co.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za',
  'com.br', 'com.mx', 'com.tr', 'com.sg',
  'co.in', 'co.id', 'co.kr',
]);

function getRegistrableDomain(hostname) {
  const labels = hostname.split('.');
  if (labels.length <= 2) return hostname;
  const lastTwo = labels.slice(-2).join('.');
  if (COMPOUND_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

function isIpLiteral(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '');
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.includes(':');
}

function ipv4ToLong(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + (parseInt(oct, 10) & 255), 0) >>> 0;
}

function isPrivateIPv4(ip) {
  const ranges = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ['224.0.0.0', 4], ['240.0.0.0', 4],
  ];
  const target = ipv4ToLong(ip);
  return ranges.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (target & mask) === (ipv4ToLong(base) & mask);
  });
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 unique local
  if (lower.startsWith('fe80')) return true; // link-local
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.split(':').pop();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4)) return isPrivateIPv4(v4);
  }
  return false;
}

function isPrivateIp(ip) {
  return ip.includes(':') ? isPrivateIPv6(ip) : isPrivateIPv4(ip);
}

// SSRF guardrail: resolves a hostname and refuses to proceed if it (or the
// literal IP given) points anywhere private/internal.
async function checkHostSafety(hostname) {
  if (isIpLiteral(hostname)) {
    const stripped = hostname.replace(/^\[|\]$/g, '');
    if (isPrivateIp(stripped)) {
      return { safe: false, reason: 'Target is a private or internal IP address.' };
    }
    return { safe: true };
  }
  let addresses;
  try {
    addresses = await dnsLookup(hostname, { all: true });
  } catch (e) {
    return { safe: false, reason: 'DNS lookup failed for this host.' };
  }
  if (!addresses.length) {
    return { safe: false, reason: 'DNS lookup returned no addresses for this host.' };
  }
  if (addresses.some((a) => isPrivateIp(a.address))) {
    return { safe: false, reason: 'This domain resolves to a private or internal IP address.' };
  }
  return { safe: true };
}

async function withTimeout(promiseFactory, ms, onTimeoutMessage) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await promiseFactory(controller.signal);
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(onTimeoutMessage);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function checkSafeBrowsing(targetUrl) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) return { configured: false };
  try {
    const data = await withTimeout(async (signal) => {
      const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal,
        body: JSON.stringify({
          client: { clientId: 'scamguard', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: targetUrl }],
          },
        }),
      });
      if (!res.ok) throw new Error(`Safe Browsing API returned HTTP ${res.status}`);
      return res.json();
    }, SAFE_BROWSING_TIMEOUT_MS, 'Safe Browsing check timed out.');
    return { configured: true, matches: data.matches || [] };
  } catch (e) {
    return { configured: true, error: e.message };
  }
}

async function lookupRdap(domain) {
  try {
    const data = await withTimeout(async (signal) => {
      const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        signal,
        headers: { Accept: 'application/rdap+json' },
      });
      if (res.status === 404) throw new Error('No RDAP registration record found for this domain.');
      if (!res.ok) throw new Error(`RDAP lookup returned HTTP ${res.status}`);
      return res.json();
    }, RDAP_TIMEOUT_MS, 'Domain age (RDAP) lookup timed out.');

    const registrationEvent = (data.events || []).find((e) => e.eventAction === 'registration');
    const registrarEntity = (data.entities || []).find((e) => (e.roles || []).includes('registrar'));
    let registrarName = null;
    if (registrarEntity) {
      const vcard = registrarEntity.vcardArray && registrarEntity.vcardArray[1];
      const fnEntry = Array.isArray(vcard) ? vcard.find((v) => v[0] === 'fn') : null;
      registrarName = (fnEntry && fnEntry[3]) || registrarEntity.handle || null;
    }
    let ageDays = null;
    if (registrationEvent && registrationEvent.date) {
      ageDays = Math.floor((Date.now() - new Date(registrationEvent.date).getTime()) / 86400000);
    }
    return {
      available: ageDays !== null,
      registrationDate: registrationEvent ? registrationEvent.date : null,
      ageDays,
      registrar: registrarName,
      reason: ageDays === null ? 'RDAP record had no registration date.' : null,
    };
  } catch (e) {
    return { available: false, reason: e.message };
  }
}

async function safeFetchChain(startUrl) {
  const chain = [];
  let current = startUrl;
  for (let i = 0; i < MAX_REDIRECT_HOPS; i++) {
    let u;
    try {
      u = new URL(current);
    } catch {
      chain.push({ url: current, error: 'Invalid URL encountered in redirect chain.' });
      break;
    }
    if (!['http:', 'https:'].includes(u.protocol)) {
      chain.push({ url: current, blocked: true, reason: `Redirect target uses an unsupported protocol (${u.protocol}).` });
      break;
    }
    const guard = await checkHostSafety(u.hostname);
    if (!guard.safe) {
      chain.push({ url: current, blocked: true, reason: guard.reason });
      break;
    }
    try {
      const res = await withTimeout((signal) => fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal,
        headers: { 'User-Agent': 'ScamGuardBot/1.0 (+https://scamguard.store)' },
      }), HOP_TIMEOUT_MS, 'Redirect chain lookup timed out.');
      chain.push({ url: current, status: res.status });
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get('location');
        if (!loc) break;
        current = new URL(loc, current).toString();
        continue;
      }
      break;
    } catch (e) {
      chain.push({ url: current, error: e.message });
      break;
    }
  }
  return chain;
}

exports.default = async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  const body = await readJsonBody(req);
  const rawUrl = body.url;
  if (!rawUrl || typeof rawUrl !== 'string') return json(400, { error: 'Missing url.' });

  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    return json(400, { error: 'Invalid URL.' });
  }
  if (!['http:', 'https:'].includes(target.protocol)) {
    return json(400, { error: 'Only http/https URLs are supported.' });
  }

  const guard = await checkHostSafety(target.hostname);
  if (!guard.safe) {
    return json(200, {
      blocked: true,
      reason: guard.reason,
      safeBrowsing: { configured: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY, skipped: true },
      domainAge: { available: false, reason: 'Skipped — target blocked before live lookups.' },
      redirectChain: [{ url: target.toString(), blocked: true, reason: guard.reason }],
    });
  }

  const registrable = getRegistrableDomain(target.hostname);

  const [safeBrowsing, domainAge, redirectChain] = await Promise.allSettled([
    checkSafeBrowsing(target.toString()),
    lookupRdap(registrable),
    safeFetchChain(target.toString()),
  ]);

  return json(200, {
    blocked: false,
    safeBrowsing: safeBrowsing.status === 'fulfilled' ? safeBrowsing.value : { configured: true, error: 'Lookup failed unexpectedly.' },
    domainAge: domainAge.status === 'fulfilled' ? domainAge.value : { available: false, reason: 'Lookup failed unexpectedly.' },
    redirectChain: redirectChain.status === 'fulfilled' ? redirectChain.value : [{ url: target.toString(), error: 'Lookup failed unexpectedly.' }],
  });
};
