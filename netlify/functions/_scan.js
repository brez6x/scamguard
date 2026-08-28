const dns = require('dns');
const tls = require('tls');

const dnsLookup = dns.promises.lookup;

/* =====================================================================
   Shared scan core — used by threat-check.js (single scan), bulk-scan.js
   (multi-URL scan), and watchlist-check.js (scheduled re-checks), so all
   three run the exact same real, live checks:
     1. Google Safe Browsing v4 — known malware/phishing URL lookup.
     2. Domain age / registrar via RDAP (the modern WHOIS replacement).
     3. Redirect-chain following, SSRF-guarded at every hop.
     4. SSL/TLS certificate inspection — issuer, expiry, self-signed check.
   Every check has its own timeout and failures are reported as
   "not available" with a real reason, never faked.
   ===================================================================== */

const HOP_TIMEOUT_MS = 4000;
const CHAIN_TOTAL_BUDGET_MS = 8000;
const RDAP_TIMEOUT_MS = 6000;
const SAFE_BROWSING_TIMEOUT_MS = 5000;
const SSL_TIMEOUT_MS = 5000;
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
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe80')) return true;
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.split(':').pop();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4)) return isPrivateIPv4(v4);
  }
  return false;
}

function isPrivateIp(ip) {
  return ip.includes(':') ? isPrivateIPv6(ip) : isPrivateIPv4(ip);
}

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

let rdapBootstrapCache = null;
const RDAP_BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const RDAP_USER_AGENT = 'ScamGuard/1.0 (+https://scamguard.store; automated RDAP lookup)';

async function getRdapBootstrap(signal) {
  if (rdapBootstrapCache && (Date.now() - rdapBootstrapCache.fetchedAt) < RDAP_BOOTSTRAP_TTL_MS) {
    return rdapBootstrapCache.services;
  }
  const res = await fetch('https://data.iana.org/rdap/dns.json', { signal, headers: { 'User-Agent': RDAP_USER_AGENT } });
  if (!res.ok) throw new Error(`IANA RDAP bootstrap file returned HTTP ${res.status}`);
  const data = await res.json();
  rdapBootstrapCache = { services: data.services || [], fetchedAt: Date.now() };
  return rdapBootstrapCache.services;
}

function findRdapBaseUrls(services, tld) {
  const lower = tld.toLowerCase();
  for (const entry of services) {
    const [tlds, urls] = entry;
    if (Array.isArray(tlds) && tlds.some((t) => t.toLowerCase() === lower)) {
      return urls || [];
    }
  }
  return [];
}

async function fetchRdapUrl(url, signal) {
  const res = await fetch(url, { signal, headers: { Accept: 'application/rdap+json', 'User-Agent': RDAP_USER_AGENT } });
  if (res.status === 404) throw new Error('No RDAP registration record found for this domain.');
  if (!res.ok) throw new Error(`RDAP lookup returned HTTP ${res.status} from ${new URL(url).hostname}`);
  return res.json();
}

function fetchRdapDomain(baseUrl, domain, signal) {
  const trimmed = baseUrl.endsWith('/') ? baseUrl : baseUrl + '/';
  return fetchRdapUrl(`${trimmed}domain/${encodeURIComponent(domain)}`, signal);
}

function extractRegistrationInfo(data) {
  const registrationEvent = (data.events || []).find((e) => e.eventAction === 'registration');
  const registrarEntity = (data.entities || []).find((e) => (e.roles || []).includes('registrar'));
  let registrarName = null;
  if (registrarEntity) {
    const vcard = registrarEntity.vcardArray && registrarEntity.vcardArray[1];
    const fnEntry = Array.isArray(vcard) ? vcard.find((v) => v[0] === 'fn') : null;
    registrarName = (fnEntry && fnEntry[3]) || registrarEntity.handle || null;
  }
  let ageDays = null;
  if (registrationEvent && registrationEvent.eventDate) {
    ageDays = Math.floor((Date.now() - new Date(registrationEvent.eventDate).getTime()) / 86400000);
  }
  const linkPools = [data.links, registrarEntity && registrarEntity.links];
  let referralUrl = null;
  for (const pool of linkPools) {
    const referral = (pool || []).find((l) => l && l.rel === 'related' && /rdap/i.test(l.href || ''));
    if (referral) { referralUrl = referral.href; break; }
  }
  return { registrationDate: registrationEvent ? registrationEvent.eventDate : null, ageDays, registrar: registrarName, referralUrl };
}

function toResult(info) {
  return {
    available: info.ageDays !== null,
    registrationDate: info.registrationDate,
    ageDays: info.ageDays,
    registrar: info.registrar,
    reason: info.ageDays === null ? 'RDAP record had no registration date.' : null,
  };
}

async function lookupRdap(domain) {
  const tld = domain.split('.').pop();
  let primaryError = null;

  try {
    const info = await withTimeout(async (signal) => {
      const services = await getRdapBootstrap(signal);
      const baseUrls = findRdapBaseUrls(services, tld);
      if (!baseUrls.length) throw new Error(`No RDAP server is registered with IANA for .${tld} domains.`);
      let lastErr = null;
      for (const base of baseUrls) {
        try {
          const data = await fetchRdapDomain(base, domain, signal);
          let result = extractRegistrationInfo(data);
          let referralNote = '';
          if (result.ageDays === null && result.referralUrl) {
            try {
              const refData = await fetchRdapUrl(result.referralUrl, signal);
              const refResult = extractRegistrationInfo(refData);
              if (refResult.ageDays !== null) result = refResult;
              else referralNote = ` Registrar referral (${new URL(result.referralUrl).hostname}) also had no registration date.`;
            } catch (refErr) {
              referralNote = ` Registrar referral (${new URL(result.referralUrl).hostname}) failed: ${refErr.message}`;
            }
          }
          if (result.ageDays === null) {
            const noReferral = result.referralUrl ? '' : ' No registrar referral link was present to follow.';
            throw new Error(`RDAP server at ${new URL(base).hostname} returned a record with no registration date.${noReferral}${referralNote}`);
          }
          return result;
        } catch (e) {
          lastErr = e;
        }
      }
      throw lastErr || new Error(`All known RDAP servers for .${tld} failed to respond.`);
    }, RDAP_TIMEOUT_MS, 'Domain age (RDAP) lookup timed out.');
    return toResult(info);
  } catch (e) {
    primaryError = e.message;
  }

  try {
    const data = await withTimeout((signal) => fetchRdapDomain('https://rdap.org/', domain, signal), RDAP_TIMEOUT_MS, 'Domain age (RDAP) lookup timed out.');
    const result = extractRegistrationInfo(data);
    if (result.ageDays !== null) return toResult(result);
    return { available: false, reason: `${primaryError} Fallback (rdap.org) also returned no registration date.` };
  } catch (e2) {
    return { available: false, reason: `${primaryError} Fallback (rdap.org) also failed: ${e2.message}` };
  }
}

async function safeFetchChain(startUrl) {
  const chain = [];
  let current = startUrl;
  const deadline = Date.now() + CHAIN_TOTAL_BUDGET_MS;
  for (let i = 0; i < MAX_REDIRECT_HOPS; i++) {
    const remaining = deadline - Date.now();
    if (remaining <= 500) {
      chain.push({ url: current, error: 'Redirect chain lookup ran out of time.' });
      break;
    }
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
      }), Math.min(HOP_TIMEOUT_MS, remaining), 'Redirect chain lookup timed out.');
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

// New: SSL/TLS certificate inspection. Connects directly on port 443 (does
// not go through any redirect) and reads the leaf certificate's validity
// window and issuer — a certificate that's self-signed, expired, or about
// to expire is a real trust signal worth surfacing.
function inspectSslCertificate(hostname) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (e) { /* ignore */ }
      resolve(value);
    };
    const timer = setTimeout(() => finish({ available: false, reason: 'SSL certificate check timed out.' }), SSL_TIMEOUT_MS);
    let socket;
    try {
      socket = tls.connect({
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: SSL_TIMEOUT_MS,
        rejectUnauthorized: false,
      }, () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          if (!cert || !cert.subject) {
            finish({ available: false, reason: 'No certificate was presented by this host.' });
            return;
          }
          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysUntilExpiry = validTo ? Math.ceil((validTo.getTime() - Date.now()) / 86400000) : null;
          const issuerName = cert.issuer && (cert.issuer.O || cert.issuer.CN) || null;
          const selfSigned = !!cert.issuer && !!cert.subject && cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O;
          finish({
            available: true,
            valid: !!authorized,
            authorizedError: authorized ? null : (socket.authorizationError || 'Certificate could not be verified.'),
            issuer: issuerName,
            validFrom: validFrom ? validFrom.toISOString() : null,
            validTo: validTo ? validTo.toISOString() : null,
            daysUntilExpiry,
            selfSigned,
          });
        } catch (e) {
          finish({ available: false, reason: e.message });
        }
      });
      socket.on('error', (e) => { clearTimeout(timer); finish({ available: false, reason: e.message }); });
      socket.on('timeout', () => { clearTimeout(timer); finish({ available: false, reason: 'SSL certificate check timed out.' }); });
    } catch (e) {
      clearTimeout(timer);
      finish({ available: false, reason: e.message });
    }
  });
}

// Runs the full check suite for one URL. Returns the same shape threat-check.js
// has always returned to the frontend, plus a new `sslCertificate` field.
async function runChecks(rawUrl) {
  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    return { error: 'Invalid URL.' };
  }
  if (!['http:', 'https:'].includes(target.protocol)) {
    return { error: 'Only http/https URLs are supported.' };
  }

  const guard = await checkHostSafety(target.hostname);
  if (!guard.safe) {
    return {
      url: target.toString(),
      blocked: true,
      reason: guard.reason,
      safeBrowsing: { configured: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY, skipped: true },
      domainAge: { available: false, reason: 'Skipped — target blocked before live lookups.' },
      redirectChain: [{ url: target.toString(), blocked: true, reason: guard.reason }],
      sslCertificate: { available: false, reason: 'Skipped — target blocked before live lookups.' },
    };
  }

  const registrable = getRegistrableDomain(target.hostname);

  const [safeBrowsing, domainAge, redirectChain, sslCertificate] = await Promise.allSettled([
    checkSafeBrowsing(target.toString()),
    lookupRdap(registrable),
    safeFetchChain(target.toString()),
    inspectSslCertificate(target.hostname),
  ]);

  return {
    url: target.toString(),
    blocked: false,
    safeBrowsing: safeBrowsing.status === 'fulfilled' ? safeBrowsing.value : { configured: true, error: 'Lookup failed unexpectedly.' },
    domainAge: domainAge.status === 'fulfilled' ? domainAge.value : { available: false, reason: 'Lookup failed unexpectedly.' },
    redirectChain: redirectChain.status === 'fulfilled' ? redirectChain.value : [{ url: target.toString(), error: 'Lookup failed unexpectedly.' }],
    sslCertificate: sslCertificate.status === 'fulfilled' ? sslCertificate.value : { available: false, reason: 'Lookup failed unexpectedly.' },
  };
}

module.exports = {
  runChecks,
  checkHostSafety,
  getRegistrableDomain,
  withTimeout,
};
