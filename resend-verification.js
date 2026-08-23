// Shared helper for sending transactional emails via Resend (https://resend.com).
// Requires RESEND_API_KEY to be set. If it's missing, emails are skipped (and
// logged) rather than the request failing — matches the pattern already used
// for password-reset emails.

async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log(`RESEND_API_KEY not set — skipped sending "${subject}" to ${to}`);
    return { sent: false };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM || 'ScamGuard <noreply@scamguard.store>',
      to: [to],
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    console.error('Resend API error', res.status, errText);
    return { sent: false };
  }
  return { sent: true };
}

function emailShell(title, bodyHtml) {
  return `
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color:#0f172a;">${title}</h2>
      ${bodyHtml}
    </div>
  `;
}

module.exports = { sendEmail, emailShell };
