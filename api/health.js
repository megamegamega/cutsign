// Liveness + config check. Reports which env vars are present (names only, never values).

const BASE = ['CRON_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_API_KEY', 'EMAIL_FROM', 'EMAIL_TO', 'BRIEF_SENDER_ALLOWLIST', 'DISCORD_WEBHOOK_URL', 'ANTHROPIC_API_KEY'];
const BY_SOURCE = { resend: ['BRIEF_INBOUND_ADDRESS'], gmail: ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN'] };

export default function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Cache-Control', 'no-store');
  const source = process.env.INBOUND_SOURCE === 'gmail' ? 'gmail' : 'resend';
  const missing = [...BASE, ...BY_SOURCE[source]].filter((k) => !process.env[k]);
  return res.json({ ok: true, service: 'cutsign', version: 'v0', inbound: source, paused: process.env.PAUSED === '1', missing_env: missing });
}
