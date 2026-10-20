// Liveness + config check. Reports which env vars are present (names only, never values).

const REQUIRED = ['CRON_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_API_KEY', 'DISCORD_WEBHOOK_URL',
  'ANTHROPIC_API_KEY', 'GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN'];

export default function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Cache-Control', 'no-store');
  const missing = REQUIRED.filter((k) => !process.env[k]);
  return res.json({ ok: true, service: 'cutsign', version: 'v0', paused: process.env.PAUSED === '1', missing_env: missing });
}
