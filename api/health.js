// Liveness + config check. Reports which env vars are present (names only, never values).

const BASE = ['CRON_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_API_KEY', 'EMAIL_FROM', 'EMAIL_TO', 'BRIEF_SENDER_ALLOWLIST', 'DISCORD_WEBHOOK_URL', 'ANTHROPIC_API_KEY'];
const BY_SOURCE = { resend: ['BRIEF_INBOUND_ADDRESS'], gmail: ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN'] };

// Optional tables (added by later migrations); reported as ok | missing so an unapplied migration
// is visible without database access. Never fails the health check.
const OPTIONAL_TABLES = ['watches', 'card_drafts'];

export default async function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Cache-Control', 'no-store');
  const source = process.env.INBOUND_SOURCE === 'gmail' ? 'gmail' : 'resend';
  const missing = [...BASE, ...BY_SOURCE[source]].filter((k) => !process.env[k]);
  const tables = {};
  try {
    const { createClient } = await import('@supabase/supabase-js');
    const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
    for (const t of OPTIONAL_TABLES) {
      const { error } = await sb.from(t).select('id', { count: 'exact', head: true }).limit(1);
      tables[t] = !error ? 'ok' : /does not exist|could not find|schema cache/i.test(error.message) ? 'missing' : 'error';
    }
  } catch { for (const t of OPTIONAL_TABLES) tables[t] = 'unknown'; }
  return res.json({ ok: true, service: 'cutsign', version: 'v0', inbound: source, paused: process.env.PAUSED === '1', missing_env: missing, tables });
}
