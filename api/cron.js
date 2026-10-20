// Vercel cron target (twice daily, see vercel.json). Poll Gmail for new briefs, then advance every
// open run as far as this invocation's time allows; if work remains, chain to /api/advance.
//   GET /api/cron            (Vercel cron, Authorization: Bearer $CRON_SECRET)
//   GET /api/cron?dry=1      same, but new runs are dry: full pipeline, no email
// PAUSED=1 in env halts everything without a deploy.

import { supabaseStore } from '../lib/db.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { authorized, kickAdvance } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';

export const config = { maxDuration: 300 };
const BUDGET_MS = 270_000;

export default async function handler(req, res) {
  if (!authorized(req)) { res.statusCode = 401; return res.json({ ok: false, error: 'unauthorized' }); }
  if (process.env.PAUSED === '1') return res.json({ ok: true, paused: true });
  const deadline = Date.now() + BUDGET_MS;
  const dry = new URL(req.url, 'http://x').searchParams.get('dry') === '1';
  const store = supabaseStore();
  let received;
  try {
    received = await intake(store, { dry });
  } catch (e) {
    // Gmail/DB down before any run exists: no run row to fail, so say so loudly here.
    await postDiscord(`Cutsign ✖ stage=received error=${String(e?.message || e).slice(0, 300)}`);
    res.statusCode = 500; return res.json({ ok: false, error: String(e?.message || e) });
  }
  const more = await driveRuns(store, { deadline });
  const chained = more ? await kickAdvance() : false;
  if (more && !chained) await postDiscord('Cutsign ⚠ work remains but the chain to /api/advance failed — it will resume on the next cron tick.');
  return res.json({ ok: true, received, more, chained });
}
