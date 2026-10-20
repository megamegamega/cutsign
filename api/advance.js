// Internal chain endpoint: advance open runs in the background, chaining again if work remains.
// Returns 202 immediately; the work continues under waitUntil (bounded by maxDuration).
// POST /api/advance   Authorization: Bearer $CRON_SECRET

import { waitUntil } from '@vercel/functions';
import { supabaseStore } from '../lib/db.js';
import { driveRuns } from '../lib/pipeline.js';
import { authorized, kickAdvance } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';

export const config = { maxDuration: 300 };
const BUDGET_MS = 270_000;

export default async function handler(req, res) {
  if (req.method !== 'POST' || !authorized(req)) { res.statusCode = 401; return res.json({ ok: false }); }
  if (process.env.PAUSED === '1') return res.json({ ok: true, paused: true });
  const deadline = Date.now() + BUDGET_MS;
  waitUntil((async () => {
    try {
      if (await driveRuns(supabaseStore(), { deadline })) await kickAdvance();
    } catch (e) {
      await postDiscord(`Cutsign ✖ advance error=${String(e?.message || e).slice(0, 300)}`);
    }
  })());
  res.statusCode = 202;
  return res.json({ ok: true, accepted: true });
}
