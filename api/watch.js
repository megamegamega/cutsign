// Hourly story-watch tick (24 daily Vercel crons, one per hour — Hobby allows daily jobs only, 100 of them).
// Re-checks watched stories' pages, KEV, NVD, GitHub and feeds; models run only when something changed.
//   GET /api/watch?h=NN   Authorization: Bearer $CRON_SECRET

import { supabaseStore } from '../lib/db.js';
import { runWatchTick, ensureWatches } from '../lib/watch.js';
import { authorized } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';

export const config = { maxDuration: 300 };

export default async function handler(req, res) {
  if (!authorized(req)) { res.statusCode = 401; return res.json({ ok: false }); }
  if (process.env.PAUSED === '1') return res.json({ ok: true, paused: true });
  try {
    const store = supabaseStore();
    // one-time: start watches for stories deep-read in recent runs (normally a daily run does this)
    if (new URL(req.url, 'http://x').searchParams.get('backfill') === '1') {
      const made = { watches_created: 0, watches_extended: 0 };
      for (const run of await store.listRecentSentRuns(7)) {
        const c = await ensureWatches(store, run);
        made.watches_created += c.watches_created; made.watches_extended += c.watches_extended;
      }
      return res.json({ ok: true, backfill: made });
    }
    const counts = await runWatchTick(store, { deadline: Date.now() + 270_000 });
    if (counts.errors >= 8) await postDiscord(`Cutsign ⚠ watch tick: ${counts.errors} source fetches failed (${counts.checked}/${counts.watches} watches checked).`);
    return res.json({ ok: true, ...counts });
  } catch (e) {
    await postDiscord(`Cutsign ✖ watch tick error=${String(e?.message || e).slice(0, 300)}`);
    res.statusCode = 500;
    return res.json({ ok: false, error: String(e?.message || e) });
  }
}
