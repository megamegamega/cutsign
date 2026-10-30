// Hourly story-watch tick (24 daily Vercel crons, one per hour — Hobby allows daily jobs only, 100 of them).
// Re-checks watched stories' pages, KEV, NVD, GitHub and feeds; models run only when something changed.
//   GET /api/watch?h=NN   Authorization: Bearer $CRON_SECRET

import { supabaseStore } from '../lib/db.js';
import { runWatchTick, ensureWatches } from '../lib/watch.js';
import { authorized } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';
import { hypeSweep, coverageOnlySweep } from '../lib/hype.js';

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
    const started = Date.now();
    const counts = await runWatchTick(store, { deadline: started + 270_000 });
    if (counts.errors >= 8) await postDiscord(`Cutsign ⚠ watch tick: ${counts.errors} source fetches failed (${counts.checked}/${counts.watches} watches checked).`);
    // something developed: re-score the latest brief's stories, since a KEV listing or a material
    // change during the day can push one over the card bar (lib/hype.js); never fails the tick.
    // A quiet hour still re-checks any card whose coverage went stale (daily, or the moment a
    // Shodan key appears), so no card waits for tomorrow's brief; it stops at the function's deadline
    let hype = {};
    if (counts.events > 0) {
      try {
        const latest = (await store.listRecentSentRuns(3)).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)))[0];
        if (latest) hype = await hypeSweep(store, { run: latest });
      } catch (e) { hype = { hype_error: String(e?.message || e).slice(0, 200) }; }
    } else {
      hype = await coverageOnlySweep(store, { deadline: started + 230_000 }); // a card's check may run ~1 min
    }
    return res.json({ ok: true, ...counts, hype });
  } catch (e) {
    // before migration 0002 is applied the tables don't exist — skip quietly instead of alerting hourly
    if (/watch(es|_events)/.test(String(e?.message)) && /does not exist|could not find|schema cache/i.test(String(e?.message))) {
      return res.json({ ok: true, skipped: 'watches tables missing — apply supabase/migrations/0002_watches.sql' });
    }
    await postDiscord(`Cutsign ✖ watch tick error=${String(e?.message || e).slice(0, 300)}`);
    res.statusCode = 500;
    return res.json({ ok: false, error: String(e?.message || e) });
  }
}
