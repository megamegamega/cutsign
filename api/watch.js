// Hourly story-watch tick (24 daily Vercel crons, one per hour — Hobby allows daily jobs only, 100 of them).
// Re-checks watched stories' pages, KEV, NVD, GitHub and feeds; models run only when something changed.
//   GET /api/watch?h=NN   Authorization: Bearer $CRON_SECRET

import { supabaseStore } from '../lib/db.js';
import { runWatchTick, ensureWatches } from '../lib/watch.js';
import { authorized } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';
import { hypeSweep, coverageOnlySweep } from '../lib/hype.js';
import { intake } from '../lib/intake.js';
import { applyUpdate } from '../lib/update.js';

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
    // Reader-supplied updates arrive by mail and would otherwise wait for the next daily poll: the hourly
    // tick polls the inbox too and reads them first (a brief found here waits for the cron, as before)
    let updates = {};
    try {
      const rec = await intake(store, {});
      for (const u of rec.updates || []) await applyUpdate(store, u);
      updates = { mails: rec.seen, applied: (rec.updates || []).length };
    } catch (e) { updates = { error: String(e?.message || e).slice(0, 160) }; }
    // First, any card whose coverage went stale (daily, or the moment a Shodan key appears) is
    // re-checked, in a bounded slice: new cards start for 90 s, a check runs about a minute, so the
    // watches below keep at least two minutes. The watch loop runs to its own deadline whenever
    // there are watches, so the sweep cannot come after it; a quiet hour costs it one DB read.
    const coverage = await coverageOnlySweep(store, { deadline: started + 90_000 });
    // every CVE story of the last 30 days has a watch: what an older rule skipped (quick reads) is opened
    // here without anyone finding it; nothing is extended, so watches still expire on their own
    const opened = { watches_created: 0 };
    try { for (const run of await store.listRecentSentRuns(30)) opened.watches_created += (await ensureWatches(store, run, { extend: false })).watches_created; } catch (e) { opened.error = String(e?.message || e).slice(0, 160); }
    const counts = await runWatchTick(store, { deadline: started + 270_000 });
    if (counts.errors >= 8) await postDiscord(`Cutsign ⚠ watch tick: ${counts.errors} source fetches failed (${counts.checked}/${counts.watches} watches checked).`);
    // something developed: re-score the latest brief's stories, since a KEV listing or a material
    // change during the day can push one over the card bar (lib/hype.js); never fails the tick
    // The card loop runs for today's brief and for the run of every story that developed this tick: a
    // story from two weeks ago that just landed in KEV or got a new write-up is scored where it lives.
    let hype = {};
    // stories that developed in the last day (this tick's events, or an update mail's) keep their run in the
    // loop for a day, so a draft the inbound function could not finish inside its budget is written here
    let recentStoryIds = [];
    try { recentStoryIds = [...new Set((await store.listWatchEvents({ since: new Date(started - 86_400_000).toISOString() })).filter((e) => e.level === 'HIGH').map((e) => e.watch_story_id).filter(Boolean))]; } catch { /* no events table */ }
    if (counts.events > 0 || recentStoryIds.length) {
      try {
        const latest = (await store.listRecentSentRuns(3)).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)))[0];
        const runIds = new Set(latest ? [latest.id] : []);
        for (const sid of [...(counts.event_story_ids || []), ...recentStoryIds]) { try { const s = await store.getStory(sid); if (s?.run_id) runIds.add(s.run_id); } catch { /* skip */ } }
        const runs = [];
        for (const id of [...runIds].slice(0, 4)) { const r = id === latest?.id ? latest : await store.getRun(id); if (r) runs.push(r); }
        for (const r of runs) {
          const h = await hypeSweep(store, { run: r });
          for (const [k, v] of Object.entries(h)) hype[k] = typeof v === 'number' ? (hype[k] || 0) + v : v;
        }
        hype.runs = runs.length;
      } catch (e) { hype = { hype_error: String(e?.message || e).slice(0, 200) }; }
    }
    return res.json({ ok: true, ...counts, updates, opened, coverage, hype });
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
