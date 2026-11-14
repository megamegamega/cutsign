// Story-watch tick. Since 2026-11-12 it runs as one daily block after the brief has been read (ten
// Vercel crons, 14:30-23:30 UTC, vercel.json; it was hourly before). The first tick or two read every
// watch once (pages, feeds, and a model only where something changed); the later ticks collect the
// batched model answers, finish the free checks (KEV, NVD, GitHub) and refresh card coverage.
// Order inside a tick: batched answers, response actions for cards that have none yet, the inbox, the
// watches, the card loop, then card coverage with what is left of the tick. Every step has a deadline
// inside the function's 300 s (2026-11-14: the card loop had none, and a tick that ran long was cut
// off before it answered, with the steps behind the loop never reached).
//   GET /api/watch?h=NN   Authorization: Bearer $CRON_SECRET

import { supabaseStore } from '../lib/db.js';
import { runWatchTick, ensureWatches } from '../lib/watch.js';
import { authorized } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';
import { hypeSweep, coverageOnlySweep, actionsOnlySweep } from '../lib/hype.js';
import { intake } from '../lib/intake.js';
import { applyUpdate } from '../lib/update.js';
import { collectJobs } from '../lib/jobs.js';

export const config = { maxDuration: 300 };

const num = (k, d) => { const v = process.env[k]; return v === undefined || v === '' || !Number.isFinite(Number(v)) ? d : Number(v); };
// A watch is read once per daily block: 18 h is longer than the block and shorter than the gap between
// two blocks' ends, so a watch read at any point today is due again at some tick tomorrow.
const WATCH_EVERY_MS = () => num('WATCH_MIN_INTERVAL_H', 18) * 3_600_000;
const SLOW_GAP_MS = () => num('WATCH_SLOW_GAP_MS', 7000);

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
    // seconds into the tick at which each step ended: one log line and a field of the answer, so a tick
    // that runs close to the 300 s is read from the log without guessing which step took the time
    const secs = {}; const mark = (k) => { secs[k] = Math.round((Date.now() - started) / 1000); };
    // Batched model answers first (lib/jobs.js): the hunt proposals and card drafts submitted earlier at
    // half price land here — a proposal onto its story, a card published with its coverage check and mail.
    // The deadline leaves room for one live rerun of a failed card draft (150 s, LIVE_RESERVE_MS): at
    // 150 s it could never start, and the failed job held its story's card back for good.
    let jobs = {};
    try { jobs = await collectJobs(store, { deadline: started + 170_000 }); } catch (e) { jobs = { error: String(e?.message || e).slice(0, 160) }; }
    mark('jobs');
    // Response actions for published cards that have none yet (lib/actions.js), which includes a card
    // landed just above. Here and not at the end: on a tick where the watches take their full time
    // the end was never reached. No call starts after 105 s (or 45 s after the step began), each is
    // given a minute, so the watches start by 165 s at the latest; nothing is pending on most ticks.
    const actions = await actionsOnlySweep(store, { deadline: started + 150_000 });
    mark('actions');
    // Reader-supplied updates arrive by mail and would otherwise wait for the next daily poll: the watch
    // tick polls the inbox too and reads them first (a brief found here waits for the cron, as before)
    let updates = {};
    try {
      const rec = await intake(store, {});
      for (const u of rec.updates || []) await applyUpdate(store, u);
      updates = { mails: rec.seen, applied: (rec.updates || []).length };
    } catch (e) { updates = { error: String(e?.message || e).slice(0, 160) }; await postDiscord(`Cutsign ✖ inbox poll on the watch tick failed: ${updates.error}`); }
    // every CVE story of the last 30 days has a watch: what an older rule skipped (quick reads) is opened
    // here without anyone finding it; nothing is extended, so watches still expire on their own
    const opened = { watches_created: 0 };
    try { for (const run of await store.listRecentSentRuns(30)) opened.watches_created += (await ensureWatches(store, run, { extend: false })).watches_created; } catch (e) { opened.error = String(e?.message || e).slice(0, 160); }
    // 240 s, not 270 (2026-11-14: a tick answered at 274 s of the 300 s, which is the plan's ceiling). The
    // watches start a model read with as little as 20 s left on this clock and a read can take a minute:
    // now the last one starts by 220 s. A watch not reached is held, not marked read, for the next tick.
    const counts = await runWatchTick(store, { deadline: started + 240_000, minIntervalMs: WATCH_EVERY_MS(), slowGapMs: SLOW_GAP_MS() });
    mark('watches');
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
    // and for a run whose hunt proposals just landed (a day-one draft waited for them, lib/hype.js)
    const landedRuns = jobs.runs || [];
    if (counts.events > 0 || recentStoryIds.length || landedRuns.length) {
      try {
        const latest = (await store.listRecentSentRuns(3)).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)))[0];
        const runIds = new Set([...(latest ? [latest.id] : []), ...landedRuns]);
        for (const sid of [...(counts.event_story_ids || []), ...recentStoryIds]) { try { const s = await store.getStory(sid); if (s?.run_id) runIds.add(s.run_id); } catch { /* skip */ } }
        const runs = [];
        for (const id of [...runIds].slice(0, 4)) { const r = id === latest?.id ? latest : await store.getRun(id); if (r) runs.push(r); }
        for (const r of runs) {
          // response actions: done above. Deadlines: no story starts after 260 s and no coverage check after
          // 210 s; a live draft (a batch submission refused) waits for a sweep with minutes to spare
          const h = await hypeSweep(store, { run: r, actions: false, deadline: started + 270_000, reserveMs: 10_000 });
          for (const [k, v] of Object.entries(h)) hype[k] = typeof v === 'number' ? (hype[k] || 0) + v : v;
        }
        hype.runs = runs.length;
      } catch (e) { hype = { hype_error: String(e?.message || e).slice(0, 200) }; }
    }
    // Card coverage last (it ran first while the tick was hourly and every watch was always due): the
    // watches and their re-reads get the full tick, and a tick with no watch due — most of the block —
    // leaves coverage a couple of minutes. Cards whose check is stale are taken stalest first; none
    // starts after 200 s (a check runs about a minute, the function ends at 300 s). On a tick that ran
    // long the sweep only lists what is stale (a few DB reads) and defers it all.
    mark('cards');
    const coverage = await coverageOnlySweep(store, { deadline: started + 200_000 });
    mark('coverage');
    console.log(`[watch] tick ended at ${secs.coverage} s of 300: ${JSON.stringify(secs)}`);
    return res.json({ ok: true, ...counts, jobs, actions, updates, opened, coverage, hype, seconds: secs });
  } catch (e) {
    // before migration 0002 is applied the tables don't exist — skip quietly instead of alerting on every tick
    if (/watch(es|_events)/.test(String(e?.message)) && /does not exist|could not find|schema cache/i.test(String(e?.message))) {
      return res.json({ ok: true, skipped: 'watches tables missing — apply supabase/migrations/0002_watches.sql' });
    }
    await postDiscord(`Cutsign ✖ watch tick error=${String(e?.message || e).slice(0, 300)}`);
    res.statusCode = 500;
    return res.json({ ok: false, error: String(e?.message || e) });
  }
}
