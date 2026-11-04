// Batched model calls, collected. Work that can wait an hour goes through the Batches API at half price
// (lib/llm.js submitStructured): a hunt proposal from the queried stage (lib/pipeline.js), a card draft,
// revision or hand-card re-issue draft from the card loop (lib/hype.js). Each is a row in llm_jobs
// (migration 0007) holding what the finish needs — ids and facts, never source text. The hourly tick
// calls collectJobs first: every pending job is asked for; an answer is finished exactly as the live
// path would have finished it (the proposal linted onto its story and counted on its run; the card
// published, re-issued or revised with its coverage check and mail). An answer the API could not give
// (an error, a refusal, a batch still running after BATCH_MAX_WAIT_MS) is finished by one live call.
// An answer nobody waits for any more (the head changed, the story left its brief) is abandoned.

import { collectStructured, cancelBatch, callStructured } from './llm.js';
import { proposalCall, finishProposalAnswer } from './queries.js';
import { draftRequest, finishDraftAnswer } from './carddraft.js';
import { finishCardDraft, finishReissueDraft, threadOf, fetchKevEntries, sweepCounts } from './hype.js';
import { buildDigestData } from './render.js';
import { addRunUsage, proposalCounts } from './pipeline.js';
import { activeCards } from './cards.js';
import { postDiscord } from './discord.js';

/** A batch still running after this long is cancelled and its call made live. */
export const BATCH_MAX_WAIT_MS = 6 * 3600_000;
// room a live fallback needs: the call with its correction turn, and for a card its coverage check and mail
const LIVE_RESERVE_MS = { proposal: 120_000, card_draft: 150_000 };
const FINISH_RESERVE_MS = 60_000; // a landed card's coverage check and mail

/**
 * Ask for every pending job and finish what landed. Returns counts and `runs`: the runs whose proposals
 * landed, which the card loop should sweep now (a day-one draft waited for them).
 */
export async function collectJobs(store, { fetchImpl = fetch, now = Date.now(), deadline = Infinity } = {}) {
  const counts = { checked: 0, pending: 0, landed: 0, live: 0, failed: 0, abandoned: 0, errors: 0, cost: 0 };
  const runs = new Set();
  let jobs = [];
  try { jobs = await store.listJobs({ status: 'pending', limit: 100 }); } catch { return { ...counts, runs: [] }; } // table missing: nothing is batched
  const ctx = { fetchImpl, now, kev: null, cache: new Map(), digests: new Map() };
  for (const job of jobs) {
    if (deadline - Date.now() < FINISH_RESERVE_MS) break;
    counts.checked++;
    let r;
    try { r = await collectStructured(job); } catch (e) { r = { status: 'pending', error: String(e?.message || e).slice(0, 200) }; }
    if (r.status === 'pending' && now - Date.parse(job.created_at) > BATCH_MAX_WAIT_MS) {
      await cancelBatch(job.batch_id);
      r = { status: 'failed', error: `not answered in ${Math.round(BATCH_MAX_WAIT_MS / 3600_000)} h` };
    }
    if (r.status === 'pending') { counts.pending++; continue; }
    if (r.status === 'failed' && deadline - Date.now() < LIVE_RESERVE_MS[job.kind]) { counts.pending++; continue; } // the live call waits for a tick with room
    try {
      const out = job.kind === 'proposal' ? await finishProposalJob(store, job, r, ctx) : await finishDraftJob(store, job, r, ctx);
      await store.updateJob(job.id, { status: out.status, outcome: out.outcome || null, cost_usd: Number((out.cost || 0).toFixed(4)), finished_at: new Date().toISOString() });
      counts.cost += out.cost || 0;
      if (out.status === 'done') {
        counts.landed++;
        if (r.status === 'failed') counts.live++;
        if (job.kind === 'proposal' && job.run_id) runs.add(job.run_id);
      } else if (out.status === 'abandoned') counts.abandoned++;
      else counts.failed++;
    } catch (e) {
      counts.errors++;
      const msg = String(e?.message || e).slice(0, 300);
      try { await store.updateJob(job.id, { status: 'failed', outcome: msg, finished_at: new Date().toISOString() }); } catch { /* said below */ }
      await postDiscord(`Cutsign ✖ batched ${job.kind.replace('_', ' ')} could not be finished: ${msg}`);
    }
  }
  return { ...counts, runs: [...runs] };
}

const guidance = (evidence) => evidence.filter((e) => e.kind === 'guidance');
const samples = (evidence) => evidence.filter((e) => e.kind !== 'guidance');

async function finishProposalJob(store, job, r, ctx) {
  const s = await store.getStory(job.story_id);
  if (!s || s.raw_iocs?.proposals?.pending !== job.id) return { status: 'abandoned', outcome: 'the story no longer waits for this answer' };
  const at = s.raw_iocs.proposals.at;
  const [behaviors, evidence] = await Promise.all([store.listBehaviors([s.id]), store.listEvidence([s.id])]);
  const call = proposalCall({ story: s, behaviors, guidance: guidance(evidence), samples: samples(evidence), iocs: s.raw_iocs?.iocs || [] });
  if (call.skipped) {
    await store.updateStory(s.id, { raw_iocs: { ...s.raw_iocs, proposed_queries: [], proposals: { at, model_tier: null, model: null, cost_usd: 0, skipped: call.skipped, dropped: [] } } });
    return { status: 'abandoned', outcome: call.skipped };
  }
  // the tier it was submitted on, whatever the spend is now
  call.model_tier = job.payload?.model_tier || call.model_tier; call.args.tier = call.model_tier;
  try {
    const answer = r.status === 'ok' ? r : await callStructured({ ...call.args, messages: call.messages });
    const out = await finishProposalAnswer(call, answer);
    await store.updateStory(s.id, { raw_iocs: { ...s.raw_iocs, proposed_queries: out.proposals,
      proposals: { at, finished_at: new Date(ctx.now).toISOString(), model_tier: out.model_tier, model: out.model, cost_usd: Number(out.cost.toFixed(4)), skipped: null, dropped: out.dropped, batched: r.status === 'ok' } } });
    if (job.run_id) {
      await addRunUsage(store, job.run_id, { tier: 'propose', cost: out.cost, usage: out.usage, model: out.model });
      const cur = await store.getRun(job.run_id);
      if (cur) await store.updateRun(job.run_id, { counts: { ...cur.counts, ...(await proposalCounts(store, job.run_id)) } });
    }
    return { status: 'done', outcome: r.status === 'ok' ? null : `live: ${r.error}`, cost: out.cost };
  } catch (e) {
    await store.updateStory(s.id, { raw_iocs: { ...s.raw_iocs, proposed_queries: [], proposals: { at, error: String(e?.message || e).slice(0, 400) } } });
    return { status: 'failed', outcome: String(e?.message || e).slice(0, 300) };
  }
}

async function finishDraftJob(store, job, r, ctx) {
  const p = job.payload || {};
  const run = job.run_id ? await store.getRun(job.run_id) : null;
  if (!run) return { status: 'abandoned', outcome: 'the run is gone' };
  if (!ctx.digests.has(run.id)) ctx.digests.set(run.id, await buildDigestData(store, run));
  const d = ctx.digests.get(run.id);
  const s = d.analyzed.find((x) => x.id === job.story_id);
  if (!s) return { status: 'abandoned', outcome: 'the story is no longer in its brief' };
  const thread = threadOf(s, d.priorById);
  const existing = p.existing_id ? await store.getCardDraft(p.existing_id) : null;
  if (p.existing_id && (!existing || !['promoted', 'draft'].includes(existing.status))) return { status: 'abandoned', outcome: 'the version this revises is no longer the head' };
  // another version appeared meanwhile (a live call, or an earlier answer): this one is stale
  const rows = await store.listCardDrafts({ storyIds: thread.map((x) => x.id), limit: 5 });
  const head = p.reissue ? rows.find((x) => x.status === 'draft') || null : rows.find((x) => x.status === 'promoted') || rows.find((x) => x.status === 'draft') || null;
  if ((head?.id || null) !== (existing?.id || null)) return { status: 'abandoned', outcome: 'another version was written meanwhile' };
  const card = p.reissue ? activeCards().find((c) => c.slug === p.card_slug) || null : null;
  if (p.reissue && !card) return { status: 'abandoned', outcome: 'the hand-written card is no longer active' };
  const changes = p.changes || [];
  const req = draftRequest({ story: s, thread, data: d, score: p.score || 0, reasons: p.reasons || [], prior: existing, changes, card });
  const answer = r.status === 'ok' ? r : await callStructured({ ...req.args, messages: req.messages });
  const out = await finishDraftAnswer(req, answer, { thread, prior: existing, changes, card });
  const counts = sweepCounts();
  let made;
  if (p.reissue) {
    made = await finishReissueDraft(store, { story: s, thread, card, existing, changes, devs: p.devs || [], link: p.link, r: out, now: ctx.now, counts });
  } else {
    ctx.kev ??= await fetchKevEntries(ctx.fetchImpl);
    let takenSlugs = new Set();
    try { takenSlugs = new Set((await store.listCardDrafts({ limit: 200 })).map((x) => x.promoted_slug).filter(Boolean)); } catch { /* none */ }
    made = await finishCardDraft(store, { story: s, thread, data: d, score: p.score || 0, reasons: p.reasons || [], existing, held: { facts: p.held || [] }, facts: p.facts || [], surfaced: !!p.surfaced, link: p.link,
      r: { ...out, changes }, fetchImpl: ctx.fetchImpl, cache: ctx.cache, now: ctx.now, counts, kevFull: ctx.kev, takenSlugs });
  }
  // the story's hype state points at its newest version, as the live sweep would have left it
  try { const cur = await store.getStory(s.id); await store.updateStory(s.id, { raw_iocs: { ...(cur?.raw_iocs || {}), hype: { ...(cur?.raw_iocs?.hype || {}), draft_id: made.id } } }); } catch { counts.errors++; }
  return { status: 'done', outcome: r.status === 'ok' ? null : `live: ${r.error}`, cost: out.cost + (counts.cost - out.cost) };
}
