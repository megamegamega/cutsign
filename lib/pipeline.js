// The stage machine. `runs.stage` is always the last stage that COMPLETED; each step below does the
// work to reach the next stage and is idempotent, so a run killed mid-step simply repeats that step on
// the next tick. Long steps (fetch, extract) check the time budget and yield partway — the work they
// finished is already persisted, so the next invocation picks up where they stopped.
//
//   received → parsed → fetched → extracted → normalized → validated* → queried* → rendered* → sent
//   (* v1/v2 seams: pass-through in v0)

import { parseMime, parseBrief, selectItems } from './parse-brief.js';
import { fetchSource, usable, isPrimary } from './fetch-source.js';
import { extractStory } from './extract.js';
import { normalizeIoc } from './normalize.js';
import { buildDigestData, renderDigest } from './render.js';
import { sendDigest } from './email.js';
import { postDiscord } from './discord.js';

export const STAGES = ['received', 'parsed', 'fetched', 'extracted', 'normalized', 'validated', 'queried', 'rendered', 'sent'];
const next = (s) => STAGES[STAGES.indexOf(s) + 1];
const MAX_ATTEMPTS = 3;

const env = (k, d) => (process.env[k] === undefined || process.env[k] === '' ? d : process.env[k]);
const num = (k, d) => Number(env(k, d));

// ---------------------------------------------------------------------------
// Steps. Each returns { done: boolean, counts?: {...} }. ctx = { store, run, remainingMs(), fetchImpl }

async function stepParse({ store, run }) {
  const brief = await store.getBrief(run.brief_id);
  const mime = await parseMime(brief.raw_mime);
  const parsed = parseBrief(mime);
  await store.updateBrief(brief.id, { clean_text: parsed.cleanText, urls: parsed.urls });
  const selected = selectItems(parsed.items, num('MAX_STORIES', 5));
  await store.upsertStories(parsed.items.map((i) => ({
    run_id: run.id, ordinal: i.ordinal, section: i.section, severity: i.severity,
    brief_text: (i.label ? `${i.label}: ` : '') + i.text,
    title: i.label || i.text.slice(0, 90),
    source_urls: i.urls,
    selected: selected.has(i.ordinal),
    status: selected.has(i.ordinal) ? 'pending' : 'skipped',
  })));
  if (!parsed.items.length) throw new Error('parsed 0 items from the brief — format changed?');
  return { done: true, counts: { items: parsed.items.length, selected: selected.size } };
}

const FRESH_MS = 7 * 86400000;

async function getOrFetch(store, url, fetchImpl) {
  const cached = await store.getSource(url);
  if (cached?.fetched_at && Date.now() - new Date(cached.fetched_at) < FRESH_MS && (cached.outcome === 'ok' || cached.outcome === 'too_large')) return cached;
  const row = await fetchSource(url, { fetchImpl });
  await store.upsertSource(row);
  return row;
}

async function stepFetch({ store, run, remainingMs, fetchImpl }) {
  const stories = (await store.listStories(run.id)).filter((s) => s.selected);
  const cap = num('MAX_SOURCES', 12);
  const PER_STORY = 2;
  // round-robin: every story's first link before anyone's second
  const plan = [];
  for (let k = 0; k < PER_STORY; k++) for (const s of stories) if (s.source_urls[k]) plan.push([s, s.source_urls[k]]);
  const seen = new Set();
  let fetched = 0;
  for (const [, url] of plan) {
    if (seen.has(url) || seen.size >= cap) continue;
    if (remainingMs() < 25_000) return { done: false };
    seen.add(url); await getOrFetch(store, url, fetchImpl); fetched++;
  }
  // one hop: a news page that links to a primary source (vendor/CERT) gets that page too
  for (const s of stories) {
    if (seen.size >= cap) break;
    const srcs = await store.getSources(s.source_urls.slice(0, PER_STORY));
    if (srcs.some((x) => usable(x) && isPrimary(x.final_url || x.url))) continue;
    const hop = srcs.filter(usable).flatMap((x) => x.links)
      .find((l) => isPrimary(l) && !s.source_urls.includes(l) && !/\/(tag|tags|category|author|search)\//.test(l));
    if (!hop || seen.has(hop)) continue;
    if (remainingMs() < 25_000) return { done: false };
    seen.add(hop); await getOrFetch(store, hop, fetchImpl); fetched++;
    await store.updateStory(s.id, { source_urls: [...s.source_urls.slice(0, PER_STORY), hop] });
  }
  // record per-story suspicious sources; trim each story's list to what was actually planned
  let ok = 0; let failed = 0; let suspicious = 0;
  for (const s of await store.listStories(run.id)) {
    if (!s.selected) continue;
    const urls = s.source_urls.filter((u) => seen.has(u));
    const srcs = await store.getSources(urls);
    for (const x of srcs) { if (x.suspicious) suspicious++; else if (usable(x)) ok++; else failed++; }
    await store.updateStory(s.id, { source_urls: urls, suspicious_sources: srcs.filter((x) => x.suspicious).map((x) => x.url) });
  }
  return { done: true, counts: { sources_ok: ok, sources_failed: failed, sources_suspicious: suspicious } };
}

const EXTRACT_RESERVE_MS = 150_000; // an extraction call can take ~2 min; don't start one without room

async function stepExtract(ctx) {
  const { store, run, remainingMs } = ctx;
  const stories = (await store.listStories(run.id)).filter((s) => s.selected);
  for (const s of stories.filter((x) => x.status === 'pending')) {
    if (remainingMs() < EXTRACT_RESERVE_MS) return { done: false };
    const sources = (await store.getSources(s.source_urls)).filter(usable);
    try {
      const r = await extractStory(s, sources);
      const d = r.data;
      let priority = d.story.priority;
      // deterministic floor: exploited-in-the-wild with huntable behavior, or KEV-listed → act today
      if ((/actively exploited/i.test(s.section || '') && d.behaviors.length) || /\bKEV\b/.test(s.brief_text || '')) priority = 1;
      await store.replaceStoryChildren(s.id, {
        behaviors: d.behaviors.map((b) => ({ attack_technique: b.attack_technique, pattern_kind: b.pattern_kind, parent: b.parent,
          children: b.children, log_source: b.log_source, time_window: b.time_window, vendor_stated: b.vendor_stated, source_quote_ref: b.source_quote_ref })),
        evidence: [
          ...d.detection_guidance.map((g) => ({ kind: 'guidance', raw: (g.verbatim_query ? `${g.description}\n${g.verbatim_query}` : g.description).slice(0, 2048),
            log_source: g.log_source, attack_technique: g.attack_technique, url: g.url, publisher_tier: g.publisher_tier, source_quote_ref: null })),
          ...d.evidence_samples.map((e) => ({ kind: e.kind, raw: e.raw.slice(0, 2048), log_source: e.log_source_guess,
            attack_technique: e.attack_technique, url: null, publisher_tier: null, source_quote_ref: e.source_quote_ref })),
        ],
      });
      const pub = d.story.earliest_published && /^\d{4}-\d{2}-\d{2}$/.test(d.story.earliest_published) ? d.story.earliest_published : null;
      await store.updateStory(s.id, {
        status: 'extracted', extract_error: null,
        title: d.story.title, summary: d.story.summary, threat_actor: d.story.threat_actor, malware_family: d.story.malware_family,
        cves: d.story.cves.map((c) => c.toUpperCase()), attack_techniques: d.story.attack_techniques, sector_relevance: d.story.sector_relevance,
        priority, priority_reason: priority !== d.story.priority ? `${d.story.priority_reason} (raised to P1: exploited + behaviors/KEV)` : d.story.priority_reason,
        first_published_at: pub, raw_iocs: { iocs: d.iocs, more_sources: d.more_sources },
      });
      await addUsage(ctx, r);
    } catch (e) {
      await store.updateStory(s.id, { status: 'failed', extract_error: String(e?.message || e).slice(0, 500) });
    }
  }
  const after = (await store.listStories(run.id)).filter((s) => s.selected);
  const extracted = after.filter((s) => s.status === 'extracted').length;
  const failedN = after.filter((s) => s.status === 'failed').length;
  if (after.length && !extracted) throw new Error(`every story failed extraction (first error: ${after.find((s) => s.extract_error)?.extract_error})`);
  return { done: true, counts: { stories: extracted, stories_failed: failedN } };
}

async function addUsage(ctx, r) {
  const cur = await ctx.store.getRun(ctx.run.id);
  await ctx.store.updateRun(ctx.run.id, {
    model: r.model, tokens_in: cur.tokens_in + r.usage.in, tokens_out: cur.tokens_out + r.usage.out,
    cost_usd: Math.round((Number(cur.cost_usd) + r.cost) * 10000) / 10000,
  });
}

async function stepNormalize({ store, run }) {
  const stories = (await store.listStories(run.id)).filter((s) => s.status === 'extracted');
  let dropped = 0; const linked = new Set(); const fresh = new Set();
  for (const s of stories) {
    for (const i of s.raw_iocs?.iocs || []) {
      const n = normalizeIoc(i.type, i.value);
      if (n.drop) { dropped++; continue; }
      let row = await store.getIoc(n.type, n.value_norm);
      if (!row) {
        row = await store.insertIoc({ type: n.type, value: i.value, value_norm: n.value_norm, first_seen_run_id: run.id,
          last_seen_run_id: run.id, seen_count: 1, confidence: i.confidence, context: i.context });
      } else if (row.last_seen_run_id !== run.id) {
        // counted once per run, so a crash-and-resume never double-counts
        await store.updateIoc(row.id, { seen_count: row.seen_count + 1, last_seen_run_id: run.id });
      }
      await store.linkStoryIoc(s.id, row.id, (i.role || 'unknown').slice(0, 60));
      linked.add(row.id); if (row.first_seen_run_id === run.id) fresh.add(row.id);
    }
  }
  return { done: true, counts: { iocs: linked.size, iocs_new: fresh.size, iocs_repeat: linked.size - fresh.size, iocs_dropped: dropped } };
}

const passThrough = async () => ({ done: true });

async function stepSend({ store, run }) {
  const data = await buildDigestData(store, run);
  const { subject, html, text } = renderDigest(data);
  const cap = num('MAX_MONTHLY_USD', 25);
  const spent = await store.monthCostUsd();
  if (run.dry) return { done: true, counts: { emailed: false, subject } };
  if (spent > cap) {
    await postDiscord(`Cutsign ⚠ monthly spend $${spent.toFixed(2)} is over the $${cap} cap — extracted but NOT emailing (${data.date}). Raise MAX_MONTHLY_USD to resume.`);
    return { done: true, counts: { emailed: false, over_cap: true, subject } };
  }
  await sendDigest({ subject, html, text });
  return { done: true, counts: { emailed: true, subject } };
}

const STEPS = {
  received: stepParse, parsed: stepFetch, fetched: stepExtract, extracted: stepNormalize,
  normalized: passThrough, validated: passThrough, queried: passThrough, rendered: stepSend,
};

// ---------------------------------------------------------------------------

/**
 * Advance one run as far as the time budget allows.
 * Returns 'sent' | 'yielded' | 'failed'.
 */
export async function advanceRun(store, runId, { deadline, fetchImpl } = {}) {
  const remainingMs = () => (deadline ? deadline - Date.now() : Infinity);
  let run = await store.getRun(runId);
  let stage = run.stage === 'failed' ? STAGES[Math.max(0, STAGES.indexOf(run.failed_stage) - 1)] : run.stage;
  const t0 = Date.now();
  while (stage !== 'sent') {
    const target = next(stage);
    try {
      run = await store.getRun(runId);
      const r = await STEPS[stage]({ store, run, remainingMs, fetchImpl });
      if (r.counts) {
        const cur = await store.getRun(runId);
        await store.updateRun(runId, { counts: { ...cur.counts, ...r.counts } });
      }
      if (!r.done) {
        const cur = await store.getRun(runId);
        await store.updateRun(runId, { counts: { ...cur.counts, active_ms: (cur.counts.active_ms || 0) + (Date.now() - t0) } });
        return 'yielded';
      }
      stage = target;
      await store.updateRun(runId, { stage, error: null, failed_stage: null });
    } catch (e) {
      const cur = await store.getRun(runId);
      const attempts = (cur.attempts || 0) + 1;
      const msg = String(e?.message || e).slice(0, 500);
      await store.updateRun(runId, { stage: 'failed', failed_stage: target, attempts, error: msg, finished_at: new Date().toISOString() });
      const brief = await store.getBrief(cur.brief_id);
      await postDiscord(`Cutsign ✖ ${brief.brief_date || ''} stage=${target} error=${msg.slice(0, 300)} (attempt ${attempts}/${MAX_ATTEMPTS}${attempts >= MAX_ATTEMPTS ? ', giving up' : ', will retry next tick'})`);
      return 'failed';
    }
  }
  const done = await store.getRun(runId);
  const c = { ...done.counts, active_ms: (done.counts.active_ms || 0) + (Date.now() - t0) };
  await store.updateRun(runId, { counts: c, finished_at: new Date().toISOString() });
  const brief = await store.getBrief(done.brief_id);
  const bits = [
    `${c.stories ?? 0} stories`, `${c.iocs ?? 0} IoCs (${c.iocs_new ?? 0} new)`,
    c.stories_failed ? `${c.stories_failed} failed extraction` : null,
    c.sources_suspicious ? `${c.sources_suspicious} suspicious source(s)` : null,
    `${c.sources_ok ?? 0}/${(c.sources_ok ?? 0) + (c.sources_failed ?? 0)} sources`,
    `$${Number(done.cost_usd).toFixed(2)}`, `${Math.round(c.active_ms / 1000)}s`,
  ].filter(Boolean);
  await postDiscord(`Cutsign ✔ ${brief.brief_date || ''}${done.dry ? ' (dry — no email)' : c.over_cap ? ' (over cap — no email)' : ''} · ${bits.join(' · ')}`);
  return 'sent';
}

/** Advance every open run, oldest first. Returns true if work remains (caller should chain). */
export async function driveRuns(store, { deadline, fetchImpl } = {}) {
  let remaining = false;
  for (const r of await store.listOpenRuns()) {
    if (deadline && deadline - Date.now() < 30_000) { remaining = true; break; }
    const leaseSecs = deadline ? Math.ceil((deadline - Date.now()) / 1000) + 30 : 900;
    const claimed = await store.claimRun(r.id, leaseSecs);
    if (!claimed) continue; // another invocation has it
    try {
      const out = await advanceRun(store, r.id, { deadline, fetchImpl });
      if (out === 'yielded') remaining = true;
    } finally {
      await store.releaseRun(r.id);
    }
  }
  return remaining;
}
