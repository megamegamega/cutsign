// The stage machine. `runs.stage` is always the last stage that COMPLETED; each step below does the
// work to reach the next stage and is idempotent, so a run killed mid-step simply repeats that step on
// the next tick. Long steps (fetch, extract) check the time budget and yield partway — the work they
// finished is already persisted, so the next invocation picks up where they stopped.
//
//   received → parsed → fetched → extracted → normalized → validated* → queried* → rendered* → sent
//   (* v1/v2 seams: pass-through in v0)

import { parseMime, parseBrief } from './parse-brief.js';
import { scoreStory, pickDeep } from './select.js';
import { fetchSource, usable, isPrimary } from './fetch-source.js';
import { extractStory } from './extract.js';
import { normalizeIoc } from './normalize.js';
import { fingerprint, findUpdatedStory } from './diff.js';
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
  // Every item gets a light read; which ones earn the deep read is decided after that, from the sources.
  await store.upsertStories(parsed.items.map((i) => ({
    run_id: run.id, ordinal: i.ordinal, section: i.section, severity: i.severity,
    brief_text: (i.label ? `${i.label}: ` : '') + i.text,
    title: i.label || i.text.slice(0, 90),
    source_urls: i.urls,
    selected: false,
    status: 'pending',
  })));
  if (!parsed.items.length) throw new Error('parsed 0 items from the brief — format changed?');
  return { done: true, counts: { items: parsed.items.length } };
}

const FRESH_MS = 7 * 86400000;
const FETCH_RESERVE_MS = 25_000;

async function getOrFetch(store, url, fetchImpl) {
  const cached = await store.getSource(url);
  if (cached?.fetched_at && Date.now() - new Date(cached.fetched_at) < FRESH_MS && (cached.outcome === 'ok' || cached.outcome === 'too_large')) return cached;
  const row = await fetchSource(url, { fetchImpl });
  await store.upsertSource(row);
  return row;
}

/** Light pass: each story's FIRST link only (the brief's own "Source"). */
async function stepFetch({ store, run, remainingMs, fetchImpl }) {
  const all = await store.listStories(run.id);
  const cap = num('MAX_SOURCES', 40);
  const seen = new Set();
  for (const s of all) {
    const url = s.source_urls[0];
    if (!url || seen.has(url) || seen.size >= cap) continue;
    if (remainingMs() < FETCH_RESERVE_MS) return { done: false };
    seen.add(url); await getOrFetch(store, url, fetchImpl);
  }
  let ok = 0; let failed = 0; let suspicious = 0;
  for (const s of all) {
    const urls = s.source_urls[0] && seen.has(s.source_urls[0]) ? [s.source_urls[0]] : [];
    const srcs = await store.getSources(urls);
    for (const x of srcs) { if (x.suspicious) suspicious++; else if (usable(x)) ok++; else failed++; }
    // keep the remaining brief links for a possible deep read; record which fetched source is suspicious
    await store.updateStory(s.id, { suspicious_sources: srcs.filter((x) => x.suspicious).map((x) => x.url) });
  }
  return { done: true, counts: { sources_ok: ok, sources_failed: failed, sources_suspicious: suspicious } };
}

/** Deep pass: the selected story's second brief link, plus one hop from a news page to a linked vendor/CERT page. */
async function fetchDeepSources(store, s, { remainingMs, fetchImpl }) {
  const urls = s.source_urls.slice(0, 2);
  for (const u of urls) {
    if (remainingMs() < FETCH_RESERVE_MS) return null;
    await getOrFetch(store, u, fetchImpl);
  }
  let srcs = await store.getSources(urls);
  if (!srcs.some((x) => usable(x) && isPrimary(x.final_url || x.url))) {
    const hop = srcs.filter(usable).flatMap((x) => x.links)
      .find((l) => isPrimary(l) && !urls.includes(l) && !/\/(tag|tags|category|author|search)\//.test(l));
    if (hop) {
      if (remainingMs() < FETCH_RESERVE_MS) return null;
      await getOrFetch(store, hop, fetchImpl);
      urls.push(hop);
      srcs = await store.getSources(urls);
    }
  }
  await store.updateStory(s.id, { source_urls: urls, suspicious_sources: srcs.filter((x) => x.suspicious).map((x) => x.url) });
  return srcs;
}

// don't start a call without room to finish it (and its one retry)
const EXTRACT_RESERVE_MS = { deep: 150_000, light: 60_000 };
const LIGHT_CONCURRENCY = 4;

/** Persist one extraction result for a story. */
async function saveExtraction(ctx, s, r) {
  const { store } = ctx;
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
    first_published_at: pub,
    raw_iocs: { iocs: d.iocs, more_sources: d.more_sources, selection: s.raw_iocs?.selection || null },
  });
  await addUsage(ctx, r);
}

/**
 * Three phases, each resumable:
 *  1. light read (Haiku) of every pending, unselected story — a few at a time
 *  2. score every story on what the light read found; mark the top MAX_STORIES for the deep read
 *  3. fetch extra sources for the selected stories and re-read them with the deep model
 */
async function stepExtract(ctx) {
  const { store, run, remainingMs } = ctx;
  let stories = await store.listStories(run.id);

  // 1. light reads
  const lightQueue = stories.filter((s) => s.status === 'pending' && !s.selected);
  for (let i = 0; i < lightQueue.length; i += LIGHT_CONCURRENCY) {
    if (remainingMs() < EXTRACT_RESERVE_MS.light) return { done: false };
    await Promise.all(lightQueue.slice(i, i + LIGHT_CONCURRENCY).map(async (s) => {
      const sources = (await store.getSources(s.source_urls.slice(0, 1))).filter(usable);
      try {
        await saveExtraction(ctx, s, { ...(await extractStory(s, sources, { tier: 'light' })), tier: 'light' });
      } catch (e) {
        await store.updateStory(s.id, { status: 'failed', extract_error: String(e?.message || e).slice(0, 500) });
      }
    }));
  }

  // 2. selection (once per run)
  const cur = await store.getRun(run.id);
  if (!cur.counts.selection_done) {
    stories = await store.listStories(run.id);
    const done = stories.filter((s) => s.status === 'extracted');
    const ids = done.map((s) => s.id);
    const [behaviors, evidence] = await Promise.all([store.listBehaviors(ids), store.listEvidence(ids)]);
    const scored = [];
    for (const s of done) {
      const sources = await store.getSources(s.source_urls.slice(0, 1));
      const { score, why } = scoreStory({
        story: s, behaviors: behaviors.filter((b) => b.story_id === s.id), evidence: evidence.filter((e) => e.story_id === s.id),
        iocCount: (s.raw_iocs?.iocs || []).length, sources: sources.filter(usable),
      });
      scored.push({ story: s, score, why });
    }
    const deep = new Set(pickDeep(scored, { max: num('MAX_STORIES', 4), min: num('MIN_DEEP_SCORE', 6) }).map((x) => x.story.id));
    for (const { story: s, score, why } of scored) {
      const selection = { score, why, deep: deep.has(s.id) };
      await store.updateStory(s.id, { raw_iocs: { ...(s.raw_iocs || {}), selection }, ...(deep.has(s.id) ? { selected: true, status: 'pending' } : {}) });
    }
    await store.updateRun(run.id, { counts: { ...cur.counts, selection_done: true, deep_selected: deep.size } });
  }

  // 3. deep reads; a failed deep read keeps the light result instead of losing the story
  stories = await store.listStories(run.id);
  for (const s of stories.filter((x) => x.selected && x.status === 'pending')) {
    if (remainingMs() < EXTRACT_RESERVE_MS.deep + FETCH_RESERVE_MS) return { done: false };
    const srcs = await fetchDeepSources(store, s, ctx);
    if (!srcs) return { done: false };
    const fresh = (await store.listStories(run.id)).find((x) => x.id === s.id);
    try {
      await saveExtraction(ctx, fresh, { ...(await extractStory(fresh, srcs.filter(usable), { tier: 'deep' })), tier: 'deep' });
    } catch (e) {
      await store.updateStory(s.id, { status: 'extracted', selected: false, extract_error: `deep read failed, showing quick read: ${String(e?.message || e).slice(0, 400)}` });
    }
  }

  const after = await store.listStories(run.id);
  const extracted = after.filter((s) => s.status === 'extracted').length;
  const failedN = after.filter((s) => s.status === 'failed').length;
  if (after.length && !extracted) throw new Error(`every story failed extraction (first error: ${after.find((s) => s.extract_error)?.extract_error})`);
  return { done: true, counts: { stories: extracted, stories_deep: after.filter((s) => s.selected && s.status === 'extracted').length, stories_failed: failedN } };
}

let usageChain = Promise.resolve();
function addUsage(ctx, r) {
  // light reads run concurrently; serialize the read-modify-write on the run's cost
  usageChain = usageChain.then(() => addUsageNow(ctx, r), () => addUsageNow(ctx, r));
  return usageChain;
}
async function addUsageNow(ctx, r) {
  const cur = await ctx.store.getRun(ctx.run.id);
  const models = new Set(String(cur.model || '').split(',').filter(Boolean)).add(r.model);
  const key = `cost_${r.tier || 'deep'}`;
  const counts = { ...cur.counts, [key]: Math.round(((cur.counts[key] || 0) + r.cost) * 10000) / 10000 };
  await ctx.store.updateRun(ctx.run.id, {
    counts, model: [...models].join(','), tokens_in: cur.tokens_in + r.usage.in, tokens_out: cur.tokens_out + r.usage.out,
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
  const updates = await linkStoryUpdates(store, run, stories);
  return { done: true, counts: { iocs: linked.size, iocs_new: fresh.size, iocs_repeat: linked.size - fresh.size, iocs_dropped: dropped, story_updates: updates } };
}

/** Mark each story that continues one from the trailing 14 days (stories.updates_story_id). Idempotent. */
async function linkStoryUpdates(store, run, stories) {
  const priors = await store.listPriorStories(run.id, 14);
  const links = await store.listStoryIocs([...priors.map((p) => p.id), ...stories.map((s) => s.id)]);
  const iocsOf = (id) => new Set(links.filter((l) => l.story_id === id && l.ioc).map((l) => l.ioc.id));
  const priorSets = priors.map((p) => ({ story: p, iocIds: iocsOf(p.id) }));
  let n = 0;
  for (const s of stories) {
    const prev = findUpdatedStory(s, iocsOf(s.id), priorSets);
    if (prev) n++;
    await store.updateStory(s.id, { fingerprint: fingerprint(s), updates_story_id: prev?.id || null });
  }
  return n;
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
    `${c.stories ?? 0} stories (${c.stories_deep ?? 0} deep)`, `${c.iocs ?? 0} IoCs (${c.iocs_new ?? 0} new)`,
    c.stories_failed ? `${c.stories_failed} failed extraction` : null,
    c.sources_suspicious ? `${c.sources_suspicious} suspicious source(s)` : null,
    `${c.sources_ok ?? 0}/${(c.sources_ok ?? 0) + (c.sources_failed ?? 0)} sources`,
    `$${Number(done.cost_usd).toFixed(2)} (deep $${(c.cost_deep || 0).toFixed(2)}, quick $${(c.cost_light || 0).toFixed(2)})`, `${Math.round(c.active_ms / 1000)}s`,
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
