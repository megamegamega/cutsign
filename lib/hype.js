// Hype score and the card-draft loop: surface the stories a CISO will ask about before they ask,
// from what the pipeline already stores, and keep an AI-generated draft current as the evidence
// changes. hypeScore is pure. hypeSweep runs after each brief is sent and from the hourly watch
// tick when something developed:
//   score ≥ HYPE_NOMINATE  → nominated to Discord (once, again if the score rises by 2)
//   nominated + actionable → an AI draft is generated (lib/carddraft.js); when the evidence
//                            fingerprint changes later, the draft is revised as a new version
//   score ≥ HYPE_SURFACE   → the draft is published as an AI verdict card at /cards/<slug>
//                            (CARD_AUTOPUBLISH, default on): chip on the CISO view, verdict_card in
//                            the agent JSON, listed on the Cards tab, "published" email. Revisions
//                            re-issue it in place; a dismissed draft unpublishes it.
// Every draft carries an automated detection-coverage check (lib/coverage.js: KEV, NVD, scanner
// and distro sources, vendor feeds and changelogs, IDS rules, Nuclei), re-asked daily; a change
// is posted to Discord. Hand-written cards (lib/cards.js) get the same daily check, stored on
// their manifest story row and shown on the card page by lifecycle.js, and an AI re-issue draft
// whenever something develops after their as-of date. No person is in the loop by default.
//
// Signals (tune here; every nomination lists the ones that fired):
//   priority        P1 +2, P2 +1               deep read               +1
//   KEV             +3 when a CVE in the thread was added to CISA KEV within 3 days of the brief
//                   (a listing from months ago scores nothing: it is not news)
//   thread age      +1 per earlier brief in the update chain (max +2)
//   coverage        +1 at 3 distinct publishers across the thread, +1 more at 5
//   primary source  +1 (vendor / CERT page, or tier-A published guidance)
//   exposure        +1 when the sources state internet-facing or edge exposure
//   actor           +1 when an actor is named
//   watch (48 h)    material development +2, public PoC repo +1, two or more new write-ups +1
//
// Actionable (what makes a draft worth writing): published detection guidance, a vendor-stated
// behavior, a fix version, a fresh KEV listing, evidence samples, or new IoCs. A nominated story
// with none of these waits; the loop picks it up the moment one appears.
//
// Backtest over the Oct 15–27 2026 briefs (public JSON + the KEV feed): nominating at 6 fires about
// 1.6 threads a day and would have flagged 5 of the 9 hand-chosen cards, BeyondTrust 7 days and
// PHP2Shell 4 days before they were written; the other four were judgment picks that no score
// reaches. Surfacing at 9 is roughly one every few days.

import { isPrimary } from './fetch-source.js';
import { cardForStory, slugFor, activeCards } from './cards.js';
import { postDiscord } from './discord.js';
import { sendDigest } from './email.js';
import { buildDigestData } from './render.js';
import { draftCard } from './carddraft.js';
import { checkCoverage, coverageTerms, diffCoverage, coverageStale } from './coverage.js';
import { notifyCardPublished, announceHandCards } from './subscribe.js';
import { scannerNames } from './scannernames.js';
import { namedProducts } from './exposure.js';

const num = (k, d) => Number(process.env[k] ?? d);
export const thresholds = () => ({ nominate: num('HYPE_NOMINATE', 6), surface: num('HYPE_SURFACE', 9) });
/** Publish AI drafts that cross the surface bar (default on; CARD_AUTOPUBLISH=0 keeps them as drafts). */
export const autopublish = () => process.env.CARD_AUTOPUBLISH !== '0';
/** Every P1 is drafted and published on day one, whatever its score (CARD_P1_DAY_ONE=0 reverts to score-only). */
export const p1DayOne = () => process.env.CARD_P1_DAY_ONE !== '0';
export const P1_REASON = 'P1: card on day one (score below the publish bar; revised as the story develops)';
const SITE = () => process.env.PUBLIC_BASE_URL || 'https://cutsign.vercel.app';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const DAY = 86_400_000;

const hostOf = (u) => { try { return new URL(u).hostname.replace(/^www\./, '').toLowerCase(); } catch { return ''; } };
const daysBetween = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / DAY);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const sid8 = (id) => `s-${String(id).slice(0, 8)}`;

/** Rows of a story's update chain, oldest first, ending with the story itself. */
export function threadOf(story, priorById = new Map()) {
  const rows = [story];
  const seen = new Set([story.id]);
  let cur = story;
  while (cur.updates_story_id && !seen.has(cur.updates_story_id)) {
    const p = priorById.get(cur.updates_story_id);
    if (!p) break;
    seen.add(p.id); rows.unshift(p); cur = p;
  }
  return rows;
}

const freshKev = (thread, kev, date) => [...new Set(thread.flatMap((r) => r.cves || []))]
  .filter((c) => kev.has(c) && daysBetween(kev.get(c), date) >= -1 && daysBetween(kev.get(c), date) <= 3);
const windowEvents = (thread, events, now) => { const ids = new Set(thread.map((r) => r.id)); return events.filter((e) => ids.has(e.watch_story_id) && now - Date.parse(e.created_at) <= 2 * DAY); };

/**
 * Score one story in the context of its thread. Pure.
 * @param story   analyzed story (priority, selected, cves, threat_actor, raw_iocs.exposure, sources, guidance)
 * @param thread  rows oldest → newest ending with `story` (from threadOf)
 * @param kev     Map cveID → dateAdded (YYYY-MM-DD)
 * @param events  watch events [{ watch_story_id, created_at, kind, level, assessment }]
 * @param day     the brief date (YYYY-MM-DD); @param now ms, for the 48 h watch window
 */
export function hypeScore({ story, thread = [story], kev = new Map(), events = [], day, now = Date.now() }) {
  const reasons = [];
  let score = 0;
  const add = (n, why) => { if (n > 0) { score += n; reasons.push(`${why} +${n}`); } };
  const date = day || story.brief_date || String(story.created_at || '').slice(0, 10);

  if (story.priority === 1) add(2, 'P1'); else if (story.priority === 2) add(1, 'P2');
  if (story.selected) add(1, 'deep read');
  const fresh = freshKev(thread, kev, date);
  if (fresh.length) add(3, `KEV ${fresh.join(', ')}`);
  // days the story has run, not rows: two items in one brief are one day (an undated row counts as its own)
  const dayOf = (r) => r.brief_date || String(r.created_at || '').slice(0, 10) || r.id;
  const days = new Set(thread.map(dayOf)).size;
  if (days > 1) add(Math.min(days - 1, 2), `day ${days} of the story`);

  const urls = thread.flatMap((r) => [...(r.source_urls || []), ...((r.sources || []).map((s) => s.url))]);
  const hosts = new Set(urls.map(hostOf).filter(Boolean));
  if (hosts.size >= 3) add(1, `${hosts.size} publishers`);
  if (hosts.size >= 5) add(1, 'five or more publishers');
  if (urls.some(isPrimary) || (story.guidance || []).some((g) => g.publisher_tier === 'A')) add(1, 'primary source');

  const exposure = JSON.stringify(story.raw_iocs?.exposure || story.exposure || {});
  if (/internet|exposed|public-facing|edge device|vpn|appliance|management interface/i.test(exposure)) add(1, 'internet-facing exposure stated');
  if (story.threat_actor) add(1, 'actor named');

  const win = windowEvents(thread, events, now);
  if (win.some((e) => e.level === 'HIGH' && e.assessment?.material)) add(2, 'material development on watch');
  if (win.some((e) => e.kind === 'poc_repo')) add(1, 'public PoC repo');
  if (win.filter((e) => e.kind === 'new_source').length >= 2) add(1, 'new write-ups on watch');

  return { score, reasons };
}

/** What the evidence currently is, as a comparable object; a draft records the one it was built from. */
export function evidenceFingerprint({ story, thread, kev = new Map(), events = [], day, now = Date.now() }) {
  const date = day || story.brief_date || String(story.created_at || '').slice(0, 10);
  return {
    days: new Set(thread.map((r) => r.brief_date || String(r.created_at || '').slice(0, 10) || r.id)).size,
    guidance: (story.guidance || []).length,
    behaviors: (story.behaviors || []).filter((b) => b.vendor_stated).length,
    samples: (story.samples || []).length,
    iocs: (story.newIocs || []).length + (story.repeatIocs || []).length,
    kev: freshKev(thread, kev, date).sort(),
    fixed_in: story.raw_iocs?.exposure?.fixed_in || null,
    material: windowEvents(thread, events, now).filter((e) => e.level === 'HIGH' && e.assessment?.material).length,
  };
}

/** Human-readable deltas between two fingerprints (what the revision should attend to). */
export function describeChanges(prev, cur) {
  if (!prev) return [];
  const out = [];
  if (cur.days > prev.days) out.push(`the story ran ${cur.days - prev.days} more day${cur.days - prev.days === 1 ? '' : 's'} (now ${cur.days})`);
  if (cur.guidance > prev.guidance) out.push(`${cur.guidance - prev.guidance} new published detection guidance item${cur.guidance - prev.guidance === 1 ? '' : 's'}`);
  if (cur.behaviors > prev.behaviors) out.push(`${cur.behaviors - prev.behaviors} new vendor-stated behavior${cur.behaviors - prev.behaviors === 1 ? '' : 's'}`);
  if (cur.samples > prev.samples) out.push(`${cur.samples - prev.samples} new evidence sample${cur.samples - prev.samples === 1 ? '' : 's'}`);
  if (cur.iocs > prev.iocs) out.push(`${cur.iocs - prev.iocs} new IoC${cur.iocs - prev.iocs === 1 ? '' : 's'}`);
  const newKev = (cur.kev || []).filter((c) => !(prev.kev || []).includes(c));
  if (newKev.length) out.push(`CISA KEV listed ${newKev.join(', ')}`);
  if (cur.fixed_in && cur.fixed_in !== prev.fixed_in) out.push(`a fix version is now stated: ${cur.fixed_in}`);
  if (cur.material > (prev.material || 0)) out.push(`${cur.material - (prev.material || 0)} material development${cur.material - (prev.material || 0) === 1 ? '' : 's'} on watch`);
  return out;
}

/** Is there anything a defender can act on yet? (A draft with nothing to do is noise.) */
export const actionable = (fp) => fp.guidance > 0 || fp.behaviors > 0 || fp.samples > 0 || fp.iocs > 0 || fp.kev.length > 0 || !!fp.fixed_in;

/** CISA KEV as Map cveID → { dateAdded, dueDate }; empty on any failure. */
export async function fetchKevEntries(fetchImpl = fetch) {
  try {
    const r = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return new Map();
    const j = await r.json();
    return new Map((j.vulnerabilities || []).map((v) => [v.cveID, { dateAdded: v.dateAdded, dueDate: v.dueDate || null }]));
  } catch { return new Map(); }
}
/** CISA KEV as Map cveID → dateAdded; empty on any failure (the score then just lacks that signal). */
export async function fetchKev(fetchImpl = fetch) {
  return new Map([...(await fetchKevEntries(fetchImpl))].map(([k, v]) => [k, v.dateAdded]));
}

/**
 * What has happened to a carded campaign since its card's as-of date: a KEV listing of a CVE the
 * card or thread names, or a HIGH watch development. Each has a stable key so it is raised once;
 * re-issuing the card (a later as-of date) clears them all. Pure.
 * @param kev Map cveID → dateAdded or → { dateAdded, dueDate }
 */
export function cardDevelopments({ card, thread, kev = new Map(), events = [] }) {
  const out = [];
  const cves = [...new Set([...(card.cves || []), ...thread.flatMap((r) => r.cves || [])])];
  for (const c of cves) {
    const e = kev.get(c); const added = typeof e === 'string' ? e : e?.dateAdded; const due = typeof e === 'object' ? e?.dueDate : null;
    if (added && added > card.date) out.push({ key: `kev:${c}`, text: `CISA KEV listed ${c} on ${added}${due ? ` (federal due ${due})` : ''}` });
  }
  const ids = new Set(thread.map((r) => r.id));
  for (const e of events) {
    if (!ids.has(e.watch_story_id) || e.level !== 'HIGH') continue;
    const day = String(e.created_at || '').slice(0, 10);
    if (day <= card.date) continue;
    out.push({ key: `event:${e.id || e.created_at}`, text: `${e.kind || 'development'} ${day}: ${String(e.assessment?.summary || e.summary || '').slice(0, 160)}` });
  }
  return out;
}

const missingTable = (e) => /card_drafts/.test(String(e?.message)) && /does not exist|could not find|schema cache/i.test(String(e?.message));
const fpKey = (fp) => JSON.stringify(fp);
const threadCves = (thread) => [...new Set(thread.flatMap((r) => r.cves || []))];
const threadSources = (thread) => [...new Set(thread.flatMap((r) => [...(r.source_urls || []), ...((r.sources || []).map((x) => x.url))]).filter(Boolean))];

/** The automated coverage check for a thread (and, for a hand-written card, the CVEs it names). Never throws. */
async function coverageFor({ story: s, thread, card = null, kev, fetchImpl, cache, now, prev = null, draft = null }) {
  const cves = [...new Set([...(card?.cves || []), ...threadCves(thread)])];
  const title = card?.title || s.title;
  const terms = coverageTerms({ title, malware_family: s.malware_family, threat_actor: s.threat_actor });
  // the software the campaign names, from its title alone (never the actor or malware): the exposure
  // queries fall back to it while NVD has no CPE configuration for the CVEs (lib/exposure.js)
  const affected = (draft?.scope?.affected || []).map((x) => String(x).slice(0, 200));
  const named = namedProducts({ title, affected, exclude: coverageTerms({ malware_family: s.malware_family, threat_actor: s.threat_actor }) });
  try { return await checkCoverage({ cves, terms, named, affected, title, summaryText: draft?.verdict || s.summary || card?.summary || '', namer: scannerNames, sources: threadSources(thread), kev, fetchImpl, cache, now, prev }); }
  catch (e) { return { checked_at: new Date(now).toISOString(), cves, terms, lanes: [], summary: {}, exposure: null, error: String(e?.message || e).slice(0, 200) }; }
}

const covLine = (cov) => (cov?.summary ? `coverage: ${cov.summary.published} published, ${cov.summary.nothing} nothing found, ${cov.summary.unchecked} not checkable` : '');

async function notify({ title, version, score, reasons, verdict, url, link, surfaced, changes, cost, card = null, published = false, coverage = null }) {
  const kind = card ? `AI re-issue draft for card ${card.slug} (v${version})` : published ? (version > 1 ? `AI verdict card re-issued (v${version})` : 'AI verdict card published') : version > 1 ? `AI draft revised (v${version})` : 'AI draft written';
  const head = card ? `Cutsign ▣ ${kind}, $${cost.toFixed(2)}: ${title}` : published ? `Cutsign ▣ ${kind} (score ${score}, $${cost.toFixed(2)}): ${title}` : surfaced ? `Cutsign ▣ AI draft ready to publish (score ${score}): ${title}` : `Cutsign ▣ ${kind} (score ${score}, $${cost.toFixed(2)}): ${title}`;
  const foot = published ? 'AI-generated, published automatically, not human-reviewed; dismiss the draft to unpublish.' : card ? 'AI-generated and unreviewed; the card page links it until the card is re-issued.' : 'AI-generated and unreviewed; published automatically once it crosses the publish bar.';
  await postDiscord(`${head}\n${changes.length ? `Changed: ${changes.join('; ')}\n` : ''}${coverage ? `${covLine(coverage)}\n` : ''}${url}\n${foot}`);
  try {
    await sendDigest({
      subject: published ? `Cutsign ▣ ${kind}: ${title}` : surfaced ? `Cutsign ▣ AI draft ready to publish: ${title}` : `Cutsign ▣ ${kind}: ${title}`,
      html: `<p><b>${esc(title)}</b> — version ${version}, hype score ${score}.</p><ul>${reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`
        + (changes.length ? `<p><b>Changed:</b> ${esc(changes.join('; '))}</p>` : '')
        + (coverage ? `<p>${esc(covLine(coverage))}</p>` : '')
        + `<p>${esc(verdict)}</p><p><a href="${esc(url)}">${published ? 'Open the card' : 'Read the draft'}</a> · <a href="${esc(link)}">the story in the CISO view</a></p>`
        + `<p style="color:#888">${esc(foot)}</p>`,
      text: `${title} — version ${version}, hype score ${score}\n${reasons.map((x) => '- ' + x).join('\n')}\n${changes.length ? `\nChanged: ${changes.join('; ')}\n` : ''}${coverage ? `${covLine(coverage)}\n` : ''}\n${verdict}\n\n${published ? 'Card' : 'Draft'}: ${url}\nStory: ${link}\n\n${foot}`,
    });
  } catch (e) { await postDiscord(`Cutsign ⚠ draft email failed: ${String(e?.message || e).slice(0, 200)}`); return false; }
  return true;
}

/**
 * A carded thread: raise each development after the card's as-of date once (Discord), and write
 * an AI re-issue draft that folds it in, so the card is never silently behind the evidence. The
 * raised keys ride on the story's hype state and are carried forward day to day; a re-issued card
 * (later as-of date) has nothing after it and the slate is clean.
 */
async function reissueCheck(store, { card, story: s, thread, data: d, kev, events, last, link, draft, now, counts, fetchImpl, cache }) {
  const devs = cardDevelopments({ card, thread, kev, events });
  const raised = new Set(last?.card_devs || []);
  const fresh = devs.filter((x) => !raised.has(x.key));
  const state = { card: card.slug, card_devs: devs.map((x) => x.key), at: new Date(now).toISOString(), draft_id: last?.draft_id || null };
  const cardUrl = `${SITE()}/cards/${card.slug}.html`;

  // the hand-written coverage table is a snapshot; the automated check rides on the manifest's
  // story row (the card page reads it from the cards JSON) and is re-asked daily
  let holder = null;
  try { const rows = await store.getStories(card.story_ids); holder = rows.find((r) => r.raw_iocs?.hype?.card_coverage) || rows.find((r) => r.id === card.story_ids.at(-1)) || rows[0] || null; } catch { holder = null; }
  if (!holder) holder = s;
  const prevCov = holder.raw_iocs?.hype?.card_coverage || (holder.id === s.id ? last?.card_coverage : null) || null;
  let cov = prevCov;
  if (coverageStale(prevCov, now)) {
    cov = await coverageFor({ story: s, thread, card, kev, fetchImpl, cache, now, prev: prevCov });
    counts.coverage_checked++;
    const changes = diffCoverage(prevCov, cov);
    if (changes.length) { counts.coverage_changed++; await postDiscord(`Cutsign ▣ coverage changed for card ${card.slug}:\n` + changes.map((x) => `• ${x}`).join('\n') + `\n${cardUrl}`); }
    if (holder.id !== s.id) {
      try { await store.updateStory(holder.id, { raw_iocs: { ...(holder.raw_iocs || {}), hype: { ...(holder.raw_iocs?.hype || {}), card_coverage: cov } } }); } catch { counts.errors++; }
    }
  }
  if (holder.id === s.id && cov) state.card_coverage = cov;

  if (fresh.length) {
    counts.stale++;
    await postDiscord(`Cutsign ▲ card ${card.slug} (as of ${card.date}) has developments after its date:\n` + fresh.map((x) => `• ${x.text}`).join('\n')
      + `\n${cardUrl}\nAn AI re-issue draft follows and is linked from the card page until the card is re-issued.`);
    let existing = null; let canDraft = draft;
    try {
      const rows = await store.listCardDrafts({ storyIds: thread.map((r) => r.id), limit: 5 });
      if (rows.some((r) => r.status === 'dismissed')) canDraft = false;
      existing = rows.find((r) => r.status === 'draft') || null;
    } catch (e) { canDraft = false; if (missingTable(e)) counts.drafts_disabled = 'apply supabase/migrations/0004_card_drafts.sql'; else counts.errors++; }
    if (canDraft) {
      const changes = devs.map((x) => x.text);
      try {
        const r = await draftCard({ story: s, thread, data: d, score: 0, reasons: [`re-issue of card ${card.slug}`], prior: existing, changes, card });
        const made = await store.insertCardDraft({
          story_id: s.id, thread_ids: thread.map((x) => x.id), title: r.draft.title, score: 0, reasons: [`re-issue of card ${card.slug}`],
          draft: r.draft, model: r.model, cost_usd: Number(r.cost.toFixed(4)),
          version: (existing?.version || 0) + 1, supersedes: existing?.id || null, fingerprint: JSON.stringify({ card: card.slug, devs: state.card_devs }),
          surfaced_at: new Date(now).toISOString(),
        });
        if (existing) { await store.updateCardDraft(existing.id, { status: 'superseded' }); counts.revised++; } else counts.drafted++;
        counts.surfaced++; counts.cost += r.cost; state.draft_id = made.id;
        await notify({ title: r.draft.title, version: made.version, score: 0, reasons: changes, verdict: r.draft.verdict, url: `${SITE()}/?view=draft&id=${made.id}`, link, surfaced: true, changes, cost: r.cost, card });
      } catch (e) {
        counts.errors++;
        await postDiscord(`Cutsign ✖ AI re-issue draft failed for card ${card.slug}: ${String(e?.message || e).slice(0, 300)}`);
      }
    }
  }
  try { await store.updateStory(s.id, { raw_iocs: { ...(s.raw_iocs || {}), hype: state } }); } catch { counts.errors++; }
}

/**
 * The daily coverage check for every card the main loop did not reach today: the campaign is not
 * in today's brief, but its card is live and its coverage table must still move. Hand-written
 * cards store the check on a manifest story row; AI cards and surfaced drafts on the draft row.
 */
async function coverageSweep(store, { kev, fetchImpl, cache, now, counts, seenCards, seenDrafts, deadline = Infinity }) {
  // `kev` is the KEV map, or a function that fetches it: the hourly sweep asks for the catalog only
  // once a stale card is actually found, so a quiet hour costs no fetch
  let kevMap = typeof kev === 'function' ? null : kev;
  const kevOf = async () => (kevMap ??= await kev());
  // a hand-written card that appeared since the last sweep is mailed to subscribers once (lib/subscribe.js)
  try { counts.subscribers_notified = (counts.subscribers_notified || 0) + await announceHandCards(store, { now }); } catch { counts.errors++; }
  for (const card of activeCards()) {
    if (seenCards.has(card.slug)) continue;
    if (Date.now() > deadline) { counts.coverage_deferred++; continue; }
    let rows = [];
    try { rows = await store.getStories(card.story_ids); } catch { counts.errors++; continue; }
    if (!rows.length) continue;
    const holder = rows.find((r) => r.raw_iocs?.hype?.card_coverage) || rows.find((r) => r.id === card.story_ids.at(-1)) || rows[0];
    const prev = holder.raw_iocs?.hype?.card_coverage || null;
    if (!coverageStale(prev, now)) continue;
    const cov = await coverageFor({ story: holder, thread: rows, card, kev: await kevOf(), fetchImpl, cache, now, prev });
    counts.cost += cov.exposure?.names_cost_usd || 0;
    counts.coverage_checked++;
    const changes = diffCoverage(prev, cov);
    try { await store.updateStory(holder.id, { raw_iocs: { ...(holder.raw_iocs || {}), hype: { ...(holder.raw_iocs?.hype || {}), card_coverage: cov } } }); } catch { counts.errors++; }
    if (changes.length) { counts.coverage_changed++; await postDiscord(`Cutsign ▣ coverage changed for card ${card.slug}:\n` + changes.map((x) => `• ${x}`).join('\n') + `\n${SITE()}/cards/${card.slug}.html`); }
  }
  let heads = [];
  try { heads = [...await store.listCardDrafts({ status: 'promoted', limit: 100 }), ...(await store.listCardDrafts({ status: 'draft', limit: 50 })).filter((r) => r.surfaced_at)]; } catch { return; }
  for (const head of heads) {
    if (seenDrafts.has(head.id) || !coverageStale(head.draft?.coverage, now)) continue;
    if (Date.now() > deadline) { counts.coverage_deferred++; continue; }
    let thread = [];
    try { thread = await store.getStories(head.thread_ids || []); } catch { thread = []; }
    const story = thread.at(-1) || { title: head.title };
    const cov = await coverageFor({ story, thread: thread.length ? thread : [{ cves: head.draft?.cves || [] }], kev: await kevOf(), fetchImpl, cache, now, prev: head.draft?.coverage || null, draft: head.draft });
    counts.cost += cov.exposure?.names_cost_usd || 0;
    counts.coverage_checked++;
    const changes = diffCoverage(head.draft?.coverage, cov);
    try { await store.updateCardDraft(head.id, { draft: { ...(head.draft || {}), coverage: cov } }); } catch { counts.errors++; }
    if (changes.length) {
      counts.coverage_changed++;
      const url = head.status === 'promoted' && head.promoted_slug ? `${SITE()}/cards/${head.promoted_slug}` : `${SITE()}/?view=draft&id=${head.id}`;
      await postDiscord(`Cutsign ▣ coverage changed for ${head.status === 'promoted' ? `AI card ${head.promoted_slug}` : `AI draft "${head.title}"`}:\n` + changes.map((x) => `• ${x}`).join('\n') + `\n${url}`);
    }
  }
}

/**
 * The coverage sweep on its own, for the hourly watch tick: no scoring, no drafting, no models. It
 * re-checks whatever card is stale right now (a check older than RECHECK_MS, or one made before a
 * Shodan key existed) and stops starting new cards past `deadline`; the rest wait for the next hour.
 * The KEV catalog is fetched only once a stale card is found, so a quiet hour costs nothing.
 */
export async function coverageOnlySweep(store, { fetchImpl = fetch, now = Date.now(), deadline = Infinity } = {}) {
  const counts = { coverage_checked: 0, coverage_changed: 0, coverage_deferred: 0, cost: 0, errors: 0 };
  const cache = new Map();
  try {
    await coverageSweep(store, { kev: () => fetchKevEntries(fetchImpl), fetchImpl, cache, now, counts, seenCards: new Set(), seenDrafts: new Set(), deadline });
  } catch (e) {
    // a sweep that dies is said, not swallowed: the hourly tick has no other reader
    counts.errors++; counts.error = String(e?.message || e).slice(0, 200);
    try { await postDiscord(`Cutsign ⚠ coverage sweep error=${counts.error}`); } catch { /* nothing more to do */ }
  }
  return counts;
}

/**
 * Score every story of a run; nominate, draft, revise, surface. Never throws for one story's sake:
 * a failed draft is reported and the sweep continues. Returns counts.
 * @param run     the run to sweep (its digest data is built unless `data` is passed)
 */
export async function hypeSweep(store, { run, data = null, fetchImpl = fetch, now = Date.now(), draft = true } = {}) {
  const d = data || await buildDigestData(store, run);
  const t = thresholds();
  const kevFull = await fetchKevEntries(fetchImpl);                       // cve → { dateAdded, dueDate }
  const kev = new Map([...kevFull].map(([k, v]) => [k, v.dateAdded]));   // cve → dateAdded, for the score
  let events = [];
  try { events = await store.listWatchEvents({ since: new Date(now - 2 * DAY).toISOString() }); } catch { /* watches table missing */ }
  const counts = { scored: 0, carded: 0, stale: 0, nominated: 0, drafted: 0, revised: 0, surfaced: 0, published: 0, waiting: 0, coverage_checked: 0, coverage_changed: 0, coverage_deferred: 0, cost: 0, errors: 0 };
  const seen = new Set();
  const lookup = (id) => d.priorById?.get(id) || null;
  const cache = new Map(); // one sweep asks each coverage feed once
  const seenCards = new Set(); const seenDrafts = new Set(); // what the main loop covered today
  // slugs already in use by published (or once-published) AI cards, so a new card never takes one
  let takenSlugs = new Set();
  try { takenSlugs = new Set((await store.listCardDrafts({ limit: 200 })).map((r) => r.promoted_slug).filter(Boolean)); } catch { /* table missing: handled below */ }

  for (const s of d.analyzed) {
    // a later item in today's brief carries this thread (same-brief siblings, lib/diff.js linkSiblings): score it there, once, with both rows
    if (d.analyzed.some((x) => x.updates_story_id === s.id)) continue;
    const thread = threadOf(s, d.priorById);
    if (seen.has(thread[0].id)) continue;
    seen.add(thread[0].id);
    counts.scored++;

    // last recorded verdict for this thread: on this row, or on the row it updates
    let last = s.raw_iocs?.hype || null;
    if (!last && s.updates_story_id) { try { last = (await store.getStory(s.updates_story_id))?.raw_iocs?.hype || null; } catch { last = null; } }
    const link = `${SITE()}/?view=ciso&d=${encodeURIComponent(d.date)}#${sid8(s.id)}`;

    const card = cardForStory(s, lookup);
    if (card) { // a hand-written card exists: no scoring, but it must not go stale on its own
      counts.carded++; seenCards.add(card.slug);
      await reissueCheck(store, { card, story: s, thread, data: d, kev: kevFull, events, last, link, draft, now, counts, fetchImpl, cache });
      continue;
    }
    const { score, reasons } = hypeScore({ story: s, thread, kev, events, day: d.date, now });
    // a P1 gets its card on day one: the score measures how a story is developing, and a reader
    // who sees a P1 in the brief needs a link that day, not after the corroboration arrives
    const p1 = p1DayOne() && s.priority === 1;
    if (score < t.nominate && !p1) continue;
    if (p1 && score < t.surface) reasons.push(P1_REASON);

    // `existing` is the thread's current head: an unpublished draft, or the published card's current version
    let existing = null; let canDraft = draft; let dismissed = false;
    try {
      const rows = await store.listCardDrafts({ storyIds: thread.map((r) => r.id), limit: 5 });
      dismissed = rows.some((r) => r.status === 'dismissed');
      existing = rows.find((r) => r.status === 'promoted') || rows.find((r) => r.status === 'draft') || null;
    } catch (e) { if (missingTable(e)) { canDraft = false; counts.drafts_disabled = 'apply supabase/migrations/0004_card_drafts.sql'; } else { counts.errors++; canDraft = false; } }
    const headUrl = (row) => (row.status === 'promoted' && row.promoted_slug ? `${SITE()}/cards/${row.promoted_slug}` : `${SITE()}/?view=draft&id=${row.id}`);

    const rose = !last || score >= Number(last.score || 0) + 2;
    if (rose) {
      counts.nominated++;
      await postDiscord(`Cutsign ▲ card candidate (score ${score}): ${s.title}\n` + reasons.map((r) => `• ${r}`).join('\n')
        + `\n${link}` + (existing ? `\n${existing.status === 'promoted' ? 'AI card' : 'AI draft'}: ${headUrl(existing)}` : ''));
    }

    const fp = evidenceFingerprint({ story: s, thread, kev, events, day: d.date, now });
    const surfaced = score >= t.surface || p1;
    // published once it crosses the bar, or on day one for a P1 (unless autopublish is off); a published card stays published through revisions
    const slugOf = (title) => existing?.promoted_slug || (() => { const x = slugFor(title, String(d.date).slice(0, 4), takenSlugs); takenSlugs.add(x); return x; })();
    let made = null;
    if (canDraft && !dismissed && actionable(fp) && (!existing || existing.fingerprint !== fpKey(fp))) {
      // first draft, or the evidence moved since the last one: write / revise
      const prev = existing?.fingerprint ? JSON.parse(existing.fingerprint) : null;
      const changes = describeChanges(prev, fp);
      try {
        const r = await draftCard({ story: s, thread, data: d, score, reasons, prior: existing, changes });
        const coverage = await coverageFor({ story: s, thread, kev: kevFull, fetchImpl, cache, now, prev: existing?.draft?.coverage || null, draft: r.draft });
        counts.cost += coverage.exposure?.names_cost_usd || 0;
        counts.coverage_checked++;
        const publish = existing?.status === 'promoted' || (surfaced && autopublish());
        const slug = publish ? slugOf(r.draft.title) : null;
        made = await store.insertCardDraft({
          story_id: s.id, thread_ids: thread.map((x) => x.id), title: r.draft.title, score, reasons,
          draft: { ...r.draft, cves: threadCves(thread), coverage }, model: r.model, cost_usd: Number(r.cost.toFixed(4)),
          version: (existing?.version || 0) + 1, supersedes: existing?.id || null, fingerprint: fpKey(fp),
          surfaced_at: surfaced || publish ? new Date(now).toISOString() : null,
          status: publish ? 'promoted' : 'draft', promoted_slug: slug,
        });
        if (existing) { await store.updateCardDraft(existing.id, { status: 'superseded' }); counts.revised++; } else counts.drafted++;
        if (surfaced) counts.surfaced++;
        if (publish) counts.published++;
        // the card's first publication (a revision of a published card is not news to subscribers)
        if (publish && existing?.status !== 'promoted') {
          try { counts.subscribers_notified = (counts.subscribers_notified || 0) + await notifyCardPublished(store, { title: r.draft.title, url: `${SITE()}/cards/${slug}`, summary: r.draft.verdict, lane: r.draft.lane, priority: r.draft.triage?.priority || '', kind: 'ai' }); } catch { counts.errors++; }
        }
        counts.cost += r.cost;
        await notify({ title: r.draft.title, version: made.version, score, reasons, verdict: r.draft.verdict, url: headUrl(made), link, surfaced, changes, cost: r.cost, published: publish, coverage });
      } catch (e) {
        counts.errors++;
        await postDiscord(`Cutsign ✖ AI draft failed for "${s.title}": ${String(e?.message || e).slice(0, 300)}`);
      }
    } else if (existing && existing.status === 'draft' && (surfaced || existing.surfaced_at) && (!existing.surfaced_at || autopublish())) {
      // nothing new to write, but the draft crossed the bar (or autopublish was turned on since): show / publish it
      try {
        const patch = {};
        if (!existing.surfaced_at) { patch.surfaced_at = new Date(now).toISOString(); counts.surfaced++; }
        if (autopublish()) { patch.status = 'promoted'; patch.promoted_slug = slugOf(existing.title); counts.published++; }
        await store.updateCardDraft(existing.id, patch);
        Object.assign(existing, patch);
        await notify({ title: existing.title, version: existing.version || 1, score, reasons, verdict: existing.draft?.verdict || '', url: headUrl(existing), link, surfaced: true, changes: [], cost: 0, published: patch.status === 'promoted', coverage: existing.draft?.coverage || null });
      } catch { counts.errors++; }
    } else if (canDraft && !dismissed && !existing && !actionable(fp)) {
      counts.waiting++;
      // a P1 with nothing to act on yet still gets a line and a link; the card follows the first actionable fact
      if (p1 && rose) await postDiscord(`Cutsign ▲ P1 without anything actionable yet (no guidance, behaviors, samples, IoCs, fresh KEV or fix version): ${s.title}\nThe card is written the day one of those lands.\n${link}`);
    }

    // the head's coverage check is re-asked daily; a lane that moved is posted
    if (made) seenDrafts.add(made.id); if (existing) seenDrafts.add(existing.id);
    const head = made ? null : existing;
    if (head && (head.status === 'promoted' || head.surfaced_at) && coverageStale(head.draft?.coverage, now)) {
      try {
        const coverage = await coverageFor({ story: s, thread, kev: kevFull, fetchImpl, cache, now, prev: head.draft?.coverage || null, draft: head.draft });
        counts.cost += coverage.exposure?.names_cost_usd || 0;
        counts.coverage_checked++;
        const changes = diffCoverage(head.draft?.coverage, coverage);
        await store.updateCardDraft(head.id, { draft: { ...(head.draft || {}), cves: head.draft?.cves || threadCves(thread), coverage } });
        if (changes.length) { counts.coverage_changed++; await postDiscord(`Cutsign ▣ coverage changed for ${head.status === 'promoted' ? `AI card ${head.promoted_slug}` : `AI draft "${head.title}"`}:\n` + changes.map((x) => `• ${x}`).join('\n') + `\n${headUrl(head)}`); }
      } catch { counts.errors++; }
    }

    try {
      await store.updateStory(s.id, { raw_iocs: { ...(s.raw_iocs || {}), hype: { score, reasons, at: new Date(now).toISOString(), draft_id: made?.id || existing?.id || last?.draft_id || null } } });
    } catch { counts.errors++; }
  }
  // every live card and surfaced draft the brief did not touch today still gets its daily check
  try { await coverageSweep(store, { kev: kevFull, fetchImpl, cache, now, counts, seenCards, seenDrafts }); } catch { counts.errors++; }
  return counts;
}
