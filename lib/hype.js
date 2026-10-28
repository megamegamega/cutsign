// Hype score and the card-draft loop: surface the stories a CISO will ask about before they ask,
// from what the pipeline already stores, and keep an AI-generated draft current as the evidence
// changes. hypeScore is pure. hypeSweep runs after each brief is sent and from the hourly watch
// tick when something developed:
//   score ≥ HYPE_NOMINATE  → nominated to Discord (once, again if the score rises by 2)
//   nominated + actionable → an AI draft is generated (lib/carddraft.js); when the evidence
//                            fingerprint changes later, the draft is revised as a new version
//   score ≥ HYPE_SURFACE   → the draft is surfaced: chip on the CISO view, pinned on the Cards tab,
//                            "ready for review" email
// Nothing here publishes a card; the manifest in lib/cards.js stays hand-edited, and the analyst
// fills the coverage table at promotion.
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
import { cardForStory } from './cards.js';
import { postDiscord } from './discord.js';
import { sendDigest } from './email.js';
import { buildDigestData } from './render.js';
import { draftCard } from './carddraft.js';

const num = (k, d) => Number(process.env[k] ?? d);
export const thresholds = () => ({ nominate: num('HYPE_NOMINATE', 6), surface: num('HYPE_SURFACE', 9) });
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
  if (thread.length > 1) add(Math.min(thread.length - 1, 2), `day ${thread.length} of the story`);

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
    days: thread.length,
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

async function notify({ title, version, score, reasons, verdict, url, link, surfaced, changes, cost, card = null }) {
  const kind = card ? `AI re-issue draft for card ${card.slug} (v${version})` : version > 1 ? `AI draft revised (v${version})` : 'AI draft written';
  const head = card ? `Cutsign ▣ ${kind}, $${cost.toFixed(2)}: ${title}` : surfaced ? `Cutsign ▣ AI draft ready for review (score ${score}): ${title}` : `Cutsign ▣ ${kind} (score ${score}, $${cost.toFixed(2)}): ${title}`;
  await postDiscord(`${head}\n${changes.length ? `Changed: ${changes.join('; ')}\n` : ''}${url}\nAI-generated and unreviewed. Promote by writing public/cards/ from it, or dismiss.`);
  try {
    await sendDigest({
      subject: surfaced ? `Cutsign ▣ AI draft ready for review: ${title}` : `Cutsign ▣ ${kind}: ${title}`,
      html: `<p><b>${esc(title)}</b> — version ${version}, hype score ${score}.</p><ul>${reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`
        + (changes.length ? `<p><b>Changed:</b> ${esc(changes.join('; '))}</p>` : '')
        + `<p>${esc(verdict)}</p><p><a href="${esc(url)}">Read the draft</a> · <a href="${esc(link)}">the story in the CISO view</a></p>`
        + '<p style="color:#888">AI-generated from stored public sources and unreviewed. Nothing is published until a person promotes it.</p>',
      text: `${title} — version ${version}, hype score ${score}\n${reasons.map((x) => '- ' + x).join('\n')}\n${changes.length ? `\nChanged: ${changes.join('; ')}\n` : ''}\n${verdict}\n\nDraft: ${url}\nStory: ${link}\n\nAI-generated and unreviewed.`,
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
async function reissueCheck(store, { card, story: s, thread, data: d, kev, events, last, link, draft, now, counts }) {
  const devs = cardDevelopments({ card, thread, kev, events });
  const raised = new Set(last?.card_devs || []);
  const fresh = devs.filter((x) => !raised.has(x.key));
  const state = { card: card.slug, card_devs: devs.map((x) => x.key), at: new Date(now).toISOString(), draft_id: last?.draft_id || null };
  if (fresh.length) {
    counts.stale++;
    const cardUrl = `${SITE()}/cards/${card.slug}.html`;
    await postDiscord(`Cutsign ▲ card ${card.slug} (as of ${card.date}) has developments after its date:\n` + fresh.map((x) => `• ${x.text}`).join('\n')
      + `\n${cardUrl}\nRe-issue the card (bump its as-of date) to clear this.`);
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
  const counts = { scored: 0, carded: 0, stale: 0, nominated: 0, drafted: 0, revised: 0, surfaced: 0, waiting: 0, cost: 0, errors: 0 };
  const seen = new Set();
  const lookup = (id) => d.priorById?.get(id) || null;

  for (const s of d.analyzed) {
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
      counts.carded++;
      await reissueCheck(store, { card, story: s, thread, data: d, kev: kevFull, events, last, link, draft, now, counts });
      continue;
    }
    const { score, reasons } = hypeScore({ story: s, thread, kev, events, day: d.date, now });
    if (score < t.nominate) continue;

    let existing = null; let canDraft = draft; let dismissed = false;
    try {
      const rows = await store.listCardDrafts({ storyIds: thread.map((r) => r.id), limit: 5 });
      dismissed = rows.some((r) => r.status === 'dismissed' || r.status === 'promoted');
      existing = rows.find((r) => r.status === 'draft') || null;
    } catch (e) { if (missingTable(e)) { canDraft = false; counts.drafts_disabled = 'apply supabase/migrations/0004_card_drafts.sql'; } else { counts.errors++; canDraft = false; } }

    const rose = !last || score >= Number(last.score || 0) + 2;
    if (rose) {
      counts.nominated++;
      await postDiscord(`Cutsign ▲ card candidate (score ${score}): ${s.title}\n` + reasons.map((r) => `• ${r}`).join('\n')
        + `\n${link}` + (existing ? `\nAI draft: ${SITE()}/?view=draft&id=${existing.id}` : ''));
    }

    const fp = evidenceFingerprint({ story: s, thread, kev, events, day: d.date, now });
    const surfaced = score >= t.surface;
    let made = null;
    if (canDraft && !dismissed && actionable(fp) && (!existing || existing.fingerprint !== fpKey(fp))) {
      // first draft, or the evidence moved since the last one: write / revise
      const prev = existing?.fingerprint ? JSON.parse(existing.fingerprint) : null;
      const changes = describeChanges(prev, fp);
      try {
        const r = await draftCard({ story: s, thread, data: d, score, reasons, prior: existing, changes });
        made = await store.insertCardDraft({
          story_id: s.id, thread_ids: thread.map((x) => x.id), title: r.draft.title, score, reasons,
          draft: r.draft, model: r.model, cost_usd: Number(r.cost.toFixed(4)),
          version: (existing?.version || 0) + 1, supersedes: existing?.id || null, fingerprint: fpKey(fp),
          surfaced_at: surfaced ? new Date(now).toISOString() : null,
        });
        if (existing) { await store.updateCardDraft(existing.id, { status: 'superseded' }); counts.revised++; } else counts.drafted++;
        if (surfaced) counts.surfaced++;
        counts.cost += r.cost;
        await notify({ title: r.draft.title, version: made.version, score, reasons, verdict: r.draft.verdict, url: `${SITE()}/?view=draft&id=${made.id}`, link, surfaced, changes, cost: r.cost });
      } catch (e) {
        counts.errors++;
        await postDiscord(`Cutsign ✖ AI draft failed for "${s.title}": ${String(e?.message || e).slice(0, 300)}`);
      }
    } else if (existing && surfaced && !existing.surfaced_at) {
      // nothing new to write, but the score crossed the high bar: show it
      try {
        await store.updateCardDraft(existing.id, { surfaced_at: new Date(now).toISOString() });
        counts.surfaced++;
        await notify({ title: existing.title, version: existing.version || 1, score, reasons, verdict: existing.draft?.verdict || '', url: `${SITE()}/?view=draft&id=${existing.id}`, link, surfaced: true, changes: [], cost: 0 });
      } catch { counts.errors++; }
    } else if (canDraft && !dismissed && !existing && !actionable(fp)) counts.waiting++;

    try {
      await store.updateStory(s.id, { raw_iocs: { ...(s.raw_iocs || {}), hype: { score, reasons, at: new Date(now).toISOString(), draft_id: made?.id || existing?.id || last?.draft_id || null } } });
    } catch { counts.errors++; }
  }
  return counts;
}
