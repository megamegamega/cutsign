// Hype score: surface the stories a CISO will ask about before they ask, from what the pipeline
// already stores. Pure scoring (hypeScore) plus a sweep (hypeSweep) that runs after each brief is
// sent and from the hourly watch tick when something developed: threads over one bar are nominated
// to Discord; over a higher bar a verdict-card draft is written (lib/carddraft.js) for a human to
// promote. Nothing here publishes a card; the manifest in lib/cards.js stays hand-edited.
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
// Backtest over the Oct 15–27 2026 briefs (public JSON + the KEV feed): nominating at 6 fires about
// 1.6 threads a day and would have flagged 5 of the 9 hand-chosen cards, BeyondTrust 7 days and
// PHP2Shell 4 days before they were written; the other four were judgment picks that no score
// reaches. Drafting at 7 is about one a day.

import { isPrimary } from './fetch-source.js';
import { cardForStory } from './cards.js';
import { postDiscord } from './discord.js';
import { sendDigest } from './email.js';
import { buildDigestData } from './render.js';
import { draftCard } from './carddraft.js';

const num = (k, d) => Number(process.env[k] ?? d);
export const thresholds = () => ({ nominate: num('HYPE_NOMINATE', 6), draft: num('HYPE_DRAFT', 7) });
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

  const cves = [...new Set(thread.flatMap((r) => r.cves || []))];
  const fresh = cves.filter((c) => kev.has(c) && daysBetween(kev.get(c), date) >= -1 && daysBetween(kev.get(c), date) <= 3);
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

  const ids = new Set(thread.map((r) => r.id));
  const win = events.filter((e) => ids.has(e.watch_story_id) && now - Date.parse(e.created_at) <= 2 * DAY);
  if (win.some((e) => e.level === 'HIGH' && e.assessment?.material)) add(2, 'material development on watch');
  if (win.some((e) => e.kind === 'poc_repo')) add(1, 'public PoC repo');
  if (win.filter((e) => e.kind === 'new_source').length >= 2) add(1, 'new write-ups on watch');

  return { score, reasons };
}

/** CISA KEV as Map cveID → dateAdded; empty on any failure (the score then just lacks that signal). */
export async function fetchKev(fetchImpl = fetch) {
  try {
    const r = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return new Map();
    const j = await r.json();
    return new Map((j.vulnerabilities || []).map((v) => [v.cveID, v.dateAdded]));
  } catch { return new Map(); }
}

const missingTable = (e) => /card_drafts/.test(String(e?.message)) && /does not exist|could not find|schema cache/i.test(String(e?.message));

/**
 * Score every story of a run; nominate and draft. Never throws for one story's sake: a failed draft
 * is reported and the sweep continues. Returns counts.
 * @param run     the run to sweep (its digest data is built unless `data` is passed)
 */
export async function hypeSweep(store, { run, data = null, fetchImpl = fetch, now = Date.now(), draft = true } = {}) {
  const d = data || await buildDigestData(store, run);
  const t = thresholds();
  const kev = await fetchKev(fetchImpl);
  let events = [];
  try { events = await store.listWatchEvents({ since: new Date(now - 2 * DAY).toISOString() }); } catch { /* watches table missing */ }
  const counts = { scored: 0, carded: 0, nominated: 0, drafted: 0, cost: 0, errors: 0 };
  const seen = new Set();
  const lookup = (id) => d.priorById?.get(id) || null;

  for (const s of d.analyzed) {
    const thread = threadOf(s, d.priorById);
    if (seen.has(thread[0].id)) continue;
    seen.add(thread[0].id);
    counts.scored++;
    if (cardForStory(s, lookup)) { counts.carded++; continue; } // already has a hand-written card
    const { score, reasons } = hypeScore({ story: s, thread, kev, events, day: d.date, now });
    if (score < t.nominate) continue;

    // last recorded verdict for this thread: on this row, or on the row it updates
    const own = s.raw_iocs?.hype || null;
    let last = own;
    if (!last && s.updates_story_id) { try { last = (await store.getStory(s.updates_story_id))?.raw_iocs?.hype || null; } catch { last = null; } }

    let existing = null; let canDraft = draft;
    try { existing = (await store.listCardDrafts({ storyIds: thread.map((r) => r.id) }))[0] || null; }
    catch (e) { if (missingTable(e)) { canDraft = false; counts.drafts_disabled = 'apply supabase/migrations/0004_card_drafts.sql'; } else { counts.errors++; canDraft = false; } }

    const link = `${SITE()}/?view=ciso&d=${encodeURIComponent(d.date)}#${sid8(s.id)}`;
    const rose = !last || score >= Number(last.score || 0) + 2;
    if (rose) {
      counts.nominated++;
      await postDiscord(`Cutsign ▲ card candidate (score ${score}): ${s.title}\n` + reasons.map((r) => `• ${r}`).join('\n')
        + `\n${link}` + (existing ? `\nDraft: ${SITE()}/?view=draft&id=${existing.id}` : ''));
    }

    let made = null;
    if (canDraft && !existing && score >= t.draft) {
      try {
        const r = await draftCard({ story: s, thread, data: d, score, reasons });
        made = await store.insertCardDraft({
          story_id: s.id, thread_ids: thread.map((x) => x.id), title: r.draft.title, score, reasons,
          draft: r.draft, model: r.model, cost_usd: Number(r.cost.toFixed(4)),
        });
        counts.drafted++; counts.cost += r.cost;
        const url = `${SITE()}/?view=draft&id=${made.id}`;
        await postDiscord(`Cutsign ▣ card draft ready (score ${score}, $${r.cost.toFixed(2)}): ${r.draft.title}\n${url}\nMachine-written, unreviewed. Promote by writing public/cards/ from it, or dismiss.`);
        try {
          await sendDigest({
            subject: `Cutsign ▣ card candidate: ${r.draft.title}`,
            html: `<p><b>${esc(r.draft.title)}</b> — hype score ${score}.</p><ul>${reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`
              + `<p>${esc(r.draft.verdict)}</p><p><a href="${esc(url)}">Read the draft</a> · <a href="${esc(link)}">the story in the CISO view</a></p>`
              + '<p style="color:#888">Machine-written from stored public sources and unreviewed. Nothing is published until a person promotes it.</p>',
            text: `${r.draft.title} — hype score ${score}\n${reasons.map((x) => '- ' + x).join('\n')}\n\n${r.draft.verdict}\n\nDraft: ${url}\nStory: ${link}\n\nMachine-written and unreviewed.`,
          });
        } catch (e) { counts.errors++; await postDiscord(`Cutsign ⚠ draft email failed: ${String(e?.message || e).slice(0, 200)}`); }
      } catch (e) {
        counts.errors++;
        await postDiscord(`Cutsign ✖ card draft failed for "${s.title}": ${String(e?.message || e).slice(0, 300)}`);
      }
    }

    try {
      await store.updateStory(s.id, { raw_iocs: { ...(s.raw_iocs || {}), hype: { score, reasons, at: new Date(now).toISOString(), draft_id: made?.id || existing?.id || last?.draft_id || null } } });
    } catch { counts.errors++; }
  }
  return counts;
}
