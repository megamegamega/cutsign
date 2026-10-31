// Reader-supplied sources for a story the pipeline already knows: the way to circle back on a story
// that was thin on its day (no source text yet) once the public write-ups exist. lib/intake.js hands
// over a mail from the digest's own recipient whose subject starts with "update:" and names a CVE or
// a quoted title; the body carries links. Each link is fetched like any watched page (robots, size,
// prompt-injection guards), assessed by the light model as a development of that story, stored as a
// watch event, and the card loop then runs for the story's own run, so a card is drafted, published
// or revised on the evidence that just arrived. Nothing in the mail is trusted as fact: the links
// are read, the text is assessed, the model's answer is what the card is built from.

import { createHash } from 'node:crypto';
import { fetchSource, usable, injectionMatch } from './fetch-source.js';
import { assess, isHigh, watchMatchesStory, normUrl, lineHashes } from './watch.js';
import { hypeSweep } from './hype.js';
import { postDiscord } from './discord.js';

const DAY = 86_400_000;
const WATCH_DAYS = 14;
export const MAX_URLS = 6;
export const UPDATE_RE = /^\s*(?:re:\s*|fwd?:\s*)*(?:update|circle back|sources?)\b\s*[:\-–—]?\s*(.*)$/i;
const h10 = (s) => createHash('sha1').update(s).digest('hex').slice(0, 10);

/** The addresses an update may come from: UPDATE_SENDER_ALLOWLIST, else the digest's own recipient. */
export const updateSenders = () => String(process.env.UPDATE_SENDER_ALLOWLIST || process.env.EMAIL_TO || '').toLowerCase().split(/[,\s]+/).filter(Boolean);

/** Is this mail an update? → { cves, urls, title } or null. The subject must start with the keyword. */
export function parseUpdateMail({ subject = '', text = '', html = '' } = {}) {
  const m = String(subject).match(UPDATE_RE);
  if (!m) return null;
  const body = `${m[1]}\n${text || String(html).replace(/<[^>]+>/g, ' ')}`;
  const cves = [...new Set((body.match(/CVE-\d{4}-\d{4,}/gi) || []).map((c) => c.toUpperCase()))];
  const urls = [...new Set((body.match(/https?:\/\/[^\s<>"')\]]+/gi) || []).map((u) => u.replace(/[.,;:!?]+$/, '')))]
    .filter((u, i, a) => a.findIndex((x) => normUrl(x) === normUrl(u)) === i).slice(0, MAX_URLS);
  const title = (m[1].match(/["“](.{4,160}?)["”]/) || [])[1] || null;
  return { cves, urls, title };
}

/** The newest extracted story naming one of the CVEs, else the newest whose title contains the quoted title. */
export async function findStory(store, { cves = [], title = null } = {}) {
  if (cves.length) { const rows = await store.listStoriesByCves(cves, 10); if (rows.length) return rows[0]; }
  if (title) {
    const want = title.toLowerCase().replace(/\s+/g, ' ').trim();
    const rows = (await store.listPriorStories('', 90)).filter((s) => String(s.title || '').toLowerCase().includes(want));
    if (rows.length) return rows.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
  }
  return null;
}

/**
 * Read the supplied links as developments of the story, store them on its watch (revived or created
 * when needed), then run the card loop for the story's run. Never throws; posts one Discord line.
 */
export async function applyUpdate(store, { cves = [], urls = [], title = null, from = '', fetchImpl = fetch, now = Date.now() } = {}) {
  const story = await findStory(store, { cves, title });
  if (!story) {
    await postDiscord(`Cutsign ⚠ update mail from ${from || '(unknown)'}: no stored story names ${cves.join(', ') || (title ? `"${title}"` : 'anything to match')}; nothing read.`);
    return { ok: false, reason: 'no story' };
  }
  if (!urls.length) {
    await postDiscord(`Cutsign ⚠ update mail for "${story.title}" carried no links; nothing read.`);
    return { ok: false, reason: 'no urls', story_id: story.id };
  }
  const iso = new Date(now).toISOString();
  let w = (await store.listActiveWatches()).find((x) => watchMatchesStory(x, story)) || null;
  if (!w) {
    w = await store.insertWatch({
      story_id: story.id, title: story.title, cves: story.cves || [], actor: story.threat_actor || null, malware: story.malware_family || null,
      urls: [], status: 'active', expires_at: new Date(now + WATCH_DAYS * DAY).toISOString(),
      state: { seeded: true, pages: {}, kev: [], news: [], repos: [], nvd: {}, revived_by: 'update mail' },
    });
  }
  const state = structuredClone(w.state || {}); state.pages ||= {};
  const events = []; const read = []; const skipped = []; let cost = 0;
  for (const url of urls.slice(0, MAX_URLS)) {
    let src;
    try { src = await fetchSource(url, { fetchImpl }); } catch (e) { skipped.push(`${url} (fetch failed)`); continue; }
    if (!usable(src)) { skipped.push(`${url} (${src?.outcome || 'unreadable'}${src?.suspicious ? ', prompt-injection-shaped' : ''})`); continue; }
    if (state.pages[url]?.h === src.content_hash) { skipped.push(`${url} (already read, unchanged)`); continue; } // the same mail sent twice reads nothing twice
    const text = src.clean_text.slice(0, 8000);
    const inj = injectionMatch(text);
    if (inj) { events.push({ kind: 'new_source', level: 'LOW', url, summary: `A supplied source looked like a prompt-injection attempt and was not analyzed ("${inj.slice(0, 60)}").` }); continue; }
    try {
      const { assessment, cost: c } = await assess(w, story, text, url);
      cost += c;
      if (assessment.relates === false) { skipped.push(`${url} (not about this story)`); continue; }
      assessment.text_hash = `new_source|${normUrl(url)}|${h10(text)}`;
      assessment.supplied = true; // a reader pointed at it; it still had to pass the same reading
      events.push({ kind: 'new_source', level: isHigh(assessment) ? 'HIGH' : 'LOW', url, summary: assessment.summary, assessment, cost_usd: Math.round(c * 10000) / 10000 });
      read.push(url);
      state.pages[url] = { h: src.content_hash, l: lineHashes(src.clean_text).slice(0, 4000) };
    } catch (e) { events.push({ kind: 'new_source', level: 'LOW', url, summary: `Supplied source read but assessment failed: ${String(e?.message || e).slice(0, 120)}` }); }
  }
  if (events.length) await store.insertWatchEvents(events.map((e) => ({ watch_id: w.id, cost_usd: 0, ...e })));
  const material = events.some((e) => e.level === 'HIGH' || e.assessment?.material);
  await store.updateWatch(w.id, {
    state, urls: [...new Set([...(w.urls || []), ...read])].slice(0, 8), last_checked_at: iso, ...(material ? { last_change_at: iso } : {}),
    expires_at: new Date(Math.max(Date.parse(w.expires_at) || 0, now + WATCH_DAYS * DAY)).toISOString(),
  });
  // the card loop for the story's own run: the developments just stored are its evidence now
  let hype = null;
  try { const run = await store.getRun(story.run_id); if (run) hype = await hypeSweep(store, { run, fetchImpl, now }); } catch (e) { hype = { hype_error: String(e?.message || e).slice(0, 200) }; }
  const high = events.filter((e) => e.level === 'HIGH').length;
  await postDiscord(`Cutsign ▣ update applied to "${story.title}": ${read.length} source${read.length === 1 ? '' : 's'} read (${high} HIGH)${skipped.length ? `; skipped: ${skipped.join('; ')}` : ''}`
    + (hype ? `; card loop: ${hype.published || 0} published, ${hype.drafted || 0} drafted, ${hype.revised || 0} revised${hype.hype_error ? ` (error: ${hype.hype_error})` : ''}` : ''));
  return { ok: true, story_id: story.id, watch_id: w.id, read, skipped, events: events.length, high, cost, hype };
}
