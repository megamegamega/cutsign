// Stale-card checks for hand-written cards (2026-11-22).
//
// Why this exists. A hand-written card is a snapshot: its text says "unfixed", "not in KEV", "no
// exploitation reported" as of its date. The card loop (lib/hype.js) already raises a KEV listing
// or a HIGH watch development and writes an AI re-issue draft, and the coverage sweep re-asks the
// public sources daily. Two cards still went stale in November 2026, for these reasons:
//   - a card with no story ids (carded before any brief carried the story) has no story row, so the
//     coverage sweep skipped it and nothing was ever asked about it;
//   - a development ended at a draft and one Discord line; nothing kept saying the card was behind;
//   - nothing compared what the card itself says with what the sources now say: the Debian lane read
//     "fixed" the day unstable was fixed, so stable getting the fix changed nothing, and there was no
//     Ubuntu lane at all;
//   - the coverage rows could belong to another campaign's CVEs (a thread story naming them).
// So, once a day per active hand-written card, on the watch tick that already runs (api/watch.js):
//   1. KEV          a declared CVE listed after the card's date (or while the card says "Not in KEV")
//   2. distro       Debian, Ubuntu, Red Hat re-asked wherever the card says unfixed or pending
//   3. advisory     the vendor advisories a card of the last 30 days cites: changed, or updated since
//   4. exploitation a KEV listing or an exploitation development while the card says none is reported
//   5. hygiene      automated coverage rows for a CVE the card does not declare
//   6. archive      past 30 days with no active watch (lib/cards.js archiveCandidates)
// A finding is a flag: stored (table card_checks, migration 0008), said once on Discord, and carried
// in one digest line a day until the card is re-issued or the condition is gone (an archive candidate
// is said once and not repeated). A new KEV listing
// also hands the card's run to the card loop, which writes the AI re-issue draft it always wrote.
// Nothing here edits a card, archives one, publishes, or mails anyone, and no model is called.
//
// What a card "says" is read from its own page, by the house conventions every card follows:
// a status is a <span class="ok"> or <span class="bad"> in a table row, the chips are .lane .tag,
// the timeline is ul.tl (history, never read as a claim). cardClaims() is the whole of that reading.

import { parse as parseHtml } from 'node-html-parser';
import { activeCards, archiveCandidates } from './cards.js';
import { redhatSummary, RECHECK_MS } from './coverage.js';
import { fetchSource, usable } from './fetch-source.js';
import { lineHashes, addedText } from './watch.js';
import { fetchKevEntries } from './hype.js';
import { postDiscord } from './discord.js';

const SITE = () => process.env.PUBLIC_BASE_URL || 'https://cutsign.vercel.app';
const UA = 'Mozilla/5.0 (compatible; cutsign-cardchecks/1.0; +https://cutsign.vercel.app)';
const DAY = 86_400_000;
export const CHECKS = ['kev', 'distro', 'advisory', 'exploitation', 'hygiene', 'archive'];
/** The row of card_checks that holds the day the digest was last posted. */
export const DIGEST_ROW = '_digest';
export const MIGRATION = 'supabase/migrations/0008_card_checks.sql';
/** Advisories are followed for cards whose as-of date is this recent. */
export const ADVISORY_DAYS = 30;
const MAX_ADVISORIES = 8;   // per card
const MAX_CVES = 5;         // per card, per distro
const MAX_HASHES = 4000;    // line hashes kept per advisory

const iso = (ms) => new Date(ms).toISOString();
const day = (x) => String(x || '').slice(0, 10);
const text = (el) => String(el?.text || '').replace(/\s+/g, ' ').trim();
const missingTable = (e) => /card_checks/.test(String(e?.message)) && /does not exist|could not find|schema cache/i.test(String(e?.message));

async function get(url, fetchImpl) {
  try {
    const r = await fetchImpl(url, { headers: { 'User-Agent': UA, Accept: 'text/html,application/json;q=0.9,*/*;q=0.5' }, signal: AbortSignal.timeout(12_000) });
    return { status: r.status, text: r.status === 200 ? await r.text() : '' };
  } catch (e) { return { status: 0, text: '', error: String(e?.message || e).slice(0, 120) }; }
}

// ---- what the card says --------------------------------------------------------------------------

const DISTROS = { debian: /\bDebian\b/i, ubuntu: /\bUbuntu\b/i, redhat: /\bRed Hat\b|\bRHEL\b/i };
export const DISTRO_NAMES = { debian: 'Debian', ubuntu: 'Ubuntu', redhat: 'Red Hat' };
const CHIP_OK = /\bfix(?:es|ed)?\b[^·]*\b(?:out|available|released|published|shipped)\b/i;
const CHIP_BAD = /\b(?:unfixed|not fixed|no fix(?:ed)?|still vulnerable|fix(?:es)? pending)\b/i;
const NO_EXPLOITATION = /\bno (?:known |confirmed |reported |public )?(?:in-the-wild )?exploitation\b|\bno (?:source|report|evidence)s?\b[^.]{0,60}\bexploit(?:ation|ed)\b|\bnot (?:known to be )?exploited\b/i;
const ADVISORY_TEXT = /advisor|bulletin|\balert\b|security notice|errata/i;
// what another check already reads, and pages that change for reasons that are not the advisory's
const ADVISORY_SKIP = /^https?:\/\/(?:[^/]*\.)?(?:security-tracker\.debian\.org|ubuntu\.com|nvd\.nist\.gov|cve\.org|github\.com)\/|access\.redhat\.com\/security\/cve\/|cisa\.gov\/known-exploited-vulnerabilities/i;

/**
 * What a card page claims, as far as the checks need it:
 *   distro        { debian, ubuntu, redhat }: 'unfixed' | 'fixed' | null (the card says nothing)
 *   exploitation  'none' when a chip or the opening paragraph says no exploitation is reported, else null
 *   kev           'not listed' when a chip says so, else null
 *   advisories    [{ url, label }] the vendor advisories it cites (advisoryLinks)
 * A distro is 'fixed' as soon as one row about it carries an ok status: a card that shows the fix and
 * also lists what still lags (a bundled product) has acknowledged the fix. Pure.
 */
export function cardClaims(html) {
  const root = parseHtml(String(html || ''));
  const seen = { debian: new Set(), ubuntu: new Set(), redhat: new Set() };
  for (const tr of root.querySelectorAll('tr')) {
    const tds = tr.querySelectorAll('td');
    if (!tds.length) continue;
    const pol = tr.querySelector('span.ok') ? 'ok' : tr.querySelector('span.bad') ? 'bad' : null;
    if (!pol) continue;
    // the cells that name the subject: the first, and the second unless it is the status cell
    const names = tds.slice(0, 2).filter((td, i) => i === 0 || !(td.querySelector('span.ok') || td.querySelector('span.bad'))).map(text).join(' | ');
    for (const [d, re] of Object.entries(DISTROS)) if (re.test(names)) seen[d].add(pol);
  }
  const chips = root.querySelectorAll('.lane .tag').map(text);
  for (const t of chips) {
    const which = /\bdistro/i.test(t) ? Object.keys(DISTROS) : Object.entries(DISTROS).filter(([, re]) => re.test(t)).map(([d]) => d);
    const pol = CHIP_OK.test(t) ? 'ok' : CHIP_BAD.test(t) ? 'bad' : null;
    if (pol) for (const d of which) seen[d].add(pol);
  }
  const distro = Object.fromEntries(Object.entries(seen).map(([d, s]) => [d, s.has('ok') ? 'fixed' : s.has('bad') ? 'unfixed' : null]));
  const lead = root.querySelectorAll('p.sub b').map(text);
  const exploitation = [...chips, ...lead].some((t) => NO_EXPLOITATION.test(t)) ? 'none' : null;
  const kev = chips.some((t) => /\bnot in (?:CISA )?KEV\b/i.test(t)) ? 'not listed' : null;
  return { distro, exploitation, kev, advisories: advisoryLinks(root) };
}

/**
 * The vendor advisories a card cites: the links in the "Vendor" rows of its coverage table, and the
 * source links whose text calls itself an advisory, bulletin, alert, security notice or errata. Distro
 * trackers, NVD and the KEV catalog are left out (other checks read them). At most `max`. Pure.
 */
export function advisoryLinks(htmlOrRoot, { max = MAX_ADVISORIES } = {}) {
  const root = typeof htmlOrRoot === 'string' ? parseHtml(htmlOrRoot) : htmlOrRoot;
  const out = new Map();
  const add = (a) => {
    const url = String(a.getAttribute('href') || '').replace(/&amp;/g, '&');
    if (!/^https?:\/\//i.test(url) || ADVISORY_SKIP.test(url) || out.has(url)) return;
    out.set(url, { url, label: text(a).slice(0, 80) || url });
  };
  for (const table of root.querySelectorAll('table')) {
    if (text(table.querySelector('th')) !== 'Category') continue;
    let cat = ''; let left = 0;
    for (const tr of table.querySelectorAll('tr')) {
      const tds = tr.querySelectorAll('td');
      if (!tds.length) continue;
      let names;
      if (left > 0) { names = tds[0]; left--; } else { cat = text(tds[0]); left = Math.max(0, Number(tds[0].getAttribute('rowspan') || 1) - 1); names = tds[1]; }
      if (/^vendor$/i.test(cat) && names) for (const a of names.querySelectorAll('a')) add(a);
    }
  }
  for (const a of root.querySelectorAll('p.src a')) if (ADVISORY_TEXT.test(text(a))) add(a);
  return [...out.values()].slice(0, max);
}

// ---- what the distros say ------------------------------------------------------------------------

/**
 * Debian's tracker page for a CVE: the releases fixed through the security archive, and the DSA/DLA
 * ids it names. A fix that exists only in unstable or testing is not one (the card's "unfixed" is
 * about the releases people run); a fix that reaches stable only by a point release is not seen. Pure.
 */
export function debianStatus(html) {
  const root = parseHtml(String(html || ''));
  const fixed = [];
  for (const table of root.querySelectorAll('table')) {
    if (table.querySelectorAll('th').map(text).join('|') !== 'Source Package|Release|Version|Status') continue;
    for (const tr of table.querySelectorAll('tr')) {
      const tds = tr.querySelectorAll('td');
      if (tds.length < 4) continue;
      const release = text(tds[1]);
      if (text(tds[3]) === 'fixed' && /\(security\)/.test(release)) fixed.push({ release: release.replace(/\s*\(security\)/, ''), version: text(tds[2]) });
    }
  }
  const advisories = [...new Set(String(html || '').match(/\bD[SL]A-\d+-\d+\b/g) || [])];
  return { isFixed: fixed.length > 0, fixed, advisories };
}

/** Ubuntu's CVE record (ubuntu.com/security/cves/<id>.json): the releases a fix was released for, and the notices. Pure. */
export function ubuntuStatus(json) {
  const fixed = []; const open = [];
  for (const p of json?.packages || []) for (const s of p.statuses || []) {
    if (!s.release_codename || s.release_codename === 'upstream') continue;
    if (s.status === 'released') fixed.push({ package: p.name, release: s.release_codename, version: s.description || '' });
    else if (['needed', 'pending', 'needs-triage', 'deferred'].includes(s.status)) open.push({ package: p.name, release: s.release_codename, status: s.status });
  }
  const notices = [...new Set((json?.notices || []).map((n) => n.id).filter(Boolean))];
  return { isFixed: fixed.length > 0, fixed, open, notices };
}

const DISTRO_SOURCES = {
  debian: {
    url: (c) => `https://security-tracker.debian.org/tracker/${c}`, human: (c) => `https://security-tracker.debian.org/tracker/${c}`,
    read: (body) => { const s = debianStatus(body); return s.isFixed ? `${[...new Set(s.fixed.map((f) => f.release))].join(', ')} fixed through the security archive${s.advisories.length ? ` (${s.advisories.slice(0, 4).join(', ')})` : ''}` : null; },
  },
  ubuntu: {
    url: (c) => `https://ubuntu.com/security/cves/${c}.json`, human: (c) => `https://ubuntu.com/security/${c}`,
    read: (body) => { const s = ubuntuStatus(JSON.parse(body)); return s.isFixed ? `released for ${[...new Set(s.fixed.map((f) => f.release))].slice(0, 6).join(', ')}${s.notices.length ? ` (${s.notices.slice(0, 4).join(', ')})` : ''}` : null; },
  },
  redhat: {
    url: (c) => `https://access.redhat.com/hydra/rest/securitydata/cve/${c}.json`, human: (c) => `https://access.redhat.com/security/cve/${c}`,
    read: (body) => { const s = redhatSummary(JSON.parse(body)); return s.errata.length ? `errata ${s.errata.slice(0, 4).join(', ')}${s.errata.length > 4 ? ` and ${s.errata.length - 4} more` : ''}` : null; },
  },
};

// ---- the six checks: each returns flags { key, check, text, url } ----------------------------------

/** 1. A declared CVE in CISA's catalog after the card's date, or at all while the card's chip says "Not in KEV". Pure. */
export function checkKev({ card, claims = null, kev }) {
  const out = [];
  for (const c of card.cves || []) {
    const e = kev.get(c); const added = typeof e === 'string' ? e : e?.dateAdded; const due = typeof e === 'object' ? e?.dueDate : null;
    if (!added) continue;
    if (added > card.date || claims?.kev === 'not listed') out.push({ key: `kev:${c}`, check: 'kev', text: `CISA KEV lists ${c}, added ${added}${due ? ` (federal due ${due})` : ''}${added > card.date ? `, after the card's date` : `; the card's chip says "Not in KEV"`}`, url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
  }
  return out;
}

/** 2. Each distro the card calls unfixed or pending, re-asked for every declared CVE. A source that fails is not a finding. */
export async function checkDistro({ card, claims, fetchImpl = fetch }) {
  const out = [];
  const cves = (card.cves || []).slice(0, MAX_CVES);
  await Promise.all(Object.entries(DISTRO_SOURCES).map(async ([d, src]) => {
    if (claims?.distro?.[d] !== 'unfixed' || !cves.length) return;
    const found = [];
    await Promise.all(cves.map(async (c) => {
      const r = await get(src.url(c), fetchImpl);
      if (r.status !== 200) return;
      try { const detail = src.read(r.text); if (detail) found.push({ cve: c, detail }); } catch { /* not the page we expected: no finding */ }
    }));
    if (!found.length) return;
    found.sort((a, b) => a.cve.localeCompare(b.cve));
    out.push({ key: `distro:${d}`, check: 'distro', text: `the card says ${DISTRO_NAMES[d]} is unfixed or pending; ${DISTRO_NAMES[d]} now shows ${found[0].cve}: ${found[0].detail}${found.length > 1 ? ` (and ${found.slice(1).map((f) => f.cve).join(', ')})` : ''}`, url: src.human(found[0].cve) });
  }));
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const M = '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\.?';
const UPDATED = new RegExp(`\\b(?:last\\s+)?(?:updated|revised|modified)\\b[^A-Za-z0-9]{0,6}(?:on\\s+)?(?:(\\d{1,2})\\s+(${M}),?\\s+(\\d{4})|(${M})\\s+(\\d{1,2}),?\\s+(\\d{4})|(\\d{4})-(\\d{2})-(\\d{2}))`, 'gi');
/** The dates a page gives after "updated", "revised" or "modified", as YYYY-MM-DD, newest last. Pure. */
export function updatedDates(pageText) {
  const out = new Set();
  for (const m of String(pageText || '').matchAll(UPDATED)) {
    const [d, mon, y] = m[1] ? [m[1], m[2], m[3]] : m[4] ? [m[5], m[4], m[6]] : [m[9], null, m[7]];
    const mm = mon ? MONTHS.indexOf(mon.slice(0, 3).toLowerCase()) + 1 : Number(m[8]);
    if (mm >= 1 && mm <= 12 && Number(d) >= 1 && Number(d) <= 31) out.add(`${y}-${String(mm).padStart(2, '0')}-${String(d).padStart(2, '0')}`);
  }
  return [...out].sort();
}
// a changed line is worth a human's look when it reads like an advisory moving, not a page being redecorated
const SIGNAL = /\b(?:updat|revis|fix|patch|releas|errata|version|exploit|mitigat|workaround|affected|CVE-\d{4}-\d+)/i;

/**
 * 3. The advisories a recent card cites. First sight is a baseline; after that, new lines that read
 * like an advisory changing are a flag, and so is an "updated <date>" later than the card's date.
 * Returns { flags, state }: `state` is the fingerprints to keep (line hashes, never text); a flag quotes
 * the first new line, at most 160 characters of a public page that passed the injection screen.
 */
export async function checkAdvisories({ card, claims, prev = {}, now = Date.now(), fetchImpl = fetch }) {
  const flags = []; const state = {};
  if (now - Date.parse(card.date) > ADVISORY_DAYS * DAY) return { flags, state: prev };
  await Promise.all((claims?.advisories || []).map(async ({ url, label }) => {
    const before = prev[url] || null;
    const row = await fetchSource(url, { fetchImpl });
    if (!usable(row)) { if (before) state[url] = before; return; }
    const hashes = lineHashes(row.clean_text);
    const updated = updatedDates(row.clean_text).filter((d) => d <= day(iso(now))).at(-1) || null;
    state[url] = { at: iso(now), updated, hashes: [...new Set([...(before?.hashes || []), ...hashes])].slice(-MAX_HASHES) };
    if (updated && updated > card.date && updated !== before?.updated) {
      flags.push({ key: `advisory:${url}#${updated}`, check: 'advisory', text: `${label}: the page says it was updated ${updated}, after the card's date`, url });
      return;
    }
    if (!before) return; // baseline
    const added = addedText(before.hashes, row.clean_text).split('\n').filter((l) => SIGNAL.test(l));
    if (added.length) flags.push({ key: `advisory:${url}#${day(iso(now))}`, check: 'advisory', text: `${label}: new text since ${day(before.at)} — "${added[0].slice(0, 160)}"${added.length > 1 ? ` (+${added.length - 1} more line${added.length > 2 ? 's' : ''})` : ''}`, url });
  }));
  return { flags: flags.sort((a, b) => a.key.localeCompare(b.key)), state };
}

/** Is this story the card's own campaign (not a roundup that happens to name one of its CVEs)? */
export const ownStory = (card, s) => (card.story_ids || []).includes(s.id)
  || ((s.cves || []).length > 0 && (s.cves || []).filter((c) => (card.cves || []).includes(c)).length * 2 >= (s.cves || []).length);

/**
 * 4. While the card says no exploitation is reported: a declared CVE in KEV, or a watch development
 * after the card's date that the watch read as exploitation (lib/watch.js assess: "confirmed or newly
 * reported exploitation"), on one of the card's own stories or naming one of its CVEs. Pure.
 */
export function checkExploitation({ card, claims, kev, events = [], stories = [] }) {
  if (claims?.exploitation !== 'none') return [];
  const out = [];
  for (const c of card.cves || []) {
    const e = kev.get(c); const added = typeof e === 'string' ? e : e?.dateAdded;
    if (added) out.push({ key: `exploited:kev:${c}`, check: 'exploitation', text: `the card says no exploitation is reported; ${c} is in CISA KEV (added ${added})`, url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
  }
  const own = new Set(stories.filter((s) => ownStory(card, s)).map((s) => s.id));
  const all = new Set(stories.map((s) => s.id));
  const names = (e) => (card.cves || []).some((c) => `${e.summary || ''} ${e.assessment?.summary || ''} ${e.url || ''}`.toUpperCase().includes(c.toUpperCase()));
  const hits = events.filter((e) => day(e.created_at) > card.date && e.assessment?.relates !== false
    && (e.assessment?.kinds || []).includes('exploitation') && (own.has(e.watch_story_id) || (all.has(e.watch_story_id) && names(e))))
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 3);
  for (const e of hits) out.push({ key: `exploited:event:${e.id || e.created_at}`, check: 'exploitation', text: `the card says no exploitation is reported; ${day(e.created_at)}: ${String(e.assessment?.summary || e.summary || '').slice(0, 200)}`, url: e.url || null });
  return out;
}

/** 5. Automated coverage rows for a CVE the card does not declare (a card that declares none uses its thread's, by design). Pure. */
export function checkHygiene({ card, coverage }) {
  if (!(card.cves || []).length || !coverage?.lanes) return [];
  const declared = new Set(card.cves.map((c) => c.toUpperCase()));
  const rows = coverage.lanes.filter((l) => { const m = String(l.id || '').match(/(CVE-\d{4}-\d+)$/i); return m && !declared.has(m[1].toUpperCase()); });
  const foreign = [...new Set([...rows.map((l) => l.id.match(/(CVE-\d{4}-\d+)$/i)[1].toUpperCase()), ...(coverage.cves || []).map((c) => c.toUpperCase()).filter((c) => !declared.has(c))])].sort();
  if (!foreign.length) return [];
  return [{ key: `hygiene:${foreign.join(',')}`, check: 'hygiene', text: `the automated coverage check carries ${rows.length} row${rows.length === 1 ? '' : 's'} for ${foreign.length === 1 ? 'a CVE' : 'CVEs'} this card does not declare: ${foreign.join(', ')}`, url: null }];
}

/** 6. Past 30 days with no active watch and no recent development: a candidate, never an action. Pure. */
export function checkArchive({ card, watchRows = [], now = Date.now() }) {
  const [c] = archiveCandidates([{ status: 'active', ...card, story_ids: card.story_ids || [] }], watchRows, now);
  return c ? [{ key: 'archive', check: 'archive', text: `eligible to archive (${c.reason}); a human sets the status in lib/cards.js, nothing is archived here`, url: null }] : [];
}

// ---- the sweep -----------------------------------------------------------------------------------

/** A card's stored state, or a clean one when the card was re-issued (its date changed) since. */
const stateFor = (stored, card) => (stored && stored.card_date === card.date ? stored : { card_date: card.date, checked_at: null, flags: [], raised: [], asked: {}, advisories: {} });

/**
 * Run the checks for every active hand-written card whose last check is older than `every` (a day),
 * stalest first, starting none after `deadline`. Never throws.
 * Returns counts; `runs` are the runs the caller should hand to the card loop (hypeSweep) so a new
 * KEV listing gets its AI re-issue draft; `skipped` names the migration when the table is missing.
 * @param cards  the cards to check (the manifest's active ones; tests pass their own)
 * @param kevOf  () => Map cve → { dateAdded, dueDate }; fetched once, and only when a card is due
 */
export async function cardChecksSweep(store, { cards = activeCards(), fetchImpl = fetch, now = Date.now(), deadline = Infinity, site = SITE(), every = RECHECK_MS, kevOf = () => fetchKevEntries(fetchImpl) } = {}) {
  const counts = { cards: cards.length, checked: 0, deferred: 0, flags_open: 0, flags_new: 0, runs: [], errors: 0 };
  let rows = [];
  try { rows = await store.listCardChecks(); } catch (e) {
    if (missingTable(e) || typeof store.listCardChecks !== 'function') return { ...counts, skipped: `apply ${MIGRATION}` };
    return { ...counts, errors: 1, error: String(e?.message || e).slice(0, 200) };
  }
  const states = new Map(rows.map((r) => [r.slug, r.state || {}]));
  const due = cards.map((card) => ({ card, state: stateFor(states.get(card.slug), card) }))
    .filter((x) => !x.state.checked_at || now - Date.parse(x.state.checked_at) >= every)
    .sort((a, b) => (Date.parse(a.state.checked_at) || 0) - (Date.parse(b.state.checked_at) || 0));

  try {
    if (due.length && Date.now() <= deadline) {
      // read once for the whole sweep: the catalog, the watches' lifecycle, the developments
      let kev = new Map(); try { kev = await kevOf(); } catch { kev = new Map(); }
      const kevOk = kev.size > 0; // an empty catalog is a failed fetch, never "nothing is listed"
      const allIds = cards.flatMap((c) => c.story_ids || []);
      let watchRows = null; try { watchRows = await store.watchFacts(allIds); } catch { watchRows = null; }
      const oldest = due.map((x) => x.card.date).sort()[0];
      let events = []; try { events = await store.listWatchEvents({ since: `${oldest}T00:00:00Z` }); } catch { events = []; }

      for (const { card, state } of due) {
        if (Date.now() > deadline) { counts.deferred++; continue; }
        try {
          const next = await checkCard(store, { card, state, kev, kevOk, watchRows, events, fetchImpl, now, site, counts });
          await store.putCardCheck(card.slug, next);
          states.set(card.slug, next);
          counts.checked++;
        } catch (e) { counts.errors++; counts.error = `${card.slug}: ${String(e?.message || e).slice(0, 160)}`; }
      }
    } else counts.deferred += due.length;

    // one line a day for what is still open from an earlier day, so a flag is not said once and forgotten.
    // An archive candidate is said once and left out: keeping a card is a decision, not a debt, and the
    // Monday self-check already repeats the list (api/selfcheck.js).
    const open = cards.map((card) => ({ card, flags: (stateFor(states.get(card.slug), card).flags || []) })).filter((x) => x.flags.length);
    counts.flags_open = open.reduce((n, x) => n + x.flags.length, 0);
    const today = day(iso(now));
    const standing = open.map((x) => ({ ...x, flags: x.flags.filter((f) => f.check !== 'archive' && day(f.since) < today) })).filter((x) => x.flags.length);
    if (standing.length && states.get(DIGEST_ROW)?.day !== today) {
      await postDiscord(`Cutsign ⚑ ${standing.reduce((n, x) => n + x.flags.length, 0)} open flag${standing.reduce((n, x) => n + x.flags.length, 0) === 1 ? '' : 's'} on ${standing.length} hand-written card${standing.length === 1 ? '' : 's'} (re-issue the card, or the flag clears when it no longer holds):\n`
        + standing.map((x) => `• ${x.card.slug} (as of ${x.card.date}): ${[...new Set(x.flags.map((f) => f.check))].join(', ')}, oldest since ${x.flags.map((f) => day(f.since)).sort()[0]}`).join('\n'));
      await store.putCardCheck(DIGEST_ROW, { day: today });
      counts.digest = standing.length;
    }
  } catch (e) { counts.errors++; counts.error = String(e?.message || e).slice(0, 200); }
  counts.runs = [...new Set(counts.runs)];
  return counts;
}

/** One card: read its page, run the checks, say what is new, return the state to store. */
async function checkCard(store, { card, state, kev, kevOk, watchRows, events, fetchImpl, now, site, counts }) {
  const page = await get(`${site}${card.url || `/cards/${card.slug}.html`}`, fetchImpl);
  const claims = page.status === 200 ? cardClaims(page.text) : null;
  if (!claims) counts.errors++; // the checks that need the card's own words wait for a round that can read it

  // the card's stories: the manifest's, and whatever brief story carries a CVE it declares
  let stories = [];
  try { stories = await store.getStories(card.story_ids || []); } catch { stories = []; }
  if ((card.cves || []).length) { try { const more = await store.listStoriesByCves(card.cves, 20); stories = [...stories, ...more.filter((m) => !stories.some((s) => s.id === m.id))]; } catch { /* manifest rows only */ } }
  const coverage = stories.filter((s) => (card.story_ids || []).includes(s.id) && s.raw_iocs?.hype?.card_coverage).map((s) => s.raw_iocs.hype.card_coverage)
    .sort((a, b) => String(b.checked_at).localeCompare(String(a.checked_at)))[0] || null;

  const found = [];
  const carry = (check) => (state.flags || []).filter((f) => f.check === check); // a check that could not run keeps what it last said
  if (kevOk) found.push(...checkKev({ card, claims, kev })); else found.push(...carry('kev'));
  if (claims) found.push(...await checkDistro({ card, claims, fetchImpl })); else found.push(...carry('distro'));
  let advisories = state.advisories || {};
  if (claims) {
    const a = await checkAdvisories({ card, claims, prev: advisories, now, fetchImpl });
    advisories = a.state;
    // an advisory change is an event, not a condition: it stays until the card is re-issued, the newest per page
    const cited = new Set(claims.advisories.map((x) => x.url)); const fresh = new Set(a.flags.map((f) => f.url));
    found.push(...a.flags, ...carry('advisory').filter((f) => cited.has(f.url) && !fresh.has(f.url)));
  } else found.push(...carry('advisory'));
  if (claims && kevOk) found.push(...checkExploitation({ card, claims, kev, events, stories })); else found.push(...carry('exploitation'));
  found.push(...checkHygiene({ card, coverage }));
  if (watchRows) found.push(...checkArchive({ card, watchRows, now })); else found.push(...carry('archive'));

  const before = new Map((state.flags || []).map((f) => [f.key, f]));
  const flags = found.map((f) => ({ ...f, since: before.get(f.key)?.since || iso(now) }));
  const raised = new Set(state.raised || []);
  const fresh = flags.filter((f) => !raised.has(f.key));
  // A KEV listing goes to the card loop, which writes the AI re-issue draft (lib/hype.js reissueCheck raises
  // a listing once per card and drafts it once, so asking again is harmless). The run is handed over on the
  // check that finds the listing and on the next day's: a tick that ran out of time before the loop reached
  // it would otherwise leave the listing without its draft.
  const asked = { ...(state.asked || {}) };
  const toDraft = flags.filter((f) => f.check === 'kev' && (asked[f.key] || 0) < 2);
  const own = toDraft.length ? stories.filter((s) => ownStory(card, s) && s.run_id).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0] : null;
  if (own) { counts.runs.push(own.run_id); for (const f of toDraft) asked[f.key] = (asked[f.key] || 0) + 1; }
  if (fresh.length) {
    counts.flags_new += fresh.length;
    let drafted = '';
    if (fresh.some((f) => f.check === 'kev')) drafted = own ? '\nKEV: the card loop is asked for an AI re-issue draft this tick.' : '\nKEV: no brief story carries this card, so no AI draft can be written; re-issue by hand.';
    await postDiscord(`Cutsign ⚑ card ${card.slug} (as of ${card.date}) may be stale:\n` + fresh.map((f) => `• [${f.check}] ${f.text}${f.url ? ` ${f.url}` : ''}`).join('\n')
      + `\n${site}${card.url || `/cards/${card.slug}.html`}${drafted}\nFlag only: nothing was changed, archived or published.`);
    for (const f of fresh) raised.add(f.key);
  }
  return { card_date: card.date, checked_at: iso(now), flags, raised: [...raised].slice(-200), asked, advisories, claims: claims ? { distro: claims.distro, exploitation: claims.exploitation, kev: claims.kev, advisories: claims.advisories.length } : state.claims || null };
}
