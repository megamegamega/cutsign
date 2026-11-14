// Hype score + the draft loop: which stories get nominated, when an AI draft is written, revised
// as evidence changes, and surfaced. Offline: memory store, fake LLM, captured mail and Discord,
// KEV served by a fake fetch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { hypeScore, threadOf, hypeSweep, coverageOnlySweep, fetchKev, evidenceFingerprint, describeChanges, actionable, cardDevelopments, cardFacts, describeFacts, P1_REASON, DRAFT_RESERVE_MS } from '../lib/hype.js';
import { scrub, DraftSchema, draftBody, buildDraftInput, huntsWithoutEsql, backfillEsql, lintPublicEsql } from '../lib/carddraft.js';
import { CARDS, cardIndex, aiCard, publishedRows } from '../lib/cards.js';
import { RECHECK_MS } from '../lib/coverage.js';
import { installFakeLLM, installFakeBatch, captureOutputs } from './helpers.js';
import { collectJobs } from '../lib/jobs.js';
import { _resetBatchMode } from '../lib/batchmode.js';

// The draft-loop tests below predate auto-publishing and read the loop with it off; the
// publishing tests at the end turn it on explicitly.
process.env.CARD_AUTOPUBLISH = '0';
// Response actions add one small call per published card (lib/actions.js). The tests here count the
// loop's own calls with that off; test/actions.test.js reads the sweeps with it on.
process.env.CARD_ACTIONS = '0';

const uuid = (n) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;
const story = (n, over = {}) => ({
  id: uuid(n), run_id: 'r1', ordinal: n, status: 'extracted', title: `Story ${n}`, summary: 'What happened, in two sentences.',
  priority: 1, selected: true, cves: [], threat_actor: null, raw_iocs: { exposure: null }, source_urls: [], sources: [], guidance: [],
  behaviors: [], samples: [], newIocs: [], repeatIocs: [], updates_story_id: null, ...over,
});

test('score: fresh KEV counts, a months-old listing does not', () => {
  const kev = new Map([['CVE-2026-1', '2026-10-15'], ['CVE-2021-9', '2021-12-10']]);
  const fresh = hypeScore({ story: story(1, { cves: ['CVE-2026-1'] }), kev, day: '2026-10-16' });
  const stale = hypeScore({ story: story(2, { cves: ['CVE-2021-9'] }), kev, day: '2026-10-16' });
  assert.equal(fresh.score - stale.score, 3);
  assert.ok(fresh.reasons.some((r) => r.startsWith('KEV CVE-2026-1')));
});

test('score: thread age, publishers, primary source, exposure, actor and watch signals add up', () => {
  const day1 = story(1, { source_urls: ['https://a.example.test/1', 'https://b.example.test/1'] });
  const day2 = story(2, { updates_story_id: day1.id, source_urls: ['https://c.example.test/2'] });
  const day3 = story(3, {
    updates_story_id: day2.id, threat_actor: 'UNC0000', raw_iocs: { exposure: { only_if: ['management interface exposed to the internet'] } },
    sources: [{ url: 'https://www.cisa.gov/news-events/alerts/x', publisher: 'CISA' }, { url: 'https://d.example.test/3' }],
  });
  const priorById = new Map([[day1.id, day1], [day2.id, day2]]);
  const thread = threadOf(day3, priorById);
  assert.deepEqual(thread.map((r) => r.id), [day1.id, day2.id, day3.id]);
  const now = Date.parse('2026-10-18T12:00:00Z');
  const events = [
    { watch_story_id: day1.id, created_at: '2026-10-17T20:00:00Z', kind: 'page_changed', level: 'HIGH', assessment: { material: true } },
    { watch_story_id: day2.id, created_at: '2026-10-18T01:00:00Z', kind: 'poc_repo', level: 'LOW' },
    { watch_story_id: day2.id, created_at: '2026-10-10T01:00:00Z', kind: 'new_source', level: 'LOW' }, // too old
  ];
  const { score, reasons } = hypeScore({ story: day3, thread, events, day: '2026-10-18', now });
  // P1 2, deep 1, day 3 → +2, 5 publishers → +2, primary 1, exposure 1, actor 1, material 2, PoC 1
  assert.equal(score, 13, reasons.join(' | '));
  assert.ok(reasons.includes('day 3 of the story +2'));
  assert.ok(reasons.includes('public PoC repo +1'));
});

test('score: two items in one brief are one day of the story, not two', () => {
  const a = story(1, { brief_date: '2026-10-29', cves: ['CVE-2026-41709'] });
  const b = story(2, { brief_date: '2026-10-29', cves: ['CVE-2026-41709'], updates_story_id: a.id });
  const { reasons } = hypeScore({ story: b, thread: threadOf(b, new Map([[a.id, a]])), day: '2026-10-29' });
  assert.ok(!reasons.some((r) => r.startsWith('day ')), reasons.join(' | '));
  const c = story(3, { brief_date: '2026-10-30', cves: ['CVE-2026-41709'], updates_story_id: b.id });
  assert.ok(hypeScore({ story: c, thread: threadOf(c, new Map([[a.id, a], [b.id, b]])), day: '2026-10-30' }).reasons.includes('day 2 of the story +1'));
});

test('threadOf stops at a cycle and at an unloaded row', () => {
  const a = story(1, { updates_story_id: uuid(2) }); const b = story(2, { updates_story_id: uuid(1) });
  assert.equal(threadOf(a, new Map([[b.id, b], [a.id, a]])).length, 2);
  assert.equal(threadOf(story(3, { updates_story_id: uuid(9) }), new Map()).length, 1);
});

test('fetchKev returns an empty map on failure', async () => {
  assert.equal((await fetchKev(async () => { throw new Error('down'); })).size, 0);
  assert.equal((await fetchKev(async () => new Response('{}', { status: 500 }))).size, 0);
});

test('fingerprint, actionability and change description', () => {
  const s = story(1);
  const fp0 = evidenceFingerprint({ story: s, thread: [s], day: '2026-10-16' });
  assert.equal(actionable(fp0), false, 'a P1 with nothing to act on waits');
  const s2 = { ...s, guidance: [{ url: 'https://v.example.test/g', raw: 'hunt', publisher_tier: 'A' }], newIocs: [{ type: 'domain', value_norm: 'c2.example-bad.net' }], cves: ['CVE-2026-1'] };
  const fp1 = evidenceFingerprint({ story: s2, thread: [s2], kev: new Map([['CVE-2026-1', '2026-10-16']]), day: '2026-10-16' });
  assert.equal(actionable(fp1), true);
  assert.deepEqual(describeChanges(fp0, fp1), ['1 new published detection guidance item', '1 new IoC', 'CISA KEV listed CVE-2026-1']);
  assert.deepEqual(describeChanges(null, fp1), []);
});

// The dirty strings are assembled at runtime so this file never carries the patterns the hygiene test forbids.
const dirty = (parts) => parts.join('');
test('scrub applies the repo hygiene rules to machine text', () => {
  const spl = dirty(['index', '=prod_main source', 'type="xyz:abc" host=db1.', 'corp.example.com | stats count']);
  const esql = dirty(['FROM logs-prod-web, <entra_signin>, metrics-x | WHERE host.name == "db1.', 'corp.example.com" | STATS c = COUNT(*)']);
  const d = scrub({ title: 'x', verdict: 'v', detect: [{ name: 'h', log_source: 'EDR', spl, esql, hit_means: 'm' }, { name: 'n', log_source: 'x', spl: 'index=*', esql: null, hit_means: 'm' }],
    what_happened: [dirty(['seen on fs01.', 'internal.example.net'])], scope: { affected: [dirty(['srv.', 'lan.example.org'])] } });
  assert.equal(d.detect[0].spl, 'index=* sourcetype=<xyz:abc> host=<host> | stats count');
  assert.equal(d.detect[0].esql, 'FROM logs-*, <entra_signin> | WHERE host.name == "<host>" | STATS c = COUNT(*)', 'concrete data streams become logs-*; placeholders stay; duplicates collapse');
  assert.equal(d.detect[1].esql, null, 'a hunt with no ES|QL twin stays without one');
  assert.equal(d.what_happened[0], 'seen on <host>');
  assert.equal(d.scope.affected[0], '<host>');
});

const DRAFT = {
  title: 'Vendor appliance zero-day exploited; patch and hunt', verdict: 'Patch today; hunt for shells from the appliance process. [S1]', lane: 'Hunt / IR + patch',
  confidence: 'high', confidence_reason: 'Vendor primary source confirms exploitation.',
  what_happened: ['Vendor confirmed exploitation. [S1]', 'CISA added the CVE to KEV. [S2]'],
  timeline: [{ date: '2026-10-15', event: 'Advisory published', source: 'S1' }],
  detect: [{ name: 'Shell from appliance process', log_source: 'appliance syslog', spl: ['index', '=main parent=httpd child=sh | stats count'].join(''),
    esql: 'FROM logs-* | WHERE process.parent.name == "httpd" AND process.name == "sh" | STATS count = COUNT(*)', hit_means: 'post-exploitation' }],
  verify: ['Confirm the child process is not the vendor backup job.'],
  triage: { priority: 'P1', why: 'Exploited in the wild, internet-facing.' },
  scope: { affected: ['Appliance versions before 1.2'], only_if: ['management interface exposed'], not_affected_if: ['1.2 or later'], fixed_in: '1.2', enumerate: ['Every appliance and its version'] },
  contain: ['Patch to 1.2', 'Rotate credentials'], eradicate: ['Remove the SUID binary'], recover: ['Validate from a clean image'],
  reenter_when: ['A second product is named'], debrief: ['Record patch dates'],
  coverage_checks: [{ category: 'vulnerability scanner', check: 'look up the CVE in the vendor KB' }],
  open_questions: [], changes_since_prior: ['something the model claims changed'],
  sources: [{ ref: 'S1', url: 'https://www.cisa.gov/news-events/alerts/x', publisher: 'CISA' }, { ref: 'S9', url: 'https://invented.example.test/', publisher: null }],
};

/** A run with one P1 deep-read story over the nominate bar, plus one quiet story. */
async function world({ carded = false, actionableStory = true } = {}) {
  const out = captureOutputs();
  const store = memoryStore();
  const t = store._tables;
  const brief = await store.insertBrief({ message_id: 'm1', brief_date: '2026-10-16', subject: 'brief', received_at: '2026-10-16T11:00:00Z' });
  const run = await store.insertRun({ brief_id: brief.id, stage: 'sent' });
  const hot = story(1, { run_id: run.id, cves: actionableStory ? ['CVE-2026-1'] : [], threat_actor: 'UNC0000', id: carded ? CARDS[0].story_ids[0] : uuid(1),
    source_urls: ['https://www.cisa.gov/news-events/alerts/x', 'https://a.example.test/1', 'https://b.example.test/2'], raw_iocs: { exposure: { only_if: ['internet-exposed'] } } });
  const quiet = story(2, { run_id: run.id, priority: 3, selected: false });
  t.stories.push(hot, quiet);
  // KEV from the catalog URL; every coverage source is unreachable in this world unless a test routes it
  const kevFetch = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }] });
  const calls = installFakeLLM(() => DRAFT);
  return { out, store, run, kevFetch, calls, hot };
}
/** A fake network: the KEV catalog, optional canned responses by URL substring, 404 for the rest. */
function routed({ kev = [], routes = {} } = {}) {
  const impl = async (url) => {
    const u = String(url); impl.calls.push(u);
    if (u.includes('cisa.gov/sites/default/files/feeds')) return new Response(JSON.stringify({ vulnerabilities: kev }), { status: 200 });
    for (const [k, body] of Object.entries(routes)) if (u.includes(k)) return new Response(typeof body === 'function' ? body() : body, { status: 200 });
    return new Response('nope', { status: 404 });
  };
  impl.calls = [];
  return impl;
}
const CF_FEED = (hit) => `<rss><channel>${hit ? '<item><title>WAF Release - Emergency - CVE-2026-1</title><link>https://developers.cloudflare.com/waf/change-log/x/</link></item>' : '<item><title>routine</title><link>https://developers.cloudflare.com/waf/change-log/y/</link></item>'}</channel></rss>`;

test('sweep: with no time for a story it yields before starting one and writes nothing; run again, it finishes', async () => {
  const { store, run, kevFetch, calls } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now, deadline: Date.now() + DRAFT_RESERVE_MS - 1000 });
  assert.equal(c1.yielded, true); assert.equal(c1.scored, 0); assert.equal(c1.drafted, 0);
  assert.equal(calls.length, 0, 'no model call started');
  assert.equal(store._tables.card_drafts?.length || 0, 0);
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now, deadline: Date.now() + 10 * 60_000 });
  assert.ok(!c2.yielded); assert.equal(c2.drafted, 1, JSON.stringify(c2));
});

test('sweep: nominates, writes an AI draft when actionable, emails and posts it, and does not repeat on unchanged evidence', async () => {
  const { out, store, run, kevFetch, calls, hot } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  // P1 2, deep 1, KEV 3, 3 publishers 1, primary 1, exposure 1, actor 1 = 10 → nominated and surfaced
  assert.equal(c1.scored, 2); assert.equal(c1.nominated, 1); assert.equal(c1.drafted, 1); assert.equal(c1.surfaced, 1); assert.equal(c1.errors, 0, JSON.stringify(c1));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▲ card candidate') && l.includes('KEV CVE-2026-1 +3')));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI draft ready to publish')));
  assert.equal(out.emails.length, 1); assert.match(out.emails[0].subject, /AI draft ready to publish/);
  const drafts = await store.listCardDrafts();
  assert.equal(drafts.length, 1); assert.equal(drafts[0].status, 'draft'); assert.equal(drafts[0].version, 1); assert.ok(drafts[0].surfaced_at);
  assert.deepEqual(drafts[0].thread_ids, [hot.id]);
  assert.equal(drafts[0].draft.detect[0].spl, 'index=* parent=httpd child=sh | stats count', 'scrubbed before storing');
  assert.deepEqual(drafts[0].draft.changes_since_prior, [], 'a first draft has no change list, whatever the model says');
  assert.ok(!drafts[0].draft.sources.some((s) => s.url.includes('invented')), 'invented sources dropped');
  assert.equal(calls.length, 1); assert.equal(calls[0].schemaName, 'card_draft');
  assert.match(calls[0].messages[0].content, /<story date="2026-10-16" today="true">/);
  assert.doesNotMatch(calls[0].messages[0].content, /<prior_draft/);
  assert.equal((await store.getStory(hot.id)).raw_iocs.hype.draft_id, drafts[0].id);
  // the hourly tick an hour later: same evidence, nothing to say or write
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c2.nominated, 0); assert.equal(c2.drafted, 0); assert.equal(c2.revised, 0); assert.equal(calls.length, 1); assert.equal(out.emails.length, 1);
  const page = draftBody(drafts[0]);
  assert.match(page, /AI-generated draft, unreviewed/); assert.match(page, /index=\*/); assert.match(page, /Re-enter the loop when/); assert.match(page, /dynamicincidentresponse\.com/);
});

test('sweep: the loop revises the draft when the evidence changes, superseding the prior version', async () => {
  const { out, store, run, kevFetch, calls, hot } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  // afternoon: published guidance lands on the story
  const row = store._tables.stories.find((s) => s.id === hot.id);
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 });
  assert.equal(c.revised, 1); assert.equal(c.drafted, 0); assert.equal(calls.length, 2);
  assert.equal(calls[1].effort, 'low', 'a revision edits the prior draft against a change list');
  assert.match(calls[1].messages[0].content, /<prior_draft version="1">/);
  assert.match(calls[1].messages[0].content, /<changes>1 new published detection guidance item<\/changes>/);
  const all = (await store.listCardDrafts()).sort((a, b) => a.version - b.version);
  assert.equal(all.length, 2); assert.equal(all[0].status, 'superseded'); assert.equal(all[1].status, 'draft'); assert.equal(all[1].version, 2); assert.equal(all[1].supersedes, all[0].id);
  assert.deepEqual(all[1].draft.changes_since_prior, ['something the model claims changed']);
  assert.ok(out.discord.some((l) => l.includes('AI draft') && l.includes('Changed: 1 new published detection guidance item')));
  assert.equal(row.raw_iocs.hype.draft_id, all[1].id);
  assert.match(draftBody(all[1]), /Changed since version 1/);
});

test('sweep: a nominated story with nothing actionable waits; actionable but under the publish bar it is still not drafted; it is drafted the sweep it crosses', async () => {
  const { store, run, kevFetch, calls, hot } = await world({ actionableStory: false });
  const now = Date.parse('2026-10-16T13:00:00Z');
  // P1 2, deep 1, 3 publishers 1, primary 1, exposure 1, actor 1 = 7 → nominated, not actionable (and not day one: the run started today, but the knob is tested elsewhere)
  process.env.CARD_P1_DAY_ONE = '0';
  try {
    const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
    assert.equal(c1.nominated, 1); assert.equal(c1.drafted, 0); assert.equal(c1.waiting, 1); assert.equal(calls.length, 0);
    // guidance lands: actionable now, score still 7 — a draft nobody would see is not written
    store._tables.evidence.push({ id: 'e1', story_id: uuid(1), kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
    const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
    assert.equal(c2.drafted, 0); assert.equal(c2.below_bar, 1, JSON.stringify(c2)); assert.equal(c2.nominated, 0, 'score unchanged, no second nomination'); assert.equal(calls.length, 0);
    // a material development on watch: +2 → 9, over the bar → its first draft, with everything gathered so far
    store._tables.watches.push({ id: 'w1', story_id: hot.id, title: hot.title, status: 'active' });
    store._tables.watch_events.push({ id: 'ev1', watch_id: 'w1', created_at: '2026-10-16T14:30:00Z', kind: 'new_source', level: 'HIGH', summary: 'Exploitation confirmed.', assessment: { material: true, summary: 'Exploitation confirmed.' } });
    const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 2 * 3600_000 });
    assert.equal(c3.drafted, 1, JSON.stringify(c3)); assert.equal(c3.surfaced, 1); assert.equal(calls.length, 1);
    assert.equal(calls[0].effort, 'medium', 'a first draft composes');
    assert.match(calls[0].messages[0].content, /<published_guidance>/);
  } finally { delete process.env.CARD_P1_DAY_ONE; }
});

test('sweep: a dismissed draft is left alone; a thread with a hand-written card is skipped', async () => {
  const w = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now });
  const [d] = await w.store.listCardDrafts();
  await w.store.updateCardDraft(d.id, { status: 'dismissed' });
  w.store._tables.evidence.push({ id: 'e1', story_id: w.hot.id, kind: 'guidance', raw: 'Hunt', url: 'https://v.example.test/g', publisher_tier: 'B' });
  const c = await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now: now + 3600_000 });
  assert.equal(c.drafted + c.revised, 0); assert.equal(w.calls.length, 1);
  const k = await world({ carded: true });
  const c2 = await hypeSweep(k.store, { run: k.run, fetchImpl: k.kevFetch, now });
  assert.equal(c2.carded, 1); assert.equal(c2.nominated, 0); assert.equal(k.calls.length, 0); assert.equal(k.out.emails.length, 0);
});

test('sweep: a draft that fails validation twice is reported, not stored, and the nomination still posts', async () => {
  const { out, store, run, kevFetch } = await world();
  installFakeLLM(() => ({ title: 'incomplete' }));
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.nominated, 1); assert.equal(c.drafted, 0); assert.equal(c.errors, 1);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ✖ AI draft failed')));
  assert.equal((await store.listCardDrafts()).length, 0);
});

test('sweep: with the drafts table missing, nominations still post and the counts say what to apply', async () => {
  const { out, store, run, kevFetch, calls } = await world();
  store.listCardDrafts = async () => { throw new Error('relation "card_drafts" does not exist'); };
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.nominated, 1); assert.equal(c.drafted, 0); assert.equal(calls.length, 0);
  assert.match(c.drafts_disabled, /0004_card_drafts/);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▲ card candidate')));
});

test('sweep: a carded thread with a KEV listing after the card date is raised once and gets a re-issue draft', async () => {
  const { out, store, run, calls, hot } = await world({ carded: true });
  const card = CARDS[0];
  const now = Date.parse('2026-10-28T13:00:00Z');
  // the catalog lists the thread's CVE the day after the card was written
  const kevLate = async () => new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-24', dueDate: '2026-10-27' }] }), { status: 200 });
  const c1 = await hypeSweep(store, { run, fetchImpl: kevLate, now });
  assert.equal(c1.carded, 1); assert.equal(c1.stale, 1); assert.equal(c1.drafted, 1); assert.equal(c1.nominated, 0); assert.equal(c1.errors, 0, JSON.stringify(c1));
  const nudge = out.discord.find((l) => l.startsWith(`Cutsign ▲ card ${card.slug}`));
  assert.ok(nudge, out.discord.join('\n')); assert.match(nudge, /CISA KEV listed CVE-2026-1 on 2026-10-24 \(federal due 2026-10-27\)/); assert.match(nudge, /AI re-issue draft follows/);
  assert.ok(out.discord.some((l) => l.includes(`AI re-issue draft for card ${card.slug}`)));
  assert.equal(calls.length, 1);
  assert.match(calls[0].messages[0].content, new RegExp(`<existing_card slug="${card.slug}" as_of="${card.date}">`));
  assert.match(calls[0].messages[0].content, /<changes>CISA KEV listed CVE-2026-1/);
  const [d] = await store.listCardDrafts();
  assert.ok(d.surfaced_at, 're-issue drafts are always surfaced'); assert.deepEqual(d.draft.changes_since_prior, ['CISA KEV listed CVE-2026-1 on 2026-10-24 (federal due 2026-10-27)']);
  assert.deepEqual((await store.getStory(hot.id)).raw_iocs.hype.card_devs, ['kev:CVE-2026-1']);
  // next tick: the same development is not raised or drafted again
  const c2 = await hypeSweep(store, { run, fetchImpl: kevLate, now: now + 3600_000 });
  assert.equal(c2.stale, 0); assert.equal(c2.drafted + c2.revised, 0); assert.equal(calls.length, 1);
  // a HIGH watch development after the card date is a second, separate development: raised and revised
  const w = { id: 'w1', story_id: hot.id, title: hot.title, status: 'active' };
  store._tables.watches.push(w);
  store._tables.watch_events.push({ id: 'ev1', watch_id: w.id, created_at: '2026-10-28T09:00:00Z', kind: 'kev_added', level: 'HIGH', summary: 'A second product is named.', assessment: { material: true, summary: 'A second product is named.' } });
  const c3 = await hypeSweep(store, { run, fetchImpl: kevLate, now: now + 7200_000 });
  assert.equal(c3.stale, 1); assert.equal(c3.revised, 1); assert.equal(calls.length, 2);
  assert.match(calls[1].messages[0].content, /<prior_draft version="1">/);
  assert.deepEqual((await store.getStory(hot.id)).raw_iocs.hype.card_devs, ['kev:CVE-2026-1', 'event:ev1']);
});

test('a draft takes its Detect section from the thread\'s proposer hunts instead of inventing queries', async () => {
  const { store, run, kevFetch, calls, hot } = await world();
  const hunt = {
    id: 'p1', name: 'sp_token_then_mail_access', shape: 'correlation', confidence: 'derived', hypothesis: 'A listed appId obtains a token and then reads mail.',
    stages: [{ log_source_key: 'entra_signin', predicate: 'x', fields: [] }, { log_source_key: 'm365_ual', predicate: 'y', fields: [] }], join: { on: 'appId', window: '1h' },
    splunk: 'index=<entra_signin> | join appId [ search index=<m365_ual> | fields appId ] | table appId', elastic: 'FROM <entra_signin> | LOOKUP JOIN <m365_ual> ON appId | KEEP appId',
    params: {}, noise_hint: 'the backup job reads mail on a schedule', from: ['behaviors[0]'], tier: 'proposed', model_tier: 'propose', model: 'm', cost_usd: 0.2,
  };
  const row = store._tables.stories.find((s) => s.id === hot.id);
  row.raw_iocs = { ...(row.raw_iocs || {}), proposed_queries: [hunt] };
  // the model writes its own (unlinted) hunt plus a hit_means for the proposer's; only the latter survives
  const draftCalls = installFakeLLM(() => ({ ...DRAFT, detect: [{ name: 'sp_token_then_mail_access', log_source: 'x', spl: 'index=* ignored', esql: null, hit_means: 'a listed app read a mailbox it never touched before' }, { name: 'invented', log_source: 'y', spl: 'index=* parent=x', esql: 'FROM logs-* | WHERE x == 1', hit_means: 'z' }] }));
  assert.equal(calls.length, 0, 'the fixture fake was replaced before any call');
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.drafted, 1, JSON.stringify(c));
  const [d] = await store.listCardDrafts();
  assert.equal(d.draft.detect.length, 1);
  assert.equal(d.draft.detect[0].spl, hunt.splunk); assert.equal(d.draft.detect[0].esql, hunt.elastic); assert.equal(d.draft.detect[0].proposal_id, 'p1');
  assert.equal(d.draft.detect[0].log_source, 'entra_signin → m365_ual'); assert.equal(d.draft.detect[0].hit_means, 'a listed app read a mailbox it never touched before');
  const input = draftCalls.at(-1).messages[0].content;
  assert.match(input, /<proposed_hunts>\n- sp_token_then_mail_access \[entra_signin → m365_ual\] derived:/);
  const page = draftBody(d);
  assert.match(page, /proposer hunt, derived/); assert.match(page, /LOOKUP JOIN &lt;m365_ual&gt;/); assert.match(page, /Noise: the backup job/);
  // both dialects sit in one switchable block (public/cards/qswitch.js adds the Splunk | Elastic tabs)
  assert.match(page, /<div class="qs"><pre data-q="spl">index=&lt;entra_signin&gt;[^<]*<\/pre><pre data-q="esql">FROM &lt;entra_signin&gt;[^<]*<\/pre><\/div>/);
});

test('a model-written hunt renders its ES|QL twin beside the Splunk search, and only the Splunk block when it has none', () => {
  const page = draftBody({ id: 'd1', version: 1, status: 'draft', score: 9, reasons: [], created_at: '2026-10-16T13:00:00Z',
    draft: { ...DRAFT, detect: [DRAFT.detect[0], { name: 'splunk only', log_source: 'x', spl: 'index=* a=1', esql: null, hit_means: 'y' }] } });
  // draftBody renders what it is given (scrub runs in the pipeline), so the fixture's raw index name shows here
  assert.match(page, /<div class="qs"><pre data-q="spl">index=\w+ parent=httpd child=sh \| stats count<\/pre><pre data-q="esql">FROM logs-\* \| WHERE process\.parent\.name == &quot;httpd&quot;[^<]*<\/pre><\/div>/);
  assert.match(page, /<div class="qs"><pre data-q="spl">index=\* a=1<\/pre><\/div>/);
  assert.ok(DraftSchema.safeParse(DRAFT).success, 'the fixture draft is a valid answer');
  assert.ok(!DraftSchema.safeParse({ ...DRAFT, detect: [{ name: 'h', log_source: 'x', spl: 'index=*', hit_means: 'm' }] }).success, 'esql is required (nullable), so the model always answers it');
});

test('cardDevelopments: nothing before the card date, KEV and HIGH events after it', () => {
  const card = { slug: 'x', date: '2026-10-23', cves: ['CVE-2026-1'] };
  const thread = [{ id: 's1', cves: ['CVE-2026-2'] }];
  const kev = new Map([['CVE-2026-1', '2026-10-20'], ['CVE-2026-2', { dateAdded: '2026-10-25', dueDate: null }]]);
  const events = [
    { id: 'a', watch_story_id: 's1', level: 'HIGH', created_at: '2026-10-22T00:00:00Z', kind: 'kev_added' },
    { id: 'b', watch_story_id: 's1', level: 'LOW', created_at: '2026-10-26T00:00:00Z', kind: 'poc_repo' },
    { id: 'c', watch_story_id: 's1', level: 'HIGH', created_at: '2026-10-26T00:00:00Z', kind: 'page_change', summary: 'Vendor confirms exploitation.' },
  ];
  assert.deepEqual(cardDevelopments({ card, thread, kev, events }).map((x) => x.key), ['kev:CVE-2026-2', 'event:c']);
});

test('draft input carries only stored facts; the schema has no slot for a coverage claim', () => {
  const s = story(1, { guidance: [{ url: 'https://vendor.example.test/g', raw: 'Hunt for X', publisher_tier: 'A' }] });
  const { text, sources } = buildDraftInput({ story: s, thread: [s], data: { date: '2026-10-16' }, score: 7, reasons: ['P1 +2'] });
  assert.equal(sources.length, 1); assert.match(text, /<published_guidance>/);
  assert.ok(!DraftSchema.safeParse({ ...DRAFT, coverage_checks: [{ vendor: 'x', status: 'covered' }] }).success);
});

// ---- auto-publishing and the automated coverage check -------------------------------------------

const published = async () => { process.env.CARD_AUTOPUBLISH = '1'; const w = await world(); return w; };
const off = () => { process.env.CARD_AUTOPUBLISH = '0'; };

test('publish: a draft over the surface bar is published as an AI card with its coverage check, and the site indexes it', async (t) => {
  t.after(off);
  const { out, store, run, calls, hot } = await published();
  const net = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': CF_FEED(true) } });
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: net, now });
  assert.equal(c1.published, 1); assert.equal(c1.drafted, 1); assert.equal(c1.coverage_checked, 1); assert.equal(c1.errors, 0, JSON.stringify(c1));
  const [row] = await store.listCardDrafts();
  assert.equal(row.status, 'promoted'); assert.equal(row.promoted_slug, 'vendor-appliance-zero-day-exploited-2026'); assert.ok(row.surfaced_at);
  assert.deepEqual(row.draft.cves, ['CVE-2026-1']);
  const cov = row.draft.coverage;
  assert.ok(cov?.lanes?.length, 'coverage stored on the draft');
  assert.equal(cov.lanes.find((l) => l.id === 'kev:CVE-2026-1').status, 'published');
  assert.equal(cov.lanes.find((l) => l.id === 'cloudflare_waf').status, 'published');
  assert.equal(cov.lanes.find((l) => l.id === 'crowdstrike').status, 'check failed');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI verdict card published') && l.includes('/cards/vendor-appliance-zero-day-exploited-2026') && l.includes('coverage:')), out.discord.join('\n'));
  assert.match(out.emails[0].subject, /AI verdict card published/);
  assert.equal(calls.length, 1, 'coverage is fetches, not model calls');
  // the site: the row is a card, found from the story thread; its page says what it is
  const idx = cardIndex(await store.listCardDrafts({ status: 'promoted' }));
  assert.equal(idx.cardForStory(hot).url, '/cards/vendor-appliance-zero-day-exploited-2026');
  const page = draftBody(row, { published: true });
  assert.match(page, /published automatically by the pipeline/); assert.match(page, /Detection coverage — checked automatically/); assert.match(page, /Cloudflare WAF/);
  assert.doesNotMatch(page, /human edit/);
  // an hour later: nothing new, coverage not yet stale, no second publish
  const c2 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.published, 0); assert.equal(c2.coverage_checked, 0); assert.equal(calls.length, 1);
});

test('publish: a P1 is drafted and published on day one even with a score far below the bar; the banner says it is an early read; CARD_P1_DAY_ONE=0 reverts', async (t) => {
  t.after(() => { off(); delete process.env.CARD_P1_DAY_ONE; });
  const { out, store, run, hot } = await published();
  // day one of a P1 from two secondary outlets: no deep read, no fresh KEV, no primary source, no actor → score 2
  Object.assign(hot, { selected: false, threat_actor: null, source_urls: ['https://news.example.test/a', 'https://news.example.test/b'], raw_iocs: { exposure: { fixed_in: '2.4.1' } } }); // actionable: a fix version is stated
  const net = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2021-01-01' }] });
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c = await hypeSweep(store, { run, fetchImpl: net, now });
  assert.equal(c.published, 1, JSON.stringify(c)); assert.equal(c.drafted, 1);
  const [row] = await store.listCardDrafts();
  assert.equal(row.status, 'promoted'); assert.ok(row.promoted_slug);
  assert.ok(row.score < 6, `score ${row.score} is below even the nomination bar`);
  assert.ok(row.reasons.includes(P1_REASON), row.reasons.join(' | '));
  const page = draftBody(row, { published: true });
  assert.match(page, /on day one because the brief rated the story P1/); assert.match(page, /early read from few sources/);
  assert.ok(out.discord.some((l) => l.includes('card candidate') && l.includes('P1: card on day one')), out.discord.join('\n'));
  // the knob off: the same story is skipped on score alone
  process.env.CARD_P1_DAY_ONE = '0';
  const w2 = await published();
  Object.assign(w2.hot, { selected: false, threat_actor: null, source_urls: ['https://news.example.test/a'], raw_iocs: { exposure: { fixed_in: '2.4.1' } } });
  const c2 = await hypeSweep(w2.store, { run: w2.run, fetchImpl: net, now });
  assert.equal(c2.published, 0); assert.equal(c2.drafted, 0);
  // a P1 with nothing actionable yet is not drafted, and Discord says what it is waiting for
  delete process.env.CARD_P1_DAY_ONE;
  const w3 = await published();
  Object.assign(w3.hot, { selected: false, threat_actor: null, cves: [], source_urls: ['https://news.example.test/a'], raw_iocs: { exposure: null }, behaviors: [] });
  const c3 = await hypeSweep(w3.store, { run: w3.run, fetchImpl: net, now });
  assert.equal(c3.published, 0); assert.equal(c3.waiting, 1, JSON.stringify(c3));
  assert.ok(w3.out.discord.some((l) => l.includes('P1 without anything actionable yet')), w3.out.discord.join('\n'));
});

/** Four more P1s behind the world's hot story: quick reads from two outlets, each with a fix version (actionable), far under the bar. */
const moreP1s = (w) => { for (const n of [3, 4, 5, 6]) w.store._tables.stories.push(story(n, { run_id: w.run.id, selected: false, source_urls: ['https://news.example.test/a', 'https://news.example.test/b'], raw_iocs: { exposure: { fixed_in: `2.4.${n}` } } })); };

test('publish: day-one cards go to the brief\'s first CARD_P1_PER_DAY P1s (3); the others are counted and wait for the publish bar, sweep after sweep', async (t) => {
  t.after(() => { off(); delete process.env.CARD_P1_PER_DAY; });
  const w = await published(); moreP1s(w);
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c = await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now });
  assert.equal(c.published, 3, JSON.stringify(c)); assert.equal(c.day_one_capped, 2); assert.equal(w.calls.length, 3);
  const rows = await w.store.listCardDrafts();
  assert.deepEqual(rows.map((r) => r.story_id).sort(), [uuid(1), uuid(3), uuid(4)], 'the top story and the next two P1s in brief order');
  assert.equal(w.out.emails.filter((m) => /AI verdict card published/.test(m.subject)).length, 3);
  // the cards existing changes nothing: no slot passes to the fourth P1 on a later sweep
  const c2 = await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now: now + 3600_000 });
  assert.equal(c2.published, 0, JSON.stringify(c2)); assert.equal(c2.day_one_capped, 2); assert.equal(w.calls.length, 3);
  // the knob raised: every P1 gets its card
  process.env.CARD_P1_PER_DAY = '9';
  const c3 = await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now: now + 7200_000 });
  assert.equal(c3.published, 2, JSON.stringify(c3)); assert.ok(!c3.day_one_capped); assert.equal(w.calls.length, 5);
});

test('publish: a revision re-issues the published card in place (same slug, old version superseded); dismissing unpublishes', async (t) => {
  t.after(off);
  const { store, run, kevFetch, calls, hot, out } = await published();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 });
  assert.equal(c.revised, 1); assert.equal(c.published, 1); assert.equal(calls.length, 2);
  const all = (await store.listCardDrafts()).sort((a, b) => a.version - b.version);
  assert.equal(all[0].status, 'superseded'); assert.equal(all[1].status, 'promoted'); assert.equal(all[1].promoted_slug, all[0].promoted_slug);
  assert.equal(cardIndex(all).cards.filter((x) => x.source === 'ai').length, 1, 'one card, the current version');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI verdict card re-issued (v2)')));
  // a person dismisses it: the loop stops and the card is gone from the index
  await store.updateCardDraft(all[1].id, { status: 'dismissed' });
  store._tables.evidence.push({ id: 'e2', story_id: hot.id, kind: 'guidance', raw: 'Hunt for Y', url: 'https://v.example.test/g', publisher_tier: 'B' });
  const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 8 * 3600_000 });
  assert.equal(c3.drafted + c3.revised + c3.published, 0); assert.equal(calls.length, 2);
  assert.equal(cardIndex(await store.listCardDrafts()).cards.filter((x) => x.source === 'ai').length, 0);
});

test('publish: a revision that leaves the Contain list alone keeps the card\'s response actions, and the record is not shown to the model', async (t) => {
  t.after(off);
  const { store, run, kevFetch, calls, hot } = await published();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  const [v1] = await store.listCardDrafts({ status: 'promoted' });
  const item = (step, text) => ({ step, text, kind: 'other', when: 'always', asset: 'any', reversible: true, pattern: null, targets: [] });
  const actions = { v: 1, for: 'record-key-0001', at: new Date(now).toISOString(), items: v1.draft.contain.map((text, i) => item(i + 1, text)), indicators: [] };
  await store.updateCardDraft(v1.id, { draft: { ...v1.draft, actions } });
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  assert.equal((await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 })).revised, 1);
  const [v2] = await store.listCardDrafts({ status: 'promoted' });
  assert.equal(v2.version, 2); assert.deepEqual(v2.draft.actions, actions);
  assert.match(calls[1].messages[0].content, /<prior_draft version="1">/);
  assert.ok(!calls[1].messages[0].content.includes('record-key-0001'), 'the prior draft goes to the model without the record');
  // a record that no longer restates the list is not carried: the next sweep classifies the new row
  await store.updateCardDraft(v2.id, { draft: { ...v2.draft, actions: { ...actions, items: [item(1, 'Some other step')] } } });
  store._tables.evidence.push({ id: 'e2', story_id: hot.id, kind: 'guidance', raw: 'Hunt for Y', url: 'https://v.example.test/g', publisher_tier: 'B' });
  assert.equal((await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 8 * 3600_000 })).revised, 1);
  const [v3] = await store.listCardDrafts({ status: 'promoted' });
  assert.equal(v3.version, 3); assert.ok(!('actions' in v3.draft));
});

test('publish: with autopublish off the draft waits; turning it on publishes it on the next sweep without a new model call', async (t) => {
  t.after(off);
  const { store, run, kevFetch, calls } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal((await store.listCardDrafts())[0].status, 'draft');
  process.env.CARD_AUTOPUBLISH = '1';
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c.published, 1); assert.equal(calls.length, 1);
  const [row] = await store.listCardDrafts();
  assert.equal(row.status, 'promoted'); assert.ok(row.promoted_slug);
});

test('mail: a published card\'s first publication is emailed; its re-issue posts to Discord and sends no email', async (t) => {
  t.after(off);
  const { store, run, kevFetch, hot, out } = await published();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(out.emails.filter((m) => /AI verdict card published/.test(m.subject)).length, 1, 'the first publication is emailed');
  const before = out.emails.length;
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 });
  assert.equal(c.revised, 1); assert.equal(c.published, 1);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI verdict card re-issued (v2)')), 'the re-issue still reaches Discord');
  assert.equal(out.emails.length, before, 'no email for the re-issue');
  assert.ok(!out.emails.some((m) => /re-issued/.test(m.subject)));
});

test('mail: a draft revised while unpublished and published later is emailed as a publication, not called a re-issue', async (t) => {
  t.after(off);
  const { store, run, kevFetch, hot, out } = await world(); // autopublish off: the draft waits
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 });
  const head = (await store.listCardDrafts()).find((d) => d.status === 'draft');
  assert.equal(head.version, 2, 'revised while unpublished');
  const before = out.emails.length;
  process.env.CARD_AUTOPUBLISH = '1';
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 5 * 3600_000 });
  assert.equal(c.published, 1, JSON.stringify(c));
  const mails = out.emails.slice(before);
  assert.equal(mails.length, 1, 'its first publication is emailed'); assert.match(mails[0].subject, /AI verdict card published/);
  assert.ok(!out.discord.some((l) => /re-issued/.test(l)), 'never labelled a re-issue');
});

test('coverage: the published card is re-checked daily and a lane that moved is posted', async (t) => {
  t.after(off);
  const { store, run, out } = await published();
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': CF_FEED(false) } }), now });
  let [row] = await store.listCardDrafts();
  assert.equal(row.draft.coverage.lanes.find((l) => l.id === 'cloudflare_waf').status, 'nothing found');
  // the next day Cloudflare ships a rule: the daily re-check sees it
  const later = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': CF_FEED(true) } });
  const c = await hypeSweep(store, { run, fetchImpl: later, now: now + RECHECK_MS + 1 });
  assert.equal(c.coverage_checked, 1, JSON.stringify(c)); assert.equal(c.coverage_changed, 1); assert.equal(c.published, 0);
  [row] = await store.listCardDrafts();
  assert.equal(row.draft.coverage.lanes.find((l) => l.id === 'cloudflare_waf').status, 'published');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ coverage changed for AI card') && l.includes('Cloudflare WAF managed-ruleset changelog: nothing found → published')));
});

test('esql backfill: a card drafted before the dialect existed gets its ES|QL twins once, in place, linted and scrubbed; the hourly tick never asks', async (t) => {
  t.after(off);
  const { store, run, calls } = await published();
  // two hunts stored without the esql key (pre-dialect); a third with null already (the model said: no twin)
  const strip = ({ esql, ...h }) => h;
  const detect = [strip(DRAFT.detect[0]), { ...strip(DRAFT.detect[0]), name: 'Second hunt', spl: 'index=* action=failure | stats count by user' }, { ...DRAFT.detect[0], name: 'No twin', esql: null }];
  const old = await store.insertCardDraft({ story_id: uuid(8), thread_ids: [uuid(8)], title: 'Older published card', score: 10, reasons: [], cost_usd: 0.5,
    draft: { ...DRAFT, detect, cves: ['CVE-2026-8'], coverage: { checked_at: '2026-10-16T12:00:00Z', lanes: [] } }, version: 1, status: 'promoted', promoted_slug: 'older-2026', surfaced_at: '2026-10-16T12:00:00Z' });
  assert.equal(huntsWithoutEsql(old.draft).length, 2);
  assert.ok(draftBody(old, { published: true }).split('data-q="esql"').length === 1, 'nothing to switch to before the backfill');
  const twins = { hunts: [
    { name: 'Shell from appliance process', esql: 'FROM logs-prod-endpoint | WHERE process.parent.name == "httpd" AND process.name == "sh" | STATS count = COUNT(*)' },
    { name: 'Second hunt', esql: 'FROM logs-* | WHERE event.outcome == "failure" AND source.ip == "203.0.113.9" | STATS count = COUNT(*) BY user.name' },
  ] };
  const before = calls.length;
  const base = installFakeLLM((user, n, req) => (req?.schemaName === 'esql_twins' ? twins : DRAFT));
  const net = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }] });
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c = await hypeSweep(store, { run, fetchImpl: net, now });
  assert.equal(c.esql_backfilled, 1, JSON.stringify(c)); assert.equal(c.errors, 0);
  const twinCalls = base.filter((r) => r.schemaName === 'esql_twins');
  assert.equal(twinCalls.length, 1, 'one call per card, not per hunt');
  assert.equal(twinCalls[0].effort, 'low');
  assert.doesNotMatch(twinCalls[0].messages[0].content, /No twin/, 'a hunt that already has its slot is not re-asked');
  const row = await store.getCardDraft(old.id);
  assert.equal(row.draft.detect[0].esql, 'FROM logs-* | WHERE process.parent.name == "httpd" AND process.name == "sh" | STATS count = COUNT(*)', 'a concrete data stream becomes logs-*');
  assert.equal(row.draft.detect[1].esql, null, 'an IP literal the Splunk search did not carry fails lint and is dropped');
  assert.equal(row.draft.detect[2].esql, null);
  assert.equal(huntsWithoutEsql(row.draft).length, 0, 'every hunt now has its slot');
  assert.ok(row.cost_usd > 0.5, 'the call is charged to the card');
  assert.equal(row.version, 1, 'no new version: the text did not change');
  assert.ok(row.draft.coverage?.checked_at, 'the daily coverage patch ran after the twins and kept them');
  const page = draftBody(row, { published: true });
  assert.equal(page.split('data-q="esql"').length - 1, 1); assert.equal(page.split('data-q="spl"').length - 1, 3);
  // again: nothing left to translate, no call; the hourly coverage-only tick never translates
  const c2 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.esql_backfilled, undefined); assert.equal(base.filter((r) => r.schemaName === 'esql_twins').length, 1);
  const fresh = await store.insertCardDraft({ story_id: uuid(9), thread_ids: [uuid(9)], title: 'Another old card', score: 10, reasons: [], draft: { ...DRAFT, detect: [strip(DRAFT.detect[0])], cves: [], coverage: { checked_at: '2026-10-01T12:00:00Z', lanes: [] } }, version: 1, status: 'promoted', promoted_slug: 'another-2026', surfaced_at: '2026-10-01T12:00:00Z' });
  await coverageOnlySweep(store, { fetchImpl: net, now: now + RECHECK_MS + 1 });
  assert.equal(huntsWithoutEsql((await store.getCardDraft(fresh.id)).draft).length, 1, 'the hourly tick left it for the daily sweep');
  assert.equal(base.filter((r) => r.schemaName === 'esql_twins').length, 1);
  void before;
});

test('esql backfill: an answer out of shape throws (retried another day) and a lint-clean public query passes', async () => {
  installFakeLLM(() => ({ nonsense: true }));
  await assert.rejects(backfillEsql({ detect: [{ name: 'x', spl: 'index=* | stats count' }] }), /failed validation/);
  assert.ok(lintPublicEsql('FROM logs-* | WHERE process.name == "sh" | STATS c = COUNT(*)').ok);
  assert.ok(!lintPublicEsql('FROM logs-* | WHERE user.name == "jsmith" | STATS c = COUNT(*)').ok, 'a username literal fails');
  assert.equal((await backfillEsql({ detect: [{ name: 'y', spl: 'index=*', esql: null }] })).translated, 0, 'nothing to do, no call');
});

test('coverage: a hand-written card gets the same daily check, stored on its manifest story row for the card page', async () => {
  const { store, run, hot, out } = await world({ carded: true });
  const card = CARDS[0];
  const now = Date.parse('2026-10-28T13:00:00Z');
  const net = routed({ kev: [{ cveID: card.cves[0] || 'CVE-2026-1', dateAdded: '2026-10-16' }], routes: { 'developers.cloudflare.com': CF_FEED(false) } });
  const c1 = await hypeSweep(store, { run, fetchImpl: net, now });
  assert.equal(c1.carded, 1); assert.equal(c1.coverage_checked, 1);
  const row = await store.getStory(hot.id);
  const cov = row.raw_iocs.hype.card_coverage;
  assert.ok(cov?.lanes?.length);
  assert.ok(cov.cves.includes(card.cves[0] || 'CVE-2026-1'), 'the CVEs the card names are checked');
  // same day: not re-asked; next day: re-asked, and a change is posted
  const c2 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.coverage_checked, 0);
  const c3 = await hypeSweep(store, { run, fetchImpl: routed({ kev: [], routes: { 'developers.cloudflare.com': CF_FEED(true) } }), now: now + RECHECK_MS + 1 });
  assert.equal(c3.coverage_checked, 1);
  assert.ok(out.discord.some((l) => l.startsWith(`Cutsign ▣ coverage changed for card ${card.slug}`)), out.discord.join('\n'));
});

test('coverage: cards and published drafts whose campaign is not in today\'s brief are still checked daily', async (t) => {
  t.after(off);
  const { store, run, out } = await published();
  const now = Date.parse('2026-10-28T13:00:00Z');
  // a hand-written card whose manifest row exists but belongs to an older run (not analyzed today)
  const card = CARDS[1];
  store._tables.stories.push(story(9, { id: card.story_ids[0], run_id: 'old-run', cves: card.cves, source_urls: ['https://www.cisa.gov/news-events/alerts/x'] }));
  // a published AI card from an earlier day, its check a day old
  const old = await store.insertCardDraft({ story_id: uuid(8), thread_ids: [uuid(8)], title: 'Older published card', score: 10, reasons: [], draft: { ...DRAFT, cves: ['CVE-2026-8'], coverage: { checked_at: '2026-10-27T12:00:00Z', lanes: [{ id: 'cloudflare_waf', name: 'Cloudflare WAF managed-ruleset changelog', status: 'nothing found', detail: '' }] } }, version: 1, status: 'promoted', promoted_slug: 'older-2026', surfaced_at: '2026-10-27T12:00:00Z' });
  const net = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': '<rss><channel><item><title>WAF Release - CVE-2026-8</title><link>https://developers.cloudflare.com/waf/change-log/z/</link></item></channel></rss>' } });
  const c = await hypeSweep(store, { run, fetchImpl: net, now });
  // today's story (1) + the older AI card + the untouched hand card
  assert.equal(c.coverage_checked, 3, JSON.stringify(c)); assert.equal(c.errors, 0);
  assert.ok((await store.getStory(card.story_ids[0])).raw_iocs.hype.card_coverage.lanes.length, 'hand card checked and stored on its manifest row');
  const re = await store.getCardDraft(old.id);
  assert.equal(re.draft.coverage.lanes.find((l) => l.id === 'cloudflare_waf').status, 'published');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ coverage changed for AI card older-2026')));
  // same day again: nothing is re-asked
  const c2 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.coverage_checked, 0, JSON.stringify(c2));
});

test('subscribers: a card\'s first publication is mailed once to confirmed addresses, its revision is not', async (t) => {
  t.after(off);
  const { out, store, run, kevFetch } = await published();
  await store.insertSubscriber({ email: 'subscriber@example.test', token: 'b'.repeat(48), status: 'confirmed', requested_at: '2026-10-16T10:00:00Z' });
  await store.insertSubscriber({ email: 'pending@example.test', token: 'c'.repeat(48), status: 'pending', requested_at: '2026-10-16T10:00:00Z' });
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(c1.published, 1, JSON.stringify(c1));
  const mails = out.emails.filter((m) => m.to === 'subscriber@example.test');
  assert.equal(mails.length, 1); assert.match(mails[0].subject, /new verdict card/); assert.match(mails[0].html, /\/cards\//);
  assert.equal(mails[0].headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click');
  assert.ok(!out.emails.some((m) => m.to === 'pending@example.test'), 'an unconfirmed address gets nothing');
  assert.equal(c1.subscribers_notified, 1);
  // the evidence moves: the card is revised, subscribers are not mailed again
  store._tables.evidence.push({ id: 'e9', story_id: uuid(1), kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 4 * 3600_000 });
  assert.equal(c2.revised, 1, JSON.stringify(c2));
  assert.equal(out.emails.filter((m) => m.to === 'subscriber@example.test').length, 1);
});

test('coverage: the hourly tick re-checks stale cards on its own, fetches KEV only when one is stale, and defers past its deadline', async (t) => {
  t.after(off);
  const { store, out } = await published();
  const now = Date.parse('2026-10-28T13:00:00Z');
  const old = await store.insertCardDraft({ story_id: uuid(8), thread_ids: [uuid(8)], title: 'Older published card', score: 10, reasons: [], draft: { ...DRAFT, cves: ['CVE-2026-8'], coverage: { checked_at: '2026-10-27T12:00:00Z', lanes: [{ id: 'cloudflare_waf', name: 'Cloudflare WAF managed-ruleset changelog', status: 'nothing found', detail: '' }] } }, version: 1, status: 'promoted', promoted_slug: 'older-2026', surfaced_at: '2026-10-27T12:00:00Z' });
  const net = routed({ kev: [{ cveID: 'CVE-2026-8', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': '<rss><channel><item><title>WAF Release - CVE-2026-8</title><link>https://developers.cloudflare.com/waf/change-log/z/</link></item></channel></rss>' } });
  // a deadline already past: every stale card is deferred, nothing is fetched (not even KEV)
  const d0 = await coverageOnlySweep(store, { fetchImpl: net, now, deadline: 0 });
  assert.equal(d0.coverage_checked, 0); assert.ok(d0.coverage_deferred >= 1, JSON.stringify(d0));
  assert.equal(net.calls.length, 0, 'nothing fetched when every card is deferred');
  // the real hourly call: the published draft and the hand cards with no check yet are all re-checked
  const c = await coverageOnlySweep(store, { fetchImpl: net, now });
  assert.ok(c.coverage_checked >= 1, JSON.stringify(c)); assert.equal(c.errors, 0);
  assert.equal(net.calls.filter((u) => u.includes('cisa.gov/sites/default/files/feeds')).length, 1, 'KEV fetched once for the whole sweep');
  const re = await store.getCardDraft(old.id);
  assert.equal(re.draft.coverage.lanes.find((l) => l.id === 'cloudflare_waf').status, 'published');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ coverage changed for AI card older-2026')));
  // an hour later nothing is stale: no check, no KEV fetch
  const before = net.calls.length;
  const c2 = await coverageOnlySweep(store, { fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.coverage_checked, 0, JSON.stringify(c2));
  assert.equal(net.calls.length, before, 'a quiet hour fetches nothing');
});

test('coverage: stale cards are checked stalest first, whatever order they are listed in', async (t) => {
  t.after(off);
  const { store } = await published();
  const now = Date.parse('2026-10-28T13:00:00Z');
  const mk = (n, checked_at) => store.insertCardDraft({ story_id: uuid(n), thread_ids: [uuid(n)], title: `Card ${n}`, score: 10, reasons: [], draft: { ...DRAFT, cves: [`CVE-2026-${n}`], ...(checked_at ? { coverage: { checked_at, lanes: [], exposure: null } } : {}) }, version: 1, status: 'promoted', promoted_slug: `card-${n}-2026`, surfaced_at: '2026-10-20T12:00:00Z' });
  const recent = await mk(31, '2026-10-27T12:00:00Z');
  const never = await mk(32, null);
  const oldest = await mk(33, '2026-10-22T12:00:00Z');
  const fresh = await mk(34, '2026-10-28T12:00:00Z');
  const order = [];
  const update = store.updateCardDraft.bind(store);
  store.updateCardDraft = async (id, patch) => { if (patch.draft?.coverage) order.push(id); return update(id, patch); };
  const c = await coverageOnlySweep(store, { fetchImpl: routed({}), now });
  assert.equal(c.errors, 0, JSON.stringify(c));
  assert.deepEqual(order.filter((id) => [recent.id, never.id, oldest.id, fresh.id].includes(id)), [never.id, oldest.id, recent.id], 'never checked, then the oldest check; a fresh one is left alone');
});

// Revisions for new facts only (2026-11-01: one AI card was re-drafted 27 times overnight, the
// hourly tick sweeping two briefs that each carried a copy of its story with different counts).
const DAY = 86_400_000;
const briefRun = async (store, day) => {
  const b = await store.insertBrief({ message_id: `m-${day}`, brief_date: day, subject: 'brief', received_at: `${day}T11:00:00Z` });
  return store.insertRun({ brief_id: b.id, stage: 'sent' });
};

test('cardFacts: stable keys over the whole thread; a rephrased fix version or a re-extracted guidance item or sample is the same fact', async () => {
  const store = memoryStore(); const t = store._tables;
  const a = story(1, { cves: ['CVE-2026-1', 'CVE-2026-2'], raw_iocs: { exposure: { fixed_in: 'Appliance 7.0.3 and later' } } });
  const b = story(2, { cves: ['CVE-2026-1'], raw_iocs: { exposure: { fixed_in: '7.0.3' } }, updates_story_id: a.id });
  t.stories.push(a, b);
  t.behaviors.push({ id: 'b1', story_id: a.id, attack_technique: 'T1190', pattern_kind: 'other', vendor_stated: true },
    { id: 'b2', story_id: b.id, attack_technique: 'T1190', pattern_kind: 'other', vendor_stated: true },
    { id: 'b3', story_id: b.id, attack_technique: 'T1059', pattern_kind: 'other', vendor_stated: false });
  t.evidence.push({ id: 'e1', story_id: a.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://v.example.test/g#rule' },
    { id: 'e2', story_id: b.id, kind: 'guidance', raw: 'Hunt for X, reworded', url: 'https://v.example.test/g/' },
    { id: 'e3', story_id: a.id, kind: 'command_line', raw: 'SH -c id' }, { id: 'e4', story_id: b.id, kind: 'command_line', raw: 'sh  -c  id' });
  t.iocs.push({ id: 'i1', type: 'domain', value_norm: 'c2.example-bad.net' });
  t.story_iocs.push({ story_id: a.id, ioc_id: 'i1', role: 'c2' }, { story_id: b.id, ioc_id: 'i1', role: 'c2' });
  const events = [
    { id: 'ev1', watch_story_id: b.id, level: 'HIGH', kind: 'new_source', assessment: { material: true } },
    { id: 'ev2', watch_story_id: b.id, level: 'HIGH', kind: 'new_source', assessment: { material: false } }, // HIGH, not material
    { id: 'ev3', watch_story_id: uuid(9), level: 'HIGH', kind: 'kev_added' },                                   // another story's
  ];
  const facts = await cardFacts(store, { ids: [a.id, b.id], kev: new Map([['CVE-2026-1', { dateAdded: '2026-10-15' }]]), events });
  assert.deepEqual(facts.filter((k) => !k.startsWith('sample:')), ['beh:T1190', 'event:ev1', 'fix:7.0.3', 'guide:https://v.example.test/g', 'ioc:domain:c2.example-bad.net', 'kev:CVE-2026-1']);
  assert.equal(facts.filter((k) => k.startsWith('sample:command_line:')).length, 1, 'one sample, whatever its spacing and case');
  assert.deepEqual(describeFacts(facts), ['1 new published detection guidance item', '1 new vendor-stated behavior', '1 new evidence sample', '1 new IoC',
    'CISA KEV listed CVE-2026-1', 'a fix version is now stated: 7.0.3', '1 material development on watch']);
});

/** Two briefs a day apart, each with its own copy of one campaign (both update the first day's row), each copy with evidence the other lacks. */
async function twoBriefs() {
  const out = captureOutputs(); const store = memoryStore(); const t = store._tables;
  const calls = installFakeLLM(() => DRAFT);
  const runA = await briefRun(store, '2026-10-15'); const runB = await briefRun(store, '2026-10-16');
  const base = { cves: ['CVE-2026-1'], threat_actor: 'UNC0000', created_at: new Date().toISOString(), raw_iocs: { exposure: { only_if: ['internet-exposed'] } },
    source_urls: ['https://www.cisa.gov/news-events/alerts/x', 'https://a.example.test/1', 'https://b.example.test/2'] };
  const root = story(1, { ...base, run_id: 'r0' });
  const a = story(2, { ...base, run_id: runA.id, updates_story_id: root.id });
  const b = story(3, { ...base, run_id: runB.id, updates_story_id: root.id });
  t.stories.push(root, a, b);
  t.iocs.push({ id: 'i1', type: 'domain', value_norm: 'c2.example-bad.net', first_seen_run_id: runA.id });
  t.story_iocs.push({ story_id: a.id, ioc_id: 'i1', role: 'c2' });
  t.evidence.push({ id: 'e1', story_id: b.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://v.example.test/g', publisher_tier: 'A' });
  return { out, store, calls, runA, runB, a, b, kevFetch: routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }] }) };
}

test('facts: an old card reached from two briefs is seeded from both copies at once, so neither brief re-drafts it', async () => {
  const { store, calls, runA, runB, kevFetch, a, b } = await twoBriefs();
  // what the overnight loop left: versions drafted from each copy, the head holding a count snapshot
  const snap = JSON.stringify({ days: 2, guidance: 1, behaviors: 0, samples: 0, iocs: 0, kev: ['CVE-2026-1'], fixed_in: null, material: 0 });
  const row = { title: DRAFT.title, score: 12, reasons: [], draft: { ...DRAFT, cves: ['CVE-2026-1'] }, promoted_slug: 'vendor-appliance-2026', surfaced_at: '2026-10-16T12:00:00Z', fingerprint: snap };
  const v1 = await store.insertCardDraft({ ...row, story_id: a.id, thread_ids: [uuid(1), a.id], version: 1, status: 'superseded' });
  const v2 = await store.insertCardDraft({ ...row, story_id: b.id, thread_ids: [uuid(1), b.id], version: 2, supersedes: v1.id, status: 'promoted' });
  const now = Date.parse('2026-10-16T13:00:00Z');
  for (let i = 0; i < 4; i++) await hypeSweep(store, { run: i % 2 ? runB : runA, fetchImpl: kevFetch, now: now + i * 3600_000 });
  assert.equal(calls.length, 0, `${calls.length} drafts written`);
  assert.deepEqual(JSON.parse((await store.getCardDraft(v2.id)).fingerprint), { v: 2, facts: ['guide:https://v.example.test/g', 'ioc:domain:c2.example-bad.net', 'kev:CVE-2026-1'] });
});

test('facts: a card reached from two briefs is revised once for what the second copy adds, never back and forth', async () => {
  const { store, calls, runA, runB, kevFetch } = await twoBriefs();
  const now = Date.parse('2026-10-16T13:00:00Z');
  // the hourly tick sweeps both briefs, three hours running
  for (let i = 0; i < 6; i++) await hypeSweep(store, { run: i % 2 ? runB : runA, fetchImpl: kevFetch, now: now + i * 3600_000 });
  assert.equal(calls.length, 2, `${calls.length} drafts written`);
  const all = (await store.listCardDrafts()).sort((x, y) => x.version - y.version);
  assert.deepEqual(all.map((r) => [r.version, r.status]), [[1, 'superseded'], [2, 'draft']]);
  assert.match(calls[1].messages[0].content, /<changes>1 new published detection guidance item<\/changes>/, 'the one fact only the second copy carries');
  assert.match(calls[1].messages[0].content, /<published_guidance>[\s\S]*Hunt for X/, 'drafted from the copy that carries it');
  assert.deepEqual(JSON.parse(all[1].fingerprint), { v: 2, facts: ['guide:https://v.example.test/g', 'ioc:domain:c2.example-bad.net', 'kev:CVE-2026-1'] });
});

test('facts: another day of the story, one more outlet and a development aging out of the window revise nothing; a material development does', async () => {
  const { store, run, kevFetch, calls, hot } = await world();
  hot.created_at = new Date().toISOString(); // a prior row for the next brief (listPriorStories reads the real clock)
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(calls.length, 1);
  store._tables.watches.push({ id: 'w1', story_id: hot.id, title: hot.title, status: 'active' });
  store._tables.watch_events.push({ id: 'ev1', watch_id: 'w1', created_at: '2026-10-16T14:00:00Z', kind: 'new_source', level: 'HIGH', summary: 'Exploitation confirmed.', assessment: { material: true, summary: 'Exploitation confirmed.' } });
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 2 * 3600_000 });
  assert.equal(c2.revised, 1); assert.equal(calls.length, 2);
  assert.match(calls[1].messages[0].content, /<changes>1 material development on watch<\/changes>/);
  // three days on, the development is out of the 48 h window: nothing was learned, nothing is written
  const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3 * DAY });
  assert.equal(c3.revised, 0, JSON.stringify(c3)); assert.equal(calls.length, 2);
  // the next brief carries the story again, from one more outlet, with nothing new to act on
  const run2 = await briefRun(store, '2026-10-19');
  store._tables.stories.push(story(3, { run_id: run2.id, updates_story_id: hot.id, cves: ['CVE-2026-1'], threat_actor: 'UNC0000', source_urls: [...hot.source_urls, 'https://c.example.test/3'] }));
  const c4 = await hypeSweep(store, { run: run2, fetchImpl: kevFetch, now: now + 3 * DAY + 3600_000 });
  assert.equal(c4.revised + c4.drafted, 0, JSON.stringify(c4)); assert.equal(calls.length, 2);
});

test('facts: a card stored before facts were kept is seeded on its next sweep with no model call, then revised only for a new fact', async () => {
  const { store, run, kevFetch, calls, hot } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  // the version the old loop stored: a count snapshot that differs from today's evidence
  const old = await store.insertCardDraft({ story_id: hot.id, thread_ids: [hot.id], title: DRAFT.title, score: 10, reasons: [], draft: { ...DRAFT, cves: ['CVE-2026-1'] },
    version: 1, status: 'draft', surfaced_at: '2026-10-16T12:00:00Z', fingerprint: JSON.stringify({ days: 1, guidance: 0, behaviors: 0, samples: 0, iocs: 0, kev: [], fixed_in: null, material: 0 }) });
  // KEV unreadable: seeding waits (a listing missed now would read as a new fact on the next sweep)
  const c0 = await hypeSweep(store, { run, fetchImpl: async () => new Response('down', { status: 503 }), now: now - 3600_000 });
  assert.equal(c0.seeded, undefined); assert.equal(calls.length, 0);
  assert.equal(JSON.parse((await store.getCardDraft(old.id)).fingerprint).v, undefined, 'still the old snapshot');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(c1.seeded, 1); assert.equal(c1.revised, 0); assert.equal(calls.length, 0, 'the switch is not news');
  assert.deepEqual(JSON.parse((await store.getCardDraft(old.id)).fingerprint), { v: 2, facts: ['kev:CVE-2026-1'] });
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c2.seeded, undefined); assert.equal(calls.length, 0);
  store._tables.evidence.push({ id: 'e1', story_id: hot.id, kind: 'guidance', raw: 'Hunt for X', url: 'https://v.example.test/g', publisher_tier: 'A' });
  const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 2 * 3600_000 });
  assert.equal(c3.revised, 1); assert.equal(calls.length, 1);
  assert.match(calls[0].messages[0].content, /<changes>1 new published detection guidance item<\/changes>/);
});

test('facts: past CARD_REISSUES_PER_DAY revisions in a UTC day the new facts wait, Discord says so once, and the next day folds them in', async (t) => {
  t.after(() => { delete process.env.CARD_REISSUES_PER_DAY; });
  process.env.CARD_REISSUES_PER_DAY = '1';
  const { out, store, run, kevFetch, calls, hot } = await world();
  const t0 = Date.parse('2026-10-16T13:00:00Z');
  // the store dates a version by the real clock; date each one at its sweep's hour instead
  const stamp = (ms) => { for (const r of store._tables.card_drafts) if (!r.dated) Object.assign(r, { created_at: new Date(ms).toISOString(), dated: true }); };
  // vendor-stated behaviors: facts that revise at once (a guidance link alone would wait for the day's one fold-in, below)
  const beh = (id, tech) => store._tables.behaviors.push({ id, story_id: hot.id, attack_technique: tech, pattern_kind: 'other', vendor_stated: true });
  const notes = () => out.discord.filter((l) => l.includes('revisions today (UTC)'));
  await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 }); stamp(t0);
  beh('b1', 'T1190');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 3600_000 }); stamp(t0 + 3600_000);
  assert.equal(calls.length, 2, 'the day\'s one revision');
  beh('b2', 'T1059');
  const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 2 * 3600_000 });
  assert.equal(c3.revised, 0); assert.equal(c3.capped, 1); assert.equal(calls.length, 2);
  assert.equal(notes().length, 1); assert.match(notes()[0], /new facts wait for its first sweep after midnight: 1 new vendor-stated behavior/);
  await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 3 * 3600_000 });
  assert.equal(notes().length, 1, 'said once a day'); assert.equal(calls.length, 2);
  const c5 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-17T01:00:00Z') });
  assert.equal(c5.revised, 1); assert.equal(calls.length, 3);
  assert.match(calls[2].messages[0].content, /<changes>1 new vendor-stated behavior<\/changes>/);
});

test('revisions: a sample, IoC or guidance link alone folds in once a UTC day; a KEV listing, fix version, vendor-stated behavior or material development revises at once', async () => {
  const { store, run, kevFetch, calls, hot } = await world();
  const t0 = Date.parse('2026-10-16T13:00:00Z');
  const stamp = (ms) => { for (const r of store._tables.card_drafts) if (!r.dated) Object.assign(r, { created_at: new Date(ms).toISOString(), dated: true }); };
  const guide = (id) => store._tables.evidence.push({ id, story_id: hot.id, kind: 'guidance', raw: 'Hunt', url: `https://v.example.test/${id}`, publisher_tier: 'A' });
  await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 }); stamp(t0);
  assert.equal(calls.length, 1);
  // a guidance link an hour after the card was written: held for the day
  guide('e1');
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 3600_000 });
  assert.equal(c2.revised, 0); assert.equal(c2.held, 1, JSON.stringify(c2)); assert.equal(calls.length, 1);
  // a vendor-stated behavior: revised now, and the held guidance rides along
  store._tables.behaviors.push({ id: 'b1', story_id: hot.id, attack_technique: 'T1190', pattern_kind: 'other', vendor_stated: true });
  const c3 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 2 * 3600_000 }); stamp(t0 + 2 * 3600_000);
  assert.equal(c3.revised, 1, JSON.stringify(c3)); assert.equal(calls.length, 2);
  assert.match(calls[1].messages[0].content, /<changes>1 new published detection guidance item; 1 new vendor-stated behavior<\/changes>/);
  // another link the same day: held again; the first sweep of the next UTC day folds it in
  guide('e2');
  const c4 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: t0 + 3 * 3600_000 });
  assert.equal(c4.revised, 0); assert.equal(c4.held, 1); assert.equal(calls.length, 2);
  const c5 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-17T00:30:00Z') });
  assert.equal(c5.revised, 1, JSON.stringify(c5)); assert.equal(calls.length, 3);
  assert.match(calls[2].messages[0].content, /<changes>1 new published detection guidance item<\/changes>/);
  assert.equal(calls[2].effort, 'low');
});

test('a hand-written card reached through two briefs raises a development once, not once per copy', async () => {
  const out = captureOutputs(); const store = memoryStore();
  const calls = installFakeLLM(() => DRAFT);
  const card = CARDS[0];
  const runA = await briefRun(store, '2026-10-27'); const runB = await briefRun(store, '2026-10-28');
  // two of the card's manifest rows, each in its own brief
  store._tables.stories.push(story(1, { id: card.story_ids[0], run_id: runA.id, cves: ['CVE-2026-1'] }), story(2, { id: card.story_ids[1], run_id: runB.id, cves: ['CVE-2026-1'] }));
  const kevLate = async () => new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-24' }] }), { status: 200 });
  const now = Date.parse('2026-10-28T13:00:00Z');
  const cA = await hypeSweep(store, { run: runA, fetchImpl: kevLate, now });
  assert.equal(cA.stale, 1); assert.equal(calls.length, 1);
  const cB = await hypeSweep(store, { run: runB, fetchImpl: kevLate, now: now + 60_000 });
  assert.equal(cB.carded, 1); assert.equal(cB.stale, 0, 'raised already, through the other copy'); assert.equal(calls.length, 1);
  assert.equal(out.discord.filter((l) => l.startsWith(`Cutsign ▲ card ${card.slug}`)).length, 1);
});

// ---- the card loop through the Batches API (lib/jobs.js collects what the sweep submitted) ----------

const batched = async (t, { publish = true, carded = false } = {}) => {
  process.env.LLM_BATCH = '1'; if (publish) process.env.CARD_AUTOPUBLISH = '1'; _resetBatchMode();
  t.after(() => { process.env.LLM_BATCH = '0'; off(); _resetBatchMode(); });
  return world({ carded });
};

test('batched: a draft is submitted once and finished by the collector — published with its coverage check and mail at half the cost; a later fact is a low-effort revision in place', async (t) => {
  const { out, store, run, calls, hot } = await batched(t);
  const net = routed({ kev: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }], routes: { 'developers.cloudflare.com': CF_FEED(true) } });
  const fake = installFakeBatch(() => DRAFT); fake.ready = false;
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: net, now });
  assert.equal(c1.submitted, 1, JSON.stringify(c1)); assert.equal(c1.drafted + c1.published, 0); assert.equal(calls.length, 0, 'no live call');
  assert.equal((await store.listCardDrafts()).length, 0, 'nothing written until the answer lands');
  assert.equal(fake.submitted.length, 1); assert.equal(fake.submitted[0].params.output_config.effort, 'medium'); assert.ok(!('fallbacks' in fake.submitted[0].params));
  assert.deepEqual(store._tables.llm_jobs.map((j) => [j.kind, j.status]), [['card_draft', 'pending']]);
  // an hour on, unanswered: the sweep leaves the thread alone and the collector waits
  const c2 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3600_000 });
  assert.equal(c2.submitted, 0); assert.equal(c2.in_flight, 1, JSON.stringify(c2)); assert.equal(fake.submitted.length, 1);
  const j1 = await collectJobs(store, { fetchImpl: net, now: now + 3600_000 });
  assert.equal(j1.pending, 1); assert.equal(j1.landed, 0);
  // answered: published with its coverage check, Discord and both mails; the story's hype state points at it
  fake.ready = true;
  const j2 = await collectJobs(store, { fetchImpl: net, now: now + 2 * 3600_000 });
  assert.equal(j2.landed, 1, JSON.stringify(j2)); assert.equal(j2.live, 0);
  const [row] = await store.listCardDrafts();
  assert.equal(row.status, 'promoted'); assert.equal(row.promoted_slug, 'vendor-appliance-zero-day-exploited-2026'); assert.equal(row.version, 1);
  assert.equal(row.draft.coverage.lanes.find((l) => l.id === 'cloudflare_waf').status, 'published');
  assert.equal(row.cost_usd, 0.0035, "half of Sonnet's live $0.007");
  assert.deepEqual(JSON.parse(row.fingerprint).facts, ['kev:CVE-2026-1']);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI verdict card published') && l.includes('coverage:')), out.discord.join('\n'));
  assert.equal(out.emails.filter((m) => /AI verdict card published/.test(m.subject)).length, 1);
  assert.equal((await store.getStory(hot.id)).raw_iocs.hype.draft_id, row.id);
  assert.equal(store._tables.llm_jobs[0].status, 'done'); assert.equal(store._tables.llm_jobs[0].cost_usd, 0.0035); assert.equal(calls.length, 0);
  // nothing new: nothing submitted. A vendor-stated behavior: a revision submitted at low effort, landing as v2 in place
  const c3 = await hypeSweep(store, { run, fetchImpl: net, now: now + 3 * 3600_000 });
  assert.equal(c3.submitted + c3.revised + c3.drafted, 0, JSON.stringify(c3));
  store._tables.behaviors.push({ id: 'b1', story_id: hot.id, attack_technique: 'T1190', pattern_kind: 'other', vendor_stated: true });
  const c4 = await hypeSweep(store, { run, fetchImpl: net, now: now + 4 * 3600_000 });
  assert.equal(c4.submitted, 1, JSON.stringify(c4)); assert.equal(fake.submitted[1].params.output_config.effort, 'low');
  assert.match(fake.submitted[1].params.messages[0].content, /<prior_draft version="1">/);
  assert.match(fake.submitted[1].params.messages[0].content, /<changes>1 new vendor-stated behavior<\/changes>/);
  const j3 = await collectJobs(store, { fetchImpl: net, now: now + 5 * 3600_000 });
  assert.equal(j3.landed, 1, JSON.stringify(j3));
  const all = (await store.listCardDrafts()).sort((a, b) => a.version - b.version);
  assert.deepEqual(all.map((x) => [x.version, x.status, x.promoted_slug]), [[1, 'superseded', row.promoted_slug], [2, 'promoted', row.promoted_slug]]);
  assert.deepEqual(JSON.parse(all[1].fingerprint).facts, ['beh:T1190', 'kev:CVE-2026-1']);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI verdict card re-issued (v2)') && l.includes('Changed: 1 new vendor-stated behavior')), out.discord.join('\n'));
  assert.equal(out.emails.filter((m) => /re-issued/.test(m.subject)).length, 0, 'a re-issue is Discord only, batched or not');
});

test('batched: a draft waits while the story\'s hunt proposals are in the batch, and is submitted the sweep after they land', async (t) => {
  const { store, run, kevFetch, calls, hot } = await batched(t);
  const fake = installFakeBatch(() => DRAFT);
  hot.raw_iocs = { ...hot.raw_iocs, proposals: { at: '2026-10-16T12:00:00Z', pending: 'job-1', batched: true } };
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(c1.awaiting_hunts, 1, JSON.stringify(c1)); assert.equal(c1.submitted, 0); assert.equal(fake.submitted.length, 0); assert.equal(calls.length, 0);
  hot.raw_iocs.proposals = { at: '2026-10-16T12:00:00Z', finished_at: '2026-10-16T13:30:00Z', batched: true };
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c2.submitted, 1, JSON.stringify(c2)); assert.equal(c2.awaiting_hunts, 0); assert.equal(calls.length, 0);
});

test('batched: an answer the API could not give is finished by one live call; an answer whose head changed meanwhile is abandoned; a batch unanswered for six hours is cancelled and made live; without the jobs table the loop runs live', async (t) => {
  const { store, run, kevFetch, calls, hot } = await batched(t);
  const fake = installFakeBatch(() => DRAFT);
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(fake.submitted.length, 1);
  fake.fail = 'invalid_request: The compiled grammar is too large';
  const j = await collectJobs(store, { fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(j.landed, 1, JSON.stringify(j)); assert.equal(j.live, 1); assert.equal(calls.length, 1, 'one live call');
  assert.match(store._tables.llm_jobs[0].outcome, /^live: invalid_request/);
  const [row] = await store.listCardDrafts();
  assert.equal(row.status, 'promoted'); assert.equal(row.cost_usd, 0.014, 'the live call at the list price');
  // a revision submitted, then the head dismissed before it lands: abandoned, nothing written, no call
  fake.fail = null;
  store._tables.behaviors.push({ id: 'b1', story_id: hot.id, attack_technique: 'T1190', pattern_kind: 'other', vendor_stated: true });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 2 * 3600_000 });
  assert.equal(c.submitted, 1, JSON.stringify(c));
  await store.updateCardDraft(row.id, { status: 'dismissed' });
  const j2 = await collectJobs(store, { fetchImpl: kevFetch, now: now + 3 * 3600_000 });
  assert.equal(j2.abandoned, 1, JSON.stringify(j2)); assert.equal((await store.listCardDrafts()).length, 1); assert.equal(calls.length, 1);
  assert.equal(store._tables.llm_jobs[1].status, 'abandoned');
  // six hours and no answer: cancelled and finished live
  const w = await world();
  const fake2 = installFakeBatch(() => DRAFT); fake2.ready = false;
  await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now });
  const j3 = await collectJobs(w.store, { fetchImpl: w.kevFetch, now: Date.now() + 7 * 3600_000 });
  assert.equal(j3.live, 1, JSON.stringify(j3)); assert.deepEqual(fake2.cancelled, ['msgbatch_1']); assert.equal(w.calls.length, 1);
  assert.match(w.store._tables.llm_jobs[0].outcome, /not answered in 6 h/);
  assert.equal((await w.store.listCardDrafts())[0].status, 'promoted');
  // the table missing: the loop drafts live, as before
  const v = await world(); _resetBatchMode();
  v.store.listJobs = async () => { throw new Error('relation "llm_jobs" does not exist'); };
  const cv = await hypeSweep(v.store, { run: v.run, fetchImpl: v.kevFetch, now });
  assert.equal(cv.drafted, 1, JSON.stringify(cv)); assert.equal(cv.submitted, 0); assert.equal(v.calls.length, 1);
});

test('batched: a failed card draft gets its live call inside the tick\'s own deadline; one that failed two days ago is closed without a call; a retrieve that throws cancels nothing', async (t) => {
  const { readFileSync } = await import('node:fs');
  const { store, run, kevFetch, calls } = await batched(t);
  const fake = installFakeBatch(() => DRAFT);
  const now = Date.parse('2026-10-16T13:00:00Z');
  await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  fake.fail = 'invalid_request: The compiled grammar is too large';
  // without the room a live card draft needs (150 s) the job waits for a later tick
  const j0 = await collectJobs(store, { fetchImpl: kevFetch, now: now + 3600_000, deadline: Date.now() + 149_000 });
  assert.equal(j0.pending, 1, JSON.stringify(j0)); assert.equal(calls.length, 0);
  // the deadline the tick passes (api/watch.js) has that room: it once equalled it, and the call never started
  const m = readFileSync(new URL('../api/watch.js', import.meta.url), 'utf8').match(/collectJobs\(store, \{ deadline: started \+ ([\d_]+) \}\)/);
  assert.ok(m, 'the tick passes collectJobs a deadline');
  const j = await collectJobs(store, { fetchImpl: kevFetch, now: now + 3600_000, deadline: Date.now() + Number(m[1].replace(/_/g, '')) });
  assert.equal(j.live, 1, JSON.stringify(j)); assert.equal(calls.length, 1);
  assert.equal((await store.listCardDrafts())[0].status, 'promoted');
  // a batch that failed two days ago: closed, no model call, nothing published
  const w = await world();
  const fake2 = installFakeBatch(() => DRAFT);
  await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now });
  fake2.fail = 'api_error: Overloaded';
  const j2 = await collectJobs(w.store, { fetchImpl: w.kevFetch, now: Date.now() + 49 * 3600_000 });
  assert.equal(j2.failed, 1, JSON.stringify(j2)); assert.equal(j2.live, 0); assert.equal(w.calls.length, 0, 'no live call at list price');
  assert.equal(w.store._tables.llm_jobs[0].status, 'failed'); assert.match(w.store._tables.llm_jobs[0].outcome, /too old for a live rerun/);
  assert.equal((await w.store.listCardDrafts()).length, 0);
  assert.equal((await collectJobs(w.store, { fetchImpl: w.kevFetch, now: Date.now() + 50 * 3600_000 })).checked, 0, 'and it is not asked about again');
  // the batch API unreachable for a tick, seven hours in: nothing is cancelled or rerun; the answer is collected when it answers
  const v = await world();
  const fake3 = installFakeBatch(() => DRAFT);
  await hypeSweep(v.store, { run: v.run, fetchImpl: v.kevFetch, now });
  fake3.down = true;
  const j3 = await collectJobs(v.store, { fetchImpl: v.kevFetch, now: Date.now() + 7 * 3600_000 });
  assert.equal(j3.pending, 1, JSON.stringify(j3)); assert.deepEqual(fake3.cancelled, []); assert.equal(v.calls.length, 0);
  fake3.down = false;
  const j4 = await collectJobs(v.store, { fetchImpl: v.kevFetch, now: Date.now() + 8 * 3600_000 });
  assert.equal(j4.landed, 1, JSON.stringify(j4)); assert.equal(j4.live, 0); assert.equal(v.calls.length, 0, 'collected at the batch price');
  // unreachable for more than two days: the batch is taken for gone and the job closed, so the story's card is not held back for ever
  const u = await world();
  const fake4 = installFakeBatch(() => DRAFT);
  await hypeSweep(u.store, { run: u.run, fetchImpl: u.kevFetch, now });
  fake4.down = true;
  const j5 = await collectJobs(u.store, { fetchImpl: u.kevFetch, now: Date.now() + 49 * 3600_000 });
  assert.equal(j5.failed, 1, JSON.stringify(j5)); assert.equal(j5.pending, 0); assert.equal(u.calls.length, 0);
  assert.match(u.store._tables.llm_jobs[0].outcome, /could not be read: fetch failed.*too old for a live rerun/);
});

test('batched: a failed day-one draft of a P1 outside the brief\'s day-one cards is dropped, not rerun at list price; the others get their live call', async (t) => {
  const w = await batched(t); moreP1s(w);
  t.after(() => { delete process.env.CARD_P1_PER_DAY; });
  const fake = installFakeBatch(() => DRAFT);
  const now = Date.parse('2026-10-16T13:00:00Z');
  // five drafts submitted while every P1 had a day-one card (as before the cap)
  process.env.CARD_P1_PER_DAY = '9';
  const c = await hypeSweep(w.store, { run: w.run, fetchImpl: w.kevFetch, now });
  assert.equal(c.submitted, 5, JSON.stringify(c));
  delete process.env.CARD_P1_PER_DAY;
  fake.fail = 'api_error: usage limit reached';
  const j = await collectJobs(w.store, { fetchImpl: w.kevFetch, now: now + 3600_000 });
  assert.equal(j.live, 3, JSON.stringify(j)); assert.equal(j.abandoned, 2); assert.equal(w.calls.length, 3, 'three live calls, not five');
  const dropped = w.store._tables.llm_jobs.filter((x) => x.status === 'abandoned');
  assert.deepEqual(dropped.map((x) => x.story_id).sort(), [uuid(5), uuid(6)]);
  for (const x of dropped) assert.match(x.outcome, /usage limit reached.*no live rerun/);
  assert.equal((await w.store.listCardDrafts()).length, 3);
  // an answer that did arrive for a P1 outside the cap is paid for: it is used
  const v = await batched(t); moreP1s(v);
  installFakeBatch(() => DRAFT);
  process.env.CARD_P1_PER_DAY = '9';
  await hypeSweep(v.store, { run: v.run, fetchImpl: v.kevFetch, now });
  delete process.env.CARD_P1_PER_DAY;
  const j2 = await collectJobs(v.store, { fetchImpl: v.kevFetch, now: now + 3600_000 });
  assert.equal(j2.landed, 5, JSON.stringify(j2)); assert.equal(j2.abandoned, 0); assert.equal(v.calls.length, 0);
});

test('batched: a hand-written card\'s re-issue draft goes through the batch too and lands as the surfaced draft its page links', async (t) => {
  const { out, store, run, calls, hot } = await batched(t, { publish: false, carded: true });
  const card = CARDS[0];
  const fake = installFakeBatch(() => DRAFT);
  const kevLate = async () => new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-24', dueDate: '2026-10-27' }] }), { status: 200 });
  const now = Date.parse('2026-10-28T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevLate, now });
  assert.equal(c1.stale, 1); assert.equal(c1.submitted, 1, JSON.stringify(c1)); assert.equal(c1.drafted, 0); assert.equal(calls.length, 0);
  assert.equal(store._tables.llm_jobs[0].payload.card_slug, card.slug);
  // the development is raised once; the next sweep sees the answer in flight and submits nothing
  const c2 = await hypeSweep(store, { run, fetchImpl: kevLate, now: now + 60_000 });
  assert.equal(c2.stale, 0); assert.equal(c2.submitted, 0); assert.equal(fake.submitted.length, 1);
  const j = await collectJobs(store, { fetchImpl: kevLate, now: now + 3600_000 });
  assert.equal(j.landed, 1, JSON.stringify(j));
  const [d] = await store.listCardDrafts();
  assert.ok(d.surfaced_at); assert.deepEqual(JSON.parse(d.fingerprint), { card: card.slug, devs: ['kev:CVE-2026-1'] });
  assert.deepEqual(d.draft.changes_since_prior, ['CISA KEV listed CVE-2026-1 on 2026-10-24 (federal due 2026-10-27)']);
  assert.ok(out.discord.some((l) => l.includes(`AI re-issue draft for card ${card.slug}`)), out.discord.join('\n'));
  assert.equal(out.emails.filter((m) => /AI draft ready to publish/.test(m.subject)).length, 1);
  assert.equal((await store.getStory(hot.id)).raw_iocs.hype.draft_id, d.id);
});

test('batched: a submission the API refuses is drafted live instead, and said once on Discord', async (t) => {
  const { out, store, run, kevFetch, calls } = await batched(t);
  installFakeBatch(() => DRAFT);
  const { _setBatchAPI } = await import('../lib/llm.js');
  _setBatchAPI({ async create() { throw new Error('400 output_config.format: unsupported'); } });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.submitted, 0); assert.equal(c.batch_errors, 1); assert.equal(c.published, 1, JSON.stringify(c)); assert.equal(calls.length, 1, 'drafted live');
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ⚠ batch submission failed, drafting live')), out.discord.join('\n'));
  assert.equal(store._tables.llm_jobs.length, 0);
});

// ---- 2026-11-14: the watch tick's card loop has a deadline; quiet AI cards archive themselves ----

test('sweep: on a short reserve (the watch tick) stories are scored with little time left, a live draft waits, and a sweep with room writes it', async () => {
  const { store, run, kevFetch, calls } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  // 100 s left: less than a live draft needs, plenty to score
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now, deadline: Date.now() + 100_000, reserveMs: 10_000 });
  assert.ok(!c1.yielded); assert.ok(c1.scored >= 1); assert.equal(c1.drafted, 0); assert.equal(c1.draft_deferred, 1, JSON.stringify(c1));
  assert.equal(calls.length, 0, 'no model call started');
  assert.equal(store._tables.card_drafts?.length || 0, 0);
  // less than the reserve left: it yields before a story, like any sweep
  const c0 = await hypeSweep(store, { run, fetchImpl: kevFetch, now, deadline: Date.now() + 5_000, reserveMs: 10_000 });
  assert.equal(c0.yielded, true); assert.equal(c0.scored, 0);
  // nothing was recorded as written, so the next sweep with room drafts it
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now, deadline: Date.now() + 10 * 60_000, reserveMs: 10_000 });
  assert.equal(c2.drafted, 1, JSON.stringify(c2)); assert.equal(c2.draft_deferred, undefined);
});

test('archive: an AI card quiet for 30 days with no open watch is archived in place, once, and leaves the daily checks; a watched, developing or young one stays', async (t) => {
  const prev = { a: process.env.CARD_ACTIONS, b: process.env.CARD_ARCHIVE };
  t.after(() => { for (const [k, v] of [['CARD_ACTIONS', prev.a], ['CARD_ARCHIVE', prev.b]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
  process.env.CARD_ACTIONS = '0'; // this test is about the archive step
  const out = captureOutputs();
  const store = memoryStore();
  const now = Date.parse('2026-12-20T15:00:00Z');
  const stale = { checked_at: '2026-12-18T12:00:00Z', lanes: [], exposure: null };
  const mk = (n, slug, created_at) => store.insertCardDraft({ created_at, story_id: uuid(n), thread_ids: [uuid(n)], title: `Card ${n}`, score: 10, reasons: [], version: 1, status: 'promoted', promoted_slug: slug, surfaced_at: created_at, draft: { ...DRAFT, cves: [], coverage: stale } });
  const quiet = await mk(31, 'quiet-2026', '2026-11-01T12:00:00Z');
  const watched = await mk(32, 'watched-2026', '2026-11-01T12:00:00Z');
  const moving = await mk(33, 'moving-2026', '2026-11-01T12:00:00Z');
  const young = await mk(34, 'young-2026', '2026-12-10T12:00:00Z');
  store._tables.watches.push(
    { id: 'w1', story_id: uuid(31), status: 'expired', last_change_at: '2026-11-03T00:00:00Z' },
    { id: 'w2', story_id: uuid(32), status: 'active', last_change_at: null },
    { id: 'w3', story_id: uuid(33), status: 'expired', last_change_at: '2026-12-05T00:00:00Z' });
  const net = routed();
  const get = async (r) => (await store.getCardDraft(r.id));
  // switched off: nothing is archived
  process.env.CARD_ARCHIVE = '0';
  const c0 = await coverageOnlySweep(store, { fetchImpl: net, now, deadline: 0 });
  assert.equal(c0.archived, undefined); assert.equal((await get(quiet)).draft.archived_on, undefined);
  delete process.env.CARD_ARCHIVE;
  const c = await coverageOnlySweep(store, { fetchImpl: net, now });
  assert.equal(c.archived, 1, JSON.stringify(c));
  const q = await get(quiet);
  assert.equal(q.draft.archived_on, '2026-12-20'); assert.equal(q.status, 'promoted'); assert.equal(q.promoted_slug, 'quiet-2026');
  assert.equal(q.draft.coverage.checked_at, stale.checked_at, 'an archived card is not re-checked');
  assert.equal(q.draft.verdict, DRAFT.verdict, 'the card itself is untouched');
  for (const r of [watched, moving, young]) {
    const row = await get(r);
    assert.equal(row.draft.archived_on, undefined, row.promoted_slug);
    assert.notEqual(row.draft.coverage.checked_at, stale.checked_at, `${row.promoted_slug} still gets its daily check`);
  }
  const said = out.discord.filter((l) => l.includes('archived'));
  assert.equal(said.length, 1, out.discord.join('\n'));
  assert.match(said[0], /1 AI card archived[^\n]*\n• quiet-2026 — card dated 2026-11-01, all watches expired, last development 2026-11-03/);
  // the next sweep says nothing more, and the site sees it archived at the same URL
  const again = await coverageOnlySweep(store, { fetchImpl: net, now: now + 3600_000 });
  assert.equal(again.archived, undefined); assert.equal(out.discord.filter((l) => l.includes('archived')).length, 1);
  assert.equal(aiCard(q).status, 'archived');
  const p = await publishedRows(store);
  assert.deepEqual([p.active.map((r) => r.promoted_slug).sort(), p.archived.map((r) => r.promoted_slug)], [['moving-2026', 'watched-2026', 'young-2026'], ['quiet-2026']]);
  assert.equal((await store.listCardDrafts({ status: 'promoted', slug: 'quiet-2026', limit: 1 }))[0].id, quiet.id);
});
