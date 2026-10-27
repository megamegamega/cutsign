// Hype score + sweep: which stories get nominated as card candidates, and which get a machine draft.
// Offline: memory store, fake LLM, captured mail and Discord, KEV served by a fake fetch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { hypeScore, threadOf, hypeSweep, fetchKev } from '../lib/hype.js';
import { scrub, DraftSchema, draftBody, buildDraftInput } from '../lib/carddraft.js';
import { CARDS } from '../lib/cards.js';
import { installFakeLLM, captureOutputs } from './helpers.js';

const DAY = 86_400_000;
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

test('threadOf stops at a cycle and at an unloaded row', () => {
  const a = story(1, { updates_story_id: uuid(2) }); const b = story(2, { updates_story_id: uuid(1) });
  assert.equal(threadOf(a, new Map([[b.id, b], [a.id, a]])).length, 2);
  assert.equal(threadOf(story(3, { updates_story_id: uuid(9) }), new Map()).length, 1);
});

test('fetchKev returns an empty map on failure', async () => {
  assert.equal((await fetchKev(async () => { throw new Error('down'); })).size, 0);
  assert.equal((await fetchKev(async () => new Response('{}', { status: 500 }))).size, 0);
});

test('scrub applies the repo hygiene rules to machine text', () => {
  const d = scrub({ title: 'x', verdict: 'v', hunts: [{ name: 'h', log_source: 'EDR', spl: 'index=prod_main sourcetype="xyz:abc" host=db1.corp.example.com | stats count', hit_means: 'm' }],
    what_happened: ['seen on fs01.internal.example.net'], containment: [], escalation_triggers: [], open_questions: [] });
  assert.equal(d.hunts[0].spl, 'index=* sourcetype=<xyz:abc> host=<host> | stats count');
  assert.equal(d.what_happened[0], 'seen on <host>');
});

const DRAFT = {
  title: 'Vendor appliance zero-day exploited; patch and hunt', verdict: 'Patch today; hunt for shells from the appliance process. [S1]', lane: 'Hunt / IR + patch',
  what_happened: ['Vendor confirmed exploitation. [S1]', 'CISA added the CVE to KEV. [S2]'],
  exposure: { affected: ['Appliance versions before 1.2'], only_if: ['management interface exposed'], not_affected_if: ['1.2 or later'], fixed_in: '1.2' },
  timeline: [{ date: '2026-10-15', event: 'Advisory published', source: 'S1' }],
  hunts: [{ name: 'Shell from appliance process', log_source: 'appliance syslog', spl: 'index=main parent=httpd child=sh | stats count', hit_means: 'post-exploitation' }],
  containment: ['Patch to 1.2', 'Rotate credentials'], coverage_lookups: [{ category: 'vulnerability scanner', check: 'look up the CVE in the vendor KB' }],
  escalation_triggers: ['Any hit on the hunt'], confidence: 'high', confidence_reason: 'Vendor primary source confirms exploitation.', open_questions: [],
  sources: [{ ref: 'S1', url: 'https://www.cisa.gov/news-events/alerts/x', publisher: 'CISA' }, { ref: 'S9', url: 'https://invented.example.test/', publisher: null }],
};

/** A run with one P1 deep-read story that scores over the draft bar, plus one quiet story. */
async function world({ carded = false } = {}) {
  const out = captureOutputs();
  const store = memoryStore();
  const t = store._tables;
  const brief = await store.insertBrief({ message_id: 'm1', brief_date: '2026-10-16', subject: 'brief', received_at: '2026-10-16T11:00:00Z' });
  const run = await store.insertRun({ brief_id: brief.id, stage: 'sent' });
  const hot = story(1, { run_id: run.id, cves: ['CVE-2026-1'], threat_actor: 'UNC0000', id: carded ? CARDS[0].story_ids[0] : uuid(1),
    source_urls: ['https://www.cisa.gov/news-events/alerts/x', 'https://a.example.test/1', 'https://b.example.test/2'], raw_iocs: { exposure: { only_if: ['internet-exposed'] } } });
  const quiet = story(2, { run_id: run.id, priority: 3, selected: false });
  t.stories.push(hot, quiet);
  const kevFetch = async () => new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }] }), { status: 200 });
  const calls = installFakeLLM(() => DRAFT);
  return { out, store, run, kevFetch, calls, hot };
}

test('sweep: nominates and drafts over the bars, emails and posts the draft, and does not repeat', async () => {
  const { out, store, run, kevFetch, calls, hot } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(c1.scored, 2); assert.equal(c1.nominated, 1); assert.equal(c1.drafted, 1); assert.equal(c1.errors, 0, JSON.stringify(c1));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▲ card candidate') && l.includes('KEV CVE-2026-1 +3')));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ card draft ready')));
  assert.equal(out.emails.length, 1); assert.match(out.emails[0].subject, /card candidate/);
  const drafts = await store.listCardDrafts();
  assert.equal(drafts.length, 1); assert.equal(drafts[0].status, 'draft'); assert.deepEqual(drafts[0].thread_ids, [hot.id]);
  assert.equal(drafts[0].draft.hunts[0].spl, 'index=* parent=httpd child=sh | stats count', 'scrubbed before storing');
  assert.ok(!drafts[0].draft.sources.some((s) => s.url.includes('invented')), 'invented sources dropped');
  assert.equal(calls.length, 1); assert.equal(calls[0].schemaName, 'card_draft');
  assert.match(calls[0].messages[0].content, /<story date="2026-10-16" today="true">/);
  assert.match(calls[0].messages[0].content, /\[S1\] https:\/\/www\.cisa\.gov/);
  const h = (await store.getStory(hot.id)).raw_iocs.hype;
  assert.equal(h.draft_id, drafts[0].id);
  // same day again (the hourly tick): nothing new to say, nothing new to draft
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c2.nominated, 0); assert.equal(c2.drafted, 0); assert.equal(calls.length, 1); assert.equal(out.emails.length, 1);
  const page = draftBody(drafts[0]);
  assert.match(page, /Machine draft, unreviewed/); assert.match(page, /index=\*/); assert.match(page, /href="https:\/\/www\.cisa\.gov/);
});

test('sweep: a thread that already has a hand-written card is skipped', async () => {
  const { out, store, run, kevFetch, calls } = await world({ carded: true });
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.carded, 1); assert.equal(c.nominated, 0); assert.equal(c.drafted, 0); assert.equal(calls.length, 0); assert.equal(out.emails.length, 0);
});

test('sweep: a draft that fails validation twice is reported, not stored, and the nomination still posts', async () => {
  const { out, store, run, kevFetch } = await world();
  installFakeLLM(() => ({ title: 'incomplete' }));
  const c = await hypeSweep(store, { run, fetchImpl: kevFetch, now: Date.parse('2026-10-16T13:00:00Z') });
  assert.equal(c.nominated, 1); assert.equal(c.drafted, 0); assert.equal(c.errors, 1);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ✖ card draft failed')));
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

test('draft input never includes anything but stored facts; schema rejects a coverage claim shape', () => {
  const s = story(1, { guidance: [{ url: 'https://vendor.example.test/g', raw: 'Hunt for X', publisher_tier: 'A' }] });
  const { text, sources } = buildDraftInput({ story: s, thread: [s], data: { date: '2026-10-16' }, score: 7, reasons: ['P1 +2'] });
  assert.equal(sources.length, 1); assert.match(text, /<published_guidance>/);
  assert.ok(!DraftSchema.safeParse({ ...DRAFT, coverage_lookups: [{ vendor: 'x', status: 'covered' }] }).success);
});
