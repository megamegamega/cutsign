// Hype score + the draft loop: which stories get nominated, when an AI draft is written, revised
// as evidence changes, and surfaced. Offline: memory store, fake LLM, captured mail and Discord,
// KEV served by a fake fetch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { hypeScore, threadOf, hypeSweep, fetchKev, evidenceFingerprint, describeChanges, actionable } from '../lib/hype.js';
import { scrub, DraftSchema, draftBody, buildDraftInput } from '../lib/carddraft.js';
import { CARDS } from '../lib/cards.js';
import { installFakeLLM, captureOutputs } from './helpers.js';

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
  const d = scrub({ title: 'x', verdict: 'v', detect: [{ name: 'h', log_source: 'EDR', spl, hit_means: 'm' }],
    what_happened: [dirty(['seen on fs01.', 'internal.example.net'])], scope: { affected: [dirty(['srv.', 'lan.example.org'])] } });
  assert.equal(d.detect[0].spl, 'index=* sourcetype=<xyz:abc> host=<host> | stats count');
  assert.equal(d.what_happened[0], 'seen on <host>');
  assert.equal(d.scope.affected[0], '<host>');
});

const DRAFT = {
  title: 'Vendor appliance zero-day exploited; patch and hunt', verdict: 'Patch today; hunt for shells from the appliance process. [S1]', lane: 'Hunt / IR + patch',
  confidence: 'high', confidence_reason: 'Vendor primary source confirms exploitation.',
  what_happened: ['Vendor confirmed exploitation. [S1]', 'CISA added the CVE to KEV. [S2]'],
  timeline: [{ date: '2026-10-15', event: 'Advisory published', source: 'S1' }],
  detect: [{ name: 'Shell from appliance process', log_source: 'appliance syslog', spl: ['index', '=main parent=httpd child=sh | stats count'].join(''), hit_means: 'post-exploitation' }],
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
  const kevFetch = async () => new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2026-1', dateAdded: '2026-10-15' }] }), { status: 200 });
  const calls = installFakeLLM(() => DRAFT);
  return { out, store, run, kevFetch, calls, hot };
}

test('sweep: nominates, writes an AI draft when actionable, emails and posts it, and does not repeat on unchanged evidence', async () => {
  const { out, store, run, kevFetch, calls, hot } = await world();
  const now = Date.parse('2026-10-16T13:00:00Z');
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  // P1 2, deep 1, KEV 3, 3 publishers 1, primary 1, exposure 1, actor 1 = 10 → nominated and surfaced
  assert.equal(c1.scored, 2); assert.equal(c1.nominated, 1); assert.equal(c1.drafted, 1); assert.equal(c1.surfaced, 1); assert.equal(c1.errors, 0, JSON.stringify(c1));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▲ card candidate') && l.includes('KEV CVE-2026-1 +3')));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ AI draft ready for review')));
  assert.equal(out.emails.length, 1); assert.match(out.emails[0].subject, /AI draft ready for review/);
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
  assert.match(calls[1].messages[0].content, /<prior_draft version="1">/);
  assert.match(calls[1].messages[0].content, /<changes>1 new published detection guidance item<\/changes>/);
  const all = (await store.listCardDrafts()).sort((a, b) => a.version - b.version);
  assert.equal(all.length, 2); assert.equal(all[0].status, 'superseded'); assert.equal(all[1].status, 'draft'); assert.equal(all[1].version, 2); assert.equal(all[1].supersedes, all[0].id);
  assert.deepEqual(all[1].draft.changes_since_prior, ['something the model claims changed']);
  assert.ok(out.discord.some((l) => l.includes('AI draft') && l.includes('Changed: 1 new published detection guidance item')));
  assert.equal(row.raw_iocs.hype.draft_id, all[1].id);
  assert.match(draftBody(all[1]), /Changed since version 1/);
});

test('sweep: a nominated story with nothing actionable waits, and is drafted once something lands', async () => {
  const { store, run, kevFetch, calls } = await world({ actionableStory: false });
  const now = Date.parse('2026-10-16T13:00:00Z');
  // P1 2, deep 1, 3 publishers 1, primary 1, exposure 1, actor 1 = 7 → nominated, not actionable
  const c1 = await hypeSweep(store, { run, fetchImpl: kevFetch, now });
  assert.equal(c1.nominated, 1); assert.equal(c1.drafted, 0); assert.equal(c1.waiting, 1); assert.equal(calls.length, 0);
  store._tables.evidence.push({ id: 'e1', story_id: uuid(1), kind: 'guidance', raw: 'Hunt for X', url: 'https://www.cisa.gov/news-events/alerts/x', publisher_tier: 'A' });
  const c2 = await hypeSweep(store, { run, fetchImpl: kevFetch, now: now + 3600_000 });
  assert.equal(c2.drafted, 1); assert.equal(c2.nominated, 0, 'score unchanged, no second nomination'); assert.equal(calls.length, 1);
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

test('draft input carries only stored facts; the schema has no slot for a coverage claim', () => {
  const s = story(1, { guidance: [{ url: 'https://vendor.example.test/g', raw: 'Hunt for X', publisher_tier: 'A' }] });
  const { text, sources } = buildDraftInput({ story: s, thread: [s], data: { date: '2026-10-16' }, score: 7, reasons: ['P1 +2'] });
  assert.equal(sources.length, 1); assert.match(text, /<published_guidance>/);
  assert.ok(!DraftSchema.safeParse({ ...DRAFT, coverage_checks: [{ vendor: 'x', status: 'covered' }] }).success);
});
