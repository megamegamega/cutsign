// Hype score + the draft loop: which stories get nominated, when an AI draft is written, revised
// as evidence changes, and surfaced. Offline: memory store, fake LLM, captured mail and Discord,
// KEV served by a fake fetch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { hypeScore, threadOf, hypeSweep, fetchKev, evidenceFingerprint, describeChanges, actionable, cardDevelopments } from '../lib/hype.js';
import { scrub, DraftSchema, draftBody, buildDraftInput } from '../lib/carddraft.js';
import { CARDS, cardIndex } from '../lib/cards.js';
import { RECHECK_MS } from '../lib/coverage.js';
import { installFakeLLM, captureOutputs } from './helpers.js';

// The draft-loop tests below predate auto-publishing and read the loop with it off; the
// publishing tests at the end turn it on explicitly.
process.env.CARD_AUTOPUBLISH = '0';

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
  const draftCalls = installFakeLLM(() => ({ ...DRAFT, detect: [{ name: 'sp_token_then_mail_access', log_source: 'x', spl: 'index=* ignored', hit_means: 'a listed app read a mailbox it never touched before' }, { name: 'invented', log_source: 'y', spl: 'index=* parent=x', hit_means: 'z' }] }));
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
