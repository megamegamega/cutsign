// Indicator facts (lib/enrich.js): who owns an address, when a domain was registered, whether it is
// one of the most visited. The lookups against a fake network, the rules that read them, the sweep
// that stores them, and the committed files.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { memoryStore } from '../lib/store-memory.js';
import { registrable, enrichKey, topRank, netClass, factsFor, enrichDue, lookup, wantedKeys, TOP_N, HAND_FACTS } from '../lib/enrich.js';
import { targetPolicy, policyFor, expandActions, actionsReport, indicatorsReport, indicatorsTsv, actionsTsv, sharedPlatform, INDICATOR_COLUMNS, TSV_COLUMNS } from '../lib/actions.js';
import { HAND_ACTIONS } from '../lib/handactions.js';
import { enrichOnlySweep } from '../lib/hype.js';

const NOW = Date.parse('2026-11-14T12:00:00Z'); const AT = new Date(NOW).toISOString();
const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const dns = (...data) => json({ Status: 0, Answer: data.map((d) => ({ type: 16, data: `"${d}"` })) });
/** A network that answers the three sources from tables, and records what it was asked. */
function net({ origin = {}, names = {}, kinds = {}, rdap = {}, peeringdb = null } = {}) {
  const asked = [];
  const fetchImpl = async (url) => {
    asked.push(url);
    const u = new URL(url);
    if (u.hostname === 'cloudflare-dns.com') {
      const name = u.searchParams.get('name');
      if (name.endsWith('.asn.cymru.com') && name.startsWith('AS')) return dns(names[name.slice(2, name.indexOf('.'))] || '');
      return name in origin ? dns(origin[name]) : json({ Status: 3 });
    }
    if (u.hostname === 'www.peeringdb.com') {
      if (peeringdb) return json({}, peeringdb);
      const k = kinds[u.searchParams.get('asn')];
      return json({ data: k === undefined ? [] : [{ info_type: k }] });
    }
    if (u.hostname === 'rdap.org') {
      const d = decodeURIComponent(u.pathname.split('/').pop());
      if (rdap[d] === undefined) return json({}, 404);
      if (typeof rdap[d] === 'number') return json({}, rdap[d]);
      return json({ events: [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: rdap[d] }] });
    }
    throw new Error(`unexpected request: ${url}`);
  };
  return { fetchImpl, asked };
}
const WORLD = {
  origin: { '7.113.0.203.origin.asn.cymru.com': '16509 | 203.0.113.0/24 | US | arin | 2011-01-01', '9.100.51.198.origin.asn.cymru.com': '64500 | 198.51.100.0/24 | DE | ripencc | 2020-01-01',
    '1.2.0.192.origin.asn.cymru.com': '64501 | 192.0.2.0/24 | US | arin | 2001-01-01' },
  names: { 16509: '16509 | US | arin | 2000-05-04 | AMAZON-02 - Amazon.com, Inc., US', 64500: '64500 | DE | ripencc | 2020-01-01 | RENTED - Rented Servers GmbH, DE', 64501: '64501 | US | arin | 2001-01-01 | HOMENET - Home Lines Inc, US' },
  kinds: { 64500: 'Content', 64501: 'Cable/DSL/ISP' },
  rdap: { 'evil.example.test': '2026-09-01T10:00:00Z', 'old.example.test': '2011-03-04T00:00:00Z' },
};

test('keys: an address by itself, a host by the name a registry holds, nothing for a hash or an onion name', () => {
  assert.equal(registrable('a.b.example.test'), 'example.test');
  assert.equal(registrable('shop.example.co.uk'), 'example.co.uk');
  assert.equal(registrable('localhost'), null);
  assert.deepEqual(enrichKey({ type: 'ipv4', value: '203.0.113.7' }), { key: 'ip|203.0.113.7', host: null });
  assert.equal(enrichKey({ type: 'ipv4', value: '203.0.113.0/24' }).key, 'ip|203.0.113.0');
  assert.deepEqual(enrichKey({ type: 'domain', value: 'CDN.Evil.Example.test.' }), { key: 'dom|example.test', host: 'cdn.evil.example.test' });
  assert.deepEqual(enrichKey({ type: 'url', value: 'http://cdn.example.test/a.js?x=1' }), { key: 'dom|example.test', host: 'cdn.example.test' });
  assert.equal(enrichKey({ type: 'url', value: 'http://203.0.113.7:8080/x' }).key, 'ip|203.0.113.7');
  assert.equal(enrichKey({ type: 'domain', value: 'abcdefabcdef.onion' }), null);
  assert.equal(enrichKey({ type: 'sha256', value: 'e'.repeat(64) }), null);
});

test('top sites: the committed snapshot ranks a host by the best name above it', () => {
  assert.ok(TOP_N >= 9000, `the snapshot holds ${TOP_N} domains`);
  const snap = JSON.parse(readFileSync(new URL('../lib/topsites.json', import.meta.url), 'utf8'));
  assert.match(snap.source, /^https:\/\/tranco-list\.eu\/list\//);
  assert.deepEqual(topRank(`cdn.${snap.domains[4]}`), { domain: snap.domains[4], rank: 5 });
  assert.equal(topRank('nobody-ranks-this.example.test'), null);
});

test('network classes: fixed lists for the shared edges and big clouds, the declared type for the rest', () => {
  assert.equal(netClass({ asn: 13335, kind: '' }), 'edge');
  assert.equal(netClass({ asn: 16509, kind: '' }), 'cloud');
  assert.equal(netClass({ asn: 8075, kind: 'Content' }), 'cloud');
  assert.equal(netClass({ asn: 64501, kind: 'Cable/DSL/ISP' }), 'access');
  assert.equal(netClass({ asn: 64502, kind: 'Enterprise' }), 'org');
  for (const kind of ['Content', 'NSP', '', null]) assert.equal(netClass({ asn: 64500, kind }), null, `a rented or unknown network: ${kind}`);
  assert.equal(netClass(null), null); assert.equal(netClass({ asn: null }), null);
});

test('lookups: owner and type for an address, registration for a domain, and a source that cannot be asked is a failure, not an answer', async () => {
  const w = net(WORLD);
  assert.deepEqual(await lookup('ip|203.0.113.7', { fetchImpl: w.fetchImpl, now: NOW }), { at: AT, asn: 16509, owner: 'Amazon.com, Inc., US', cc: 'US', kind: '' });
  assert.ok(!w.asked.some((u) => u.includes('peeringdb')), 'a network on the fixed lists is not asked about');
  assert.deepEqual(await lookup('ip|198.51.100.9', { fetchImpl: w.fetchImpl, now: NOW }), { at: AT, asn: 64500, owner: 'Rented Servers GmbH, DE', cc: 'DE', kind: 'Content' });
  assert.ok(w.asked.every((u) => !u.includes('example.test') || u.includes('rdap.org')), 'only the address goes to the DNS source');
  // unrouted: an answer (nobody owns it), stored as such
  assert.deepEqual(await lookup('ip|192.0.2.99', { fetchImpl: w.fetchImpl, now: NOW }), { at: AT, asn: null });
  // IPv6 goes to the nibble zone, fully expanded
  const six = net({ origin: { [`${'2001:0db8:0000:0000:0000:0000:0000:0001'.replace(/:/g, '').split('').reverse().join('.')}.origin6.asn.cymru.com`]: '64500 | 2001:db8::/32 | DE | ripencc | 2020-01-01' }, names: WORLD.names, kinds: WORLD.kinds });
  assert.equal((await lookup('ip|2001:db8::1', { fetchImpl: six.fetchImpl, now: NOW })).asn, 64500);
  // the allowance for network types: none left -> the owner is stored, the type waits and is asked again soon
  const capped = await lookup('ip|198.51.100.9', { fetchImpl: w.fetchImpl, now: NOW, budget: { peeringdb: 0 } });
  assert.deepEqual([capped.owner, capped.kind, capped.kt], ['Rented Servers GmbH, DE', null, 0]);
  assert.ok(!enrichDue(capped, NOW + 10 * 60_000) && enrichDue(capped, NOW + 40 * 60_000));
  // refused: one try used, no more questions this sweep, asked again a day later, three times in all
  const budget = { peeringdb: 5 };
  const refused = await lookup('ip|198.51.100.9', { fetchImpl: net({ ...WORLD, peeringdb: 429 }).fetchImpl, now: NOW, budget });
  assert.deepEqual([refused.kind, refused.kt, budget.peeringdb], [null, 1, 0]);
  assert.ok(!enrichDue(refused, NOW + 3_600_000) && enrichDue(refused, NOW + 21 * 3_600_000));
  assert.ok(!enrichDue({ ...refused, kt: 3 }, NOW + 21 * 3_600_000), 'after three tries the owner stands without a type');
  // domains
  assert.deepEqual(await lookup('dom|evil.example.test', { fetchImpl: w.fetchImpl, now: NOW }), { at: AT, registered: '2026-09-01' });
  assert.deepEqual(await lookup('dom|unknown.example.test', { fetchImpl: w.fetchImpl, now: NOW }), { at: AT, registered: null });
  await assert.rejects(lookup('dom|x.example.test', { fetchImpl: net({ rdap: { 'x.example.test': 503 } }).fetchImpl, now: NOW }), /rdap 503/);
  await assert.rejects(lookup('ip|203.0.113.7', { fetchImpl: async () => json({}, 502), now: NOW }), /dns 502/);
  // a stored answer stands for 90 days; a failure is retried after 20 hours, three times
  assert.ok(enrichDue(undefined, NOW) && !enrichDue({ at: AT, asn: 64500, kind: 'Content' }, NOW + 80 * 86_400_000) && enrichDue({ at: AT, asn: 64500, kind: 'Content' }, NOW + 91 * 86_400_000));
  assert.ok(!enrichDue({ at: AT, fail: 1 }, NOW + 3_600_000) && enrichDue({ at: AT, fail: 1 }, NOW + 21 * 3_600_000) && !enrichDue({ at: AT, fail: 3 }, NOW + 21 * 3_600_000));
});

const block = { step: 1, kind: 'block_indicator', when: 'always', asset: 'network', reversible: true };
const tp = (type, value, role, enrich) => targetPolicy({ type, value, role }, block, policyFor(block), enrich);
const FACTS = {
  'ip|203.0.113.7': { at: AT, asn: 16509, owner: 'Amazon.com, Inc., US', cc: 'US', kind: '' },
  'ip|203.0.113.8': { at: AT, asn: 13335, owner: 'Cloudflare, Inc., US', cc: 'US', kind: '' },
  'ip|198.51.100.9': { at: AT, asn: 64500, owner: 'Rented Servers GmbH, DE', cc: 'DE', kind: 'Content' },
  'ip|192.0.2.1': { at: AT, asn: 64501, owner: 'Home Lines Inc, US', cc: 'US', kind: 'Cable/DSL/ISP' },
  'ip|192.0.2.2': { at: AT, asn: 64502, owner: 'Example University, US', cc: 'US', kind: 'Educational/Research' },
  'dom|evilcdn.test': { at: AT, registered: '2026-09-01' },
  'dom|oldsite.test': { at: AT, registered: '2011-03-04' },
  'dom|github.io': { at: AT, registered: '2013-03-08' },
};

test('rules: an address in a shared network or a cloud is never an automatic block, whatever the reporting calls it, and the reason names the owner', () => {
  // without facts nothing changes: the reporting's reading stands
  assert.deepEqual([tp('ipv4', '203.0.113.7', 'c2').autonomy, tp('ipv4', '203.0.113.7', 'c2').owner], ['auto', null]);
  const cloud = tp('ipv4', '203.0.113.7', 'c2', FACTS);
  assert.deepEqual([cloud.autonomy, cloud.owner, cloud.gates], ['recommend', 'AS16509 Amazon.com, Inc., US', ['usage_check', 'expiry']]);
  assert.match(cloud.why, /^Public reporting reads it as a command-and-control server, but the address belongs to AS16509 Amazon\.com, Inc\., US, a cloud that rents addresses/);
  const edge = tp('ipv4', '203.0.113.8', 'attack_source', FACTS);
  assert.equal(edge.autonomy, 'recommend'); assert.match(edge.why, /AS13335 Cloudflare, Inc\., US, a delivery and relay network .* a block reaches all of them/);
  assert.match(tp('ipv4', '192.0.2.1', 'c2', FACTS).why, /Home Lines Inc, US, which lists itself as an access provider \(home and office connections\): if that is right/);
  assert.match(tp('ipv4', '192.0.2.2', 'c2', FACTS).why, /Example University, US, which lists itself as an organization's own network, not a hosting company/);
  for (const v of ['192.0.2.1', '192.0.2.2']) assert.equal(tp('ipv4', v, 'c2', FACTS).autonomy, 'recommend');
  // a rented server is where an actor's own box normally is: still automatic, and the owner is shown
  const rented = tp('ipv4', '198.51.100.9', 'c2', FACTS);
  assert.deepEqual([rented.autonomy, rented.owner], ['auto', 'AS64500 Rented Servers GmbH, DE']);
  assert.match(rented.why, /^Public reporting identifies it as the actor's own/);
  // a URL on a bare address is judged by the address
  assert.equal(tp('url', 'http://203.0.113.7/a.bin', 'payload_host', FACTS).autonomy, 'recommend');
  // where the class was already cautious the reason stays the role's, and the owner is still shown
  const unknown = tp('ipv4', '203.0.113.7', 'unknown', FACTS);
  assert.deepEqual([unknown.autonomy, unknown.owner], ['recommend', 'AS16509 Amazon.com, Inc., US']);
  assert.match(unknown.why, /does not say what part it plays/);
  // a step that only refers to an address (a hunt) keeps its own class and still carries the owner
  const hunt = { step: 1, kind: 'hunt', when: 'always', asset: 'any', reversible: true };
  const h = targetPolicy({ type: 'ipv4', value: '203.0.113.7', role: 'c2' }, hunt, policyFor(hunt), FACTS);
  assert.deepEqual([h.autonomy, h.owner], ['auto', 'AS16509 Amazon.com, Inc., US']);
});

test('rules: a long-registered or top-ranked domain is never an automatic block, and a looked-up date answers the age check', () => {
  const young = tp('domain', 'c2.evilcdn.test', 'c2', FACTS);
  assert.deepEqual([young.autonomy, young.registered, young.gates], ['auto', '2026-09-01', ['usage_check']]);
  const old = tp('domain', 'cdn.oldsite.test', 'payload_host', FACTS);
  assert.deepEqual([old.autonomy, old.registered, old.gates], ['recommend', '2011-03-04', ['usage_check']]);
  assert.match(old.why, /^Public reporting reads it as a host serving malware or tooling, but oldsite\.test was registered 2011-03-04, more than two years before it was checked/);
  // an exact URL on an old domain is narrow enough to stay with the reporting's reading; the date is shown
  const url = tp('url', 'http://cdn.oldsite.test/x.js', 'payload_host', FACTS);
  assert.deepEqual([url.autonomy, url.registered], ['auto', '2011-03-04']);
  // no date found: the reader still has the age check to run
  assert.deepEqual(tp('domain', 'nodate.example.test', 'c2', FACTS).gates, ['usage_check', 'age_check']);
  // top sites: by the committed snapshot, no lookup; exact host or URL only
  const snap = JSON.parse(readFileSync(new URL('../lib/topsites.json', import.meta.url), 'utf8'));
  const popular = snap.domains.find((d) => !sharedPlatform(d) && d.split('.').length === 2);
  const top = tp('domain', `files.${popular}`, 'c2', {});
  assert.deepEqual([top.autonomy, top.rank, top.gates.includes('exact_match_only')], ['recommend', snap.domains.indexOf(popular) + 1, true]);
  assert.match(top.why, new RegExp(`but ${popular.replace(/\./g, '\\.')} is among the [\\d,]+ most visited domains \\(rank [\\d,]+\\)`));
  assert.equal(tp('url', `https://files.${popular}/a`, 'c2', {}).autonomy, 'recommend');
  // a tenant's own name on a shared platform is judged as that: the platform's age and rank are not the tenant's
  const tenant = tp('domain', 'evil-site.github.io', 'c2', FACTS);
  assert.deepEqual([tenant.autonomy, tenant.registered, tenant.rank, tenant.gates], ['auto', null, null, ['usage_check', 'age_check', 'exact_match_only']]);
});

test('feeds: the facts reach every target, the list across cards and both tables, as three columns after why', () => {
  const stored = { v: 1, items: [{ ...block, text: 'Block the C2', targets: [{ type: 'ipv4', value: '203.0.113.7', role: 'c2' }, { type: 'domain', value: 'c2.evilcdn.test', role: 'c2' }] }], indicators: [] };
  const cards = [{ slug: 'alpha-2026', title: 'Alpha', date: '2026-11-12', lane: 'Hunt', source: 'ai', status: 'active', url: '/cards/alpha-2026', cves: [] }];
  const report = actionsReport(cards, { actionsOf: (c) => expandActions(c.slug, stored, FACTS), base: 'https://cutsign.example.test', now: NOW });
  const [a] = report.cards[0].actions;
  assert.equal(a.autonomy, 'recommend'); assert.match(a.why, /^1 of its 2 indicators puts it at recommend.*Amazon/);
  const list = indicatorsReport(report);
  const by = Object.fromEntries(list.indicators.map((r) => [r.value, r]));
  assert.deepEqual([by['203.0.113.7'].autonomy, by['203.0.113.7'].owner, by['203.0.113.7'].registered, by['203.0.113.7'].rank], ['recommend', 'AS16509 Amazon.com, Inc., US', null, null]);
  assert.deepEqual([by['c2.evilcdn.test'].autonomy, by['c2.evilcdn.test'].registered], ['auto', '2026-09-01']);
  const rows = indicatorsTsv(list).trim().split('\n').map((l) => l.split('\t'));
  assert.ok(rows.every((r) => r.length === INDICATOR_COLUMNS.length && r.every(Boolean)));
  assert.deepEqual(rows.find((r) => r[1] === '203.0.113.7').slice(-3), ['AS16509 Amazon.com, Inc., US', '-', '-']);
  const arows = actionsTsv(report).trim().split('\n').map((l) => l.split('\t'));
  assert.ok(arows.every((r) => r.length === TSV_COLUMNS.length));
  assert.deepEqual(arows.find((r) => r[12] === 'c2.evilcdn.test').slice(-3), ['-', '2026-09-01', '-']);
});

const draftOf = (targets) => ({ title: 'Card', contain: ['Block the C2'], cves: [], actions: { v: 1, items: [{ ...block, text: 'Block the C2', targets }], indicators: [{ type: 'sha256', value: 'e'.repeat(64), role: 'malware_file' }] } });
const seed = (store, slug, targets, extra = {}) => store.insertCardDraft({ story_id: `s-${slug}`, thread_ids: [], title: slug, score: 10, reasons: [], version: 1, status: 'promoted', promoted_slug: slug, draft: { ...draftOf(targets), ...extra } });

test('sweep: each fact is asked once, copied to the other cards that need it, kept beside the record, and a failure waits a day', async () => {
  const store = memoryStore();
  const a = await seed(store, 'alpha-2026', [{ type: 'ipv4', value: '203.0.113.7', role: 'c2' }, { type: 'domain', value: 'c2.evil.example.test', role: 'c2' }, { type: 'domain', value: 'x.pages.dev', role: 'c2' }]);
  const b = await seed(store, 'beta-2026', [{ type: 'ipv4', value: '203.0.113.7', role: 'c2' }, { type: 'domain', value: 'down.example.test', role: 'c2' }]);
  await seed(store, 'old-2026', [{ type: 'ipv4', value: '192.0.2.1', role: 'c2' }], { archived_on: '2026-11-01' });
  const w = net({ ...WORLD, rdap: { ...WORLD.rdap, 'example.test': '2026-09-01T10:00:00Z' } });
  // both names in this fixture share one registrable name; make the second one fail instead
  const flaky = async (url) => (url.includes('rdap.org') && w.asked.filter((u) => u.includes('rdap.org')).length >= 1 ? (w.asked.push(url), json({}, 503)) : w.fetchImpl(url));
  const first = await enrichOnlySweep(store, { now: NOW, fetchImpl: flaky });
  const rowA = await store.getCardDraft(a.id); const rowB = await store.getCardDraft(b.id);
  assert.deepEqual(Object.keys(rowA.draft.enrich).sort(), ['dom|example.test', 'ip|203.0.113.7'], 'a platform tenant and a hash are not looked up');
  assert.equal(rowA.draft.enrich['ip|203.0.113.7'].owner, 'Amazon.com, Inc., US');
  assert.deepEqual(rowB.draft.enrich['ip|203.0.113.7'], rowA.draft.enrich['ip|203.0.113.7']);
  assert.deepEqual(rowB.draft.enrich['dom|example.test'], rowA.draft.enrich['dom|example.test'], 'the same registrable name: copied');
  assert.deepEqual([first.looked_up, first.copied, first.failed, first.cards, first.errors], [2, 2, 0, 2, 0]);
  assert.equal(w.asked.filter((u) => u.includes('7.113.0.203')).length, 1, 'the shared address was asked once');
  assert.ok(!w.asked.some((u) => u.includes('1.2.0.192')), 'an archived card is not swept');
  assert.equal(rowA.draft.actions.items[0].text, 'Block the C2', 'the record is untouched');
  // nothing due: a second sweep asks nothing and writes nothing
  const before = w.asked.length;
  assert.deepEqual(await enrichOnlySweep(store, { now: NOW + 3_600_000, fetchImpl: w.fetchImpl }), { looked_up: 0, copied: 0, failed: 0, cards: 0, waiting: 0, errors: 0 });
  assert.equal(w.asked.length, before);
  // a source that is down: a failure is stored, left alone for 20 hours, then asked again
  const c = await seed(store, 'gamma-2026', [{ type: 'ipv4', value: '198.51.100.9', role: 'c2' }]);
  const down = async () => json({}, 502);
  assert.equal((await enrichOnlySweep(store, { now: NOW, fetchImpl: down })).failed, 1);
  assert.deepEqual((await store.getCardDraft(c.id)).draft.enrich, { 'ip|198.51.100.9': { at: AT, fail: 1 } });
  assert.equal((await enrichOnlySweep(store, { now: NOW + 3_600_000, fetchImpl: w.fetchImpl })).looked_up, 0);
  assert.equal((await enrichOnlySweep(store, { now: NOW + 21 * 3_600_000, fetchImpl: w.fetchImpl })).looked_up, 1);
  assert.equal((await store.getCardDraft(c.id)).draft.enrich['ip|198.51.100.9'].owner, 'Rented Servers GmbH, DE');
  // past its deadline it starts nothing; and it can be switched off
  const d = await seed(store, 'delta-2026', [{ type: 'ipv4', value: '192.0.2.1', role: 'c2' }]);
  assert.deepEqual([(await enrichOnlySweep(store, { now: NOW, fetchImpl: w.fetchImpl, deadline: Date.now() - 1 })).waiting, (await store.getCardDraft(d.id)).draft.enrich], [1, undefined]);
  process.env.CARD_ENRICH = '0';
  try { assert.equal((await enrichOnlySweep(store, { now: NOW, fetchImpl: w.fetchImpl })).looked_up, 0); } finally { delete process.env.CARD_ENRICH; }
});

test('wiring: the tick runs the sweep last with its own deadline, a re-derived record keeps the facts, and the hand cards\' file matches their indicators', () => {
  const tick = readFileSync(new URL('../api/watch.js', import.meta.url), 'utf8');
  assert.ok(tick.indexOf('enrichOnlySweep(store') > tick.indexOf('coverageOnlySweep(store'), 'after coverage');
  const m = /enrichOnlySweep\(store, \{ deadline: Math\.min\(started \+ (\d+)_000, Date\.now\(\) \+ (\d+)_000\) \}\)/.exec(tick);
  assert.ok(m && Number(m[1]) <= 270 && Number(m[2]) <= 25, 'no lookup starts late in the function');
  assert.ok(tick.includes("mark('enrich')"));
  // the derive step replaces draft.actions only, so draft.enrich (a sibling) survives it
  const hype = readFileSync(new URL('../lib/hype.js', import.meta.url), 'utf8');
  assert.ok(hype.includes('const draft = { ...(head.draft || {}), actions };') && hype.includes('const draft = { ...h.draft, enrich: next };'));
  const wanted = new Set();
  for (const stored of Object.values(HAND_ACTIONS)) for (const k of wantedKeys(stored, { skipHost: sharedPlatform })) wanted.add(k);
  for (const k of Object.keys(HAND_FACTS)) assert.ok(wanted.has(k), `handenrich.json holds a fact no hand card needs: ${k}`);
  assert.deepEqual(factsFor({ type: 'sha256', value: 'e'.repeat(64) }, HAND_FACTS), { owner: null, net: null, registered: null, old: false, reg_domain: null, rank: null, top_domain: null });
});
