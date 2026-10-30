// Shodan counts for the exposure queries: every query counted through the count endpoint (no
// query credits), Shodan's own spelling discovered when NVD's matched nothing, the totals kept as
// a daily trend. Fake network only; the key never appears in any stored text.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateExposure, shodanCount, failureKind, discoveryText, relevant, MAX_CALLS } from '../lib/shodan.js';
import { nvdCpes, exposureQueries, exposureTable, countLine, trendRows } from '../lib/exposure.js';

const CVE = 'CVE-2026-424242';
const KEY = 'test-key-not-real';
const nvd = (cpeMatch) => ({ vulnerabilities: [{ cve: { id: CVE, configurations: [{ nodes: [{ operator: 'OR', cpeMatch }] }] } }] });
const cpes = nvdCpes(nvd([
  { vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionEndExcluding: '24.3.1' },
  { vulnerable: true, criteria: 'cpe:2.3:a:acme:panel_virtual_appliance:*:*:*:*:*:*:*:*' },
]));
const quick = { minGapMs: 0, sleep: async () => {} };
const now = Date.parse('2026-10-30T12:00:00Z');

/** Fake Shodan: totals by query, facets for the discovery search, failure modes. Records every query asked. */
function fakeShodan({ totals = {}, facets = {}, vulnPlan = false, badKey = false, rate = false, plan = 'plus' } = {}) {
  const asked = [];
  const impl = async (url) => {
    const u = new URL(url);
    assert.equal(u.hostname, 'api.shodan.io');
    assert.equal(u.searchParams.get('key'), KEY);
    const json = (b, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
    if (u.pathname === '/api-info') { impl.planAsked++; return badKey ? json({ error: 'Invalid API key' }, 401) : json({ plan, query_credits: 100 }); }
    const q = u.searchParams.get('query'); asked.push(q);
    if (badKey) return json({ error: 'Invalid API key' }, 401);
    if (rate) return json({ error: 'Rate limit exceeded' }, 429);
    if (vulnPlan && q.startsWith('vuln:')) return json({ error: 'Please upgrade your API plan to use this filter.' }, 401);
    if (u.searchParams.get('facets')) return json({ total: 999, matches: [], facets: facets[q] || {} });
    return json({ total: totals[q] ?? 0, matches: [] });
  };
  impl.asked = asked; impl.planAsked = 0;
  return impl;
}

test('validateExposure: on a plan without the vuln filter a vuln: zero is marked unconfirmed, not "0 services"; a nonzero still counts; the plan is asked once', async () => {
  const ex = exposureQueries({ cves: [CVE], cpes });
  const low = fakeShodan({ plan: 'dev', totals: { 'product:"Widget Server"': 5 } });
  // two days back, so the module's hour-long plan cache from this lookup is expired for the tests that follow
  const a = await validateExposure(ex, { key: KEY, cpes, fetchImpl: low, now: now - 2 * 86400_000, ...quick, plan: undefined });
  const vuln = a.items.find((i) => i.kind === 'cve');
  assert.equal(vuln.check, 'plan'); assert.match(vuln.check_note, /returned 0 on the "dev" plan.*Small Business/);
  assert.equal(low.planAsked, 1, 'plan looked up once');
  assert.ok(!(`vuln:${CVE}` in a.trend.at(-1).totals), 'an unconfirmed zero is not a trend point');
  assert.match(countLine(vuln, a.trend), /^Shodan count: vuln: returned 0/);
  assert.equal(a.items.find((i) => i.query === 'product:"Widget Server"').check, 'counted');
  // a nonzero vuln: total on the same plan is real
  const some = fakeShodan({ plan: 'dev', totals: { [`vuln:${CVE}`]: 7 } });
  const b = await validateExposure(ex, { key: KEY, cpes, fetchImpl: some, now, ...quick, plan: 'dev' });
  assert.equal(b.items.find((i) => i.kind === 'cve').check, 'counted');
  assert.equal(some.planAsked, 0, 'a plan passed in is not looked up');
  // the product whose queries all matched nothing says the spelling was searched for
  const panel = b.items.find((i) => i.kind === 'product' && i.for === 'acme:panel_virtual_appliance');
  assert.equal(panel.check, 'empty'); assert.match(panel.check_note, /text search for "Panel".*no product or http\.component facet value/);
  assert.match(countLine(panel, b.trend), /0 services match this spelling .* — a text search/);
  assert.ok(!JSON.stringify([a, b]).includes(KEY));
});

test('shodanCount / failureKind: Shodan\'s own error text, classified; never the URL', async () => {
  const ok = await shodanCount('product:"X"', { key: KEY, fetchImpl: fakeShodan({ totals: { 'product:"X"': 5 } }) });
  assert.deepEqual([ok.status, ok.total, ok.error], [200, 5, null]);
  const bad = await shodanCount('product:"X"', { key: KEY, fetchImpl: fakeShodan({ badKey: true }) });
  assert.equal(bad.status, 401); assert.equal(bad.error, 'Invalid API key'); assert.equal(failureKind(bad), 'key');
  assert.equal(failureKind({ status: 401, error: 'Please upgrade your API plan to use this filter.' }), 'plan');
  assert.equal(failureKind({ status: 429, error: 'x' }), 'rate');
  assert.equal(failureKind({ status: 500, error: 'x' }), 'failed');
  const down = await shodanCount('x', { key: KEY, fetchImpl: async () => { throw new Error('boom'); } });
  assert.equal(down.status, 0); assert.equal(down.error, 'boom');
  assert.ok(!JSON.stringify([ok, bad, down]).includes(KEY), 'the key is in no result');
});

test('discoveryText / relevant: distinctive words only; a facet value must share a word with the product', () => {
  assert.equal(discoveryText('Panel Virtual Appliance'), 'Panel');
  assert.equal(discoveryText('Php'), 'Php');
  assert.equal(discoveryText('Node.js'), 'Node.js');
  assert.equal(discoveryText('Virtual Appliance'), 'Virtual Appliance', 'nothing distinctive left: the whole name');
  const p = { vendor: 'php', product: 'php' };
  assert.equal(relevant('PHP', p), true);
  assert.equal(relevant('Apache httpd', p), false, 'a neighbour in the same banners is not the product');
  assert.equal(relevant('nginx', p), false);
  assert.equal(relevant('Acme Panel', { vendor: 'acme', product: 'panel_virtual_appliance' }), true);
  assert.equal(relevant('Widgetry Server', { vendor: 'widgetry', product: 'widget_server' }), true);
});

test('validateExposure: every Shodan query counted, a product Shodan spells differently gets its own spelling, totals become a trend point', async () => {
  const ex = exposureQueries({ cves: [CVE], cpes, now });
  const net = fakeShodan({
    totals: { [`vuln:${CVE}`]: 1200, 'cpe:"cpe:/a:widgetry:widget_server"': 0, 'product:"Widget Server"': 48000, 'product:"Acme Panel"': 310, 'http.component:"Acme Panel UI"': 12 },
    facets: { Panel: { product: [{ value: 'Apache httpd', count: 900 }, { value: 'Acme Panel', count: 310 }], 'http.component': [{ value: 'Acme Panel UI', count: 12 }], cpe: [{ value: 'cpe:/a:acme:panel_virtual_appliance:3.1', count: 200 }] } },
  });
  const v = await validateExposure(ex, { key: KEY, cpes, fetchImpl: net, now, ...quick });
  assert.equal(ex.items.some((i) => i.check), false, 'the input is not changed');
  const by = (q) => v.items.find((i) => i.query === q);
  assert.equal(by(`vuln:${CVE}`).check, 'counted'); assert.equal(by(`vuln:${CVE}`).total, 1200);
  assert.equal(by('cpe:"cpe:/a:widgetry:widget_server"').check, 'empty');
  assert.equal(by('product:"Widget Server"').total, 48000);
  assert.equal(v.items.filter((i) => i.for === 'widgetry:widget_server' && i.kind === 'discovered').length, 0, 'a product one of whose queries matched is not re-spelled');
  // the appliance: both NVD-spelled queries empty → one text search with facets, candidates counted, the ones that match kept, the CPE row told why
  const found = v.items.filter((i) => i.kind === 'discovered');
  assert.deepEqual(found.map((i) => [i.query, i.total]), [['product:"Acme Panel"', 310], ['http.component:"Acme Panel UI"', 12]]);
  assert.match(found[0].note, /Shodan's own spelling, from the product facet of a text search for "Panel"/);
  assert.match(found[0].note, /Affected per NVD: all versions/);
  assert.equal(found[0].url, `https://www.shodan.io/search?query=${encodeURIComponent('product:"Acme Panel"')}`);
  assert.match(by('cpe:"cpe:/a:acme:panel_virtual_appliance"').check_note, /stores this CPE with its version \(e\.g\. cpe:\/a:acme:panel_virtual_appliance:3\.1\)/);
  assert.ok(!net.asked.includes('product:"Apache httpd"'), 'a neighbour product is never counted');
  const idx = (q) => v.items.findIndex((i) => i.query === q);
  assert.ok(idx('product:"Acme Panel"') > idx('host.services: (software.product = "Panel Virtual Appliance")'), 'discovered rows follow their product\'s group');
  assert.equal(net.asked.filter((q) => q === 'Panel').length, 1, 'one discovery search per product');
  // the trend: one point for the day, keyed by query, discovered queries included
  assert.deepEqual(v.trend, [{ at: '2026-10-30', totals: { [`vuln:${CVE}`]: 1200, 'cpe:"cpe:/a:widgetry:widget_server"': 0, 'product:"Widget Server"': 48000, 'cpe:"cpe:/a:acme:panel_virtual_appliance"': 0, 'product:"Panel Virtual Appliance"': 0, 'product:"Acme Panel"': 310, 'http.component:"Acme Panel UI"': 12 } }]);
  assert.equal(v.shodan.status, 'ok'); assert.equal(v.shodan.counted, 4); assert.equal(v.shodan.calls, net.asked.length);
  assert.ok(!JSON.stringify(v).includes(KEY), 'the key is in no stored text');
  assert.doesNotMatch(JSON.stringify(v), /\b(net|org|hostname):(?!<)/, 'no scope filter is ever generated');

  // a week later: the previous trend is carried, the same day replaces its own point, and the count line reads the change
  const net2 = fakeShodan({ totals: { [`vuln:${CVE}`]: 900, 'product:"Widget Server"': 47000, 'product:"Acme Panel"': 300 } });
  const later = now + 7 * 86400_000;
  const v2 = await validateExposure(exposureQueries({ cves: [CVE], cpes, now: later }), { key: KEY, cpes, prev: v, fetchImpl: net2, now: later, ...quick });
  assert.equal(v2.trend.length, 2); assert.equal(v2.trend[1].at, '2026-11-06');
  assert.equal(countLine(v2.items.find((i) => i.query === `vuln:${CVE}`), v2.trend), 'Shodan: 900 services internet-wide (2026-11-06) · 1,200 on 2026-10-30 (-300 -25%)');
  const v3 = await validateExposure(exposureQueries({ cves: [CVE], cpes, now: later + 3600_000 }), { key: KEY, cpes, prev: v2, fetchImpl: net2, now: later + 3600_000, ...quick });
  assert.equal(v3.trend.length, 2, 'a second check the same day replaces that day\'s point');
  const rows = trendRows(v3.trend);
  assert.deepEqual(rows.find((r) => r.query === `vuln:${CVE}`), { query: `vuln:${CVE}`, first: { at: '2026-10-30', n: 1200 }, latest: { at: '2026-11-06', n: 900 }, delta: -300, pct: -25, points: 2 });
  assert.equal(rows.some((r) => r.query === 'http.component:"Acme Panel UI"'), false, 'a query counted once has no trend row');
  const html = exposureTable(v3);
  assert.match(html, /Shodan: 900 services internet-wide \(2026-11-06\) · 1,200 on 2026-10-30 \(-300 -25%\)/);
  assert.match(html, /Internet-wide count, trend/); assert.match(html, /over 2 days/);
  assert.match(html, /each Shodan query counted against Shodan itself/);
});

test('validateExposure: no key → unset, trend carried; a bad key fails every query once; a plan without vuln: still counts the products; the call budget holds', async () => {
  const ex = exposureQueries({ cves: [CVE], cpes, now });
  const prev = { trend: [{ at: '2026-10-29', totals: { [`vuln:${CVE}`]: 1000 } }] };
  const unset = await validateExposure(ex, { key: '', cpes, prev, fetchImpl: async () => { throw new Error('never called'); }, now });
  assert.equal(unset.shodan.status, 'unset'); assert.match(unset.shodan.note, /SHODAN_API_KEY/); assert.deepEqual(unset.trend, prev.trend);
  assert.equal(unset.items.some((i) => i.check), false);
  assert.match(exposureTable(unset), /Internet-wide counts need SHODAN_API_KEY/);

  const bad = fakeShodan({ badKey: true });
  const b = await validateExposure(ex, { key: KEY, cpes, fetchImpl: bad, now, ...quick });
  assert.equal(bad.asked.length, 1, 'one refusal is enough');
  assert.ok(b.items.filter((i) => i.engine === 'shodan').every((i) => i.check === 'failed' && /SHODAN_API_KEY is not accepted \(Invalid API key\)/.test(i.check_note)));
  assert.equal(b.shodan.status, 'failed'); assert.equal(b.trend, undefined);
  assert.match(exposureTable(b), /Shodan count failed: SHODAN_API_KEY is not accepted/);

  const plan = fakeShodan({ vulnPlan: true, totals: { 'product:"Widget Server"': 5 } });
  const p = await validateExposure(exposureQueries({ cves: [CVE, 'CVE-2026-424243'], cpes, now }), { key: KEY, cpes, fetchImpl: plan, now, ...quick });
  const vulns = p.items.filter((i) => i.kind === 'cve');
  assert.equal(vulns.length, 2); assert.ok(vulns.every((i) => i.check === 'plan'));
  assert.equal(plan.asked.filter((q) => q.startsWith('vuln:')).length, 1, 'the second vuln: query is not asked once the plan refused the first');
  assert.equal(p.items.find((i) => i.query === 'product:"Widget Server"').total, 5);
  assert.match(p.shodan.note, /vuln: needs a higher Shodan plan/);
  assert.match(exposureTable(p), /Shodan count: the key&#39;s plan does not include this filter/);

  const tight = fakeShodan({ totals: { [`vuln:${CVE}`]: 1 } });
  const t = await validateExposure(ex, { key: KEY, cpes, fetchImpl: tight, now, maxCalls: 2, ...quick });
  assert.equal(tight.asked.length, 2);
  assert.equal(t.items.filter((i) => i.check === 'skipped').length, 3, 'the three Shodan queries past the budget are skipped, not silently uncounted');
  assert.match(t.items.find((i) => i.check === 'skipped').check_note, /call budget/);
  assert.ok(MAX_CALLS <= 15, 'a card\'s Shodan calls fit inside the GitHub lane\'s wait at one a second');

  const rate = fakeShodan({ rate: true });
  const r = await validateExposure(ex, { key: KEY, cpes, fetchImpl: rate, now, ...quick });
  assert.ok(r.items.filter((i) => i.engine === 'shodan').every((i) => i.check === 'failed' && /rate limited/.test(i.check_note)));
  assert.equal(r.shodan.status, 'ok', 'a rate limit is not a broken key');
});

test('validateExposure: calls are spaced to the one-a-second limit', async () => {
  const waits = [];
  const net = fakeShodan({ totals: { [`vuln:${CVE}`]: 1 } });
  await validateExposure(exposureQueries({ cves: [CVE], cpes, now }), { key: KEY, cpes, fetchImpl: net, now, minGapMs: 1100, sleep: async (ms) => { waits.push(ms); } });
  assert.ok(waits.length >= net.asked.length - 1, `every call after the first waits (${waits.length} waits for ${net.asked.length} calls)`);
  assert.ok(waits.every((w) => w > 0), 'the fake clock never advances, so each wait is the gap or more');
});
