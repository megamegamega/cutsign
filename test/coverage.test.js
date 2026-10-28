// The automated coverage check: parsers on canned source text, and the lane runner on a fake
// network. No model, no real fetch. Every lane ends in one of the four statuses; a source that
// fails says so rather than reading as "nothing found".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  feedItems, matchItems, qids, rapid7Flags, redhatSummary, nvdSummary, etSids, coverageTerms,
  checkCoverage, diffCoverage, coverageStale, coverageTable, RECHECK_MS,
} from '../lib/coverage.js';

const CVE = 'CVE-2026-424242';
const rss = (items) => `<?xml version="1.0"?><rss><channel><title>feed</title>${items.map((i) => `<item><title>${i.title}</title><link>${i.link}</link><description><![CDATA[${i.body || ''}]]></description></item>`).join('')}</channel></rss>`;

test('feed items, matching on CVE or whole-word terms', () => {
  const items = feedItems(rss([{ title: `Emergency rule for ${CVE}`, link: 'https://feed.example.test/1', body: '<p>added two rules</p>' }, { title: 'Weekly roundup', link: 'https://feed.example.test/2', body: 'Widgetry 2.0 and more' }]));
  assert.equal(items.length, 2); assert.equal(items[0].link, 'https://feed.example.test/1'); assert.match(items[0].text, /added two rules/);
  assert.equal(matchItems(items, { cves: [CVE] }).length, 1);
  assert.equal(matchItems(items, { terms: ['Widgetry'] }).length, 1);
  assert.equal(matchItems(items, { terms: ['Widget'] }).length, 0, 'whole words only');
  const atom = feedItems('<feed><entry><title>t</title><link href="https://a.example.test/x"/><content>body</content></entry></feed>');
  assert.equal(atom[0].link, 'https://a.example.test/x');
});

test('parsers: QIDs, Rapid7 flags, Red Hat errata, NVD score, Emerging Threats sids', () => {
  assert.deepEqual(qids('Qualys released QID 389117 and QIDs: 389120 for this'), ['389117', '389120']);
  const page = `<html><title>Vendor: ${CVE}: thing | Rapid7</title><script>{\\"has_rapid7_vm_coverage\\":true,\\"msf_module_count\\":2}</script></html>`;
  assert.deepEqual(rapid7Flags(page, CVE), { vm: true, msf: 2 });
  assert.equal(rapid7Flags('<title>Rapid7 Vulnerability Database</title>', CVE), null, 'a generic page is not an entry');
  assert.deepEqual(redhatSummary({ threat_severity: 'Important', affected_release: [{ advisory: 'RHSA-2026:1' }, { advisory: 'RHSA-2026:1' }], package_state: [{ fix_state: 'Affected' }] }), { errata: ['RHSA-2026:1'], states: ['Affected'], severity: 'Important' });
  assert.deepEqual(nvdSummary({ vulnerabilities: [{ cve: { published: '2026-10-22T14:17:37.190', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }], cvssMetricV40: [{ cvssData: { baseScore: 9.2 } }] } } }] }), { published: '2026-10-22', cvss: 9.2, cvssVersion: '4.0' });
  assert.equal(nvdSummary({ vulnerabilities: [] }), null);
  const rules = `alert http any any -> any any (msg:"ET EXPLOIT x"; reference:cve,2026-424242; sid:2061234; rev:1;)\nalert http any any -> any any (msg:"other"; sid:2061235;)\n`;
  assert.deepEqual(etSids(rules, CVE), ['2061234']);
});

test('coverage terms: stated names plus product-looking words from the title, never generic ones', () => {
  assert.deepEqual(coverageTerms({ title: 'ConnectWise Cloud Backup supply chain compromise', threat_actor: 'Storm-0940' }), ['Storm-0940', 'ConnectWise', 'Backup']);
  assert.deepEqual(coverageTerms({ title: 'Microsoft October security updates' }), []);
});

/** Fake network: a router over the URLs the lanes ask. */
function fakeNet({ nvd = true, rapid7 = 'covered', redhat = 'errata', nuclei = false, et = true, cfHit = true, qualysItems = [] } = {}) {
  const calls = [];
  const impl = async (url, opts = {}) => {
    const u = String(url); calls.push(u);
    const ok = (body, type = 'text/plain') => new Response(body, { status: 200, headers: { 'content-type': type } });
    const miss = () => new Response('nope', { status: 404 });
    if (u.includes('services.nvd.nist.gov')) return nvd ? ok(JSON.stringify({ vulnerabilities: [{ cve: { id: CVE, published: '2026-10-22T00:00:00', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] }, configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionEndExcluding: '24.3.1' }] }] }] } }] })) : ok(JSON.stringify({ vulnerabilities: [] }));
    if (u.includes('rapid7.com/db/vulnerabilities')) return rapid7 === 'none' ? ok('<title>Rapid7 Vulnerability Database</title>') : ok(`<title>Thing: ${CVE} | Rapid7</title><script>{\\"has_rapid7_vm_coverage\\":${rapid7 === 'covered'},\\"msf_module_count\\":0}</script>`);
    if (u.includes('access.redhat.com')) return redhat === 'errata' ? ok(JSON.stringify({ threat_severity: 'Important', affected_release: [{ advisory: 'RHSA-2026:7' }] })) : redhat === 'none' ? miss() : ok(JSON.stringify({ package_state: [{ fix_state: 'Affected' }] }));
    if (u.includes('security-tracker.debian.org')) return ok(`<html><title>${CVE}</title><td>fixed</td></html>`);
    if (u.includes('nuclei-templates')) return nuclei ? ok('id: x') : miss();
    if (u.includes('emergingthreats.net')) return et ? ok(`alert http any any -> any any (msg:"ET EXPLOIT"; reference:cve,${CVE.slice(4)}; sid:2099001;)\n`) : new Response('', { status: 503 });
    if (u.includes('threatprotect.qualys.com')) return ok(rss(qualysItems), 'application/rss+xml');
    if (u.includes('developers.cloudflare.com')) return ok(rss(cfHit ? [{ title: `WAF Release - Emergency - ${CVE}`, link: 'https://developers.cloudflare.com/waf/change-log/2026-10-25/' }] : [{ title: 'WAF Release - routine', link: 'https://developers.cloudflare.com/waf/change-log/x/' }]), 'application/xml');
    if (u.includes('unit42')) return ok(rss([{ title: 'A post about Widgetry', link: 'https://unit42.example.test/w' }]), 'application/rss+xml');
    if (u.includes('api.github.com/search/code')) return (opts.headers || {}).Authorization ? ok(JSON.stringify({ total_count: 1, items: [{ path: 'rules/web/x.yml' }] })) : new Response('{"message":"Requires authentication"}', { status: 401 });
    return miss(); // every other feed: not reachable in the lab
  };
  impl.calls = calls;
  return impl;
}

const byId = (cov, id) => cov.lanes.find((l) => l.id === id);

test('checkCoverage: every lane answers with an honest status; feeds match the CVE, not the product name', async () => {
  const net = fakeNet();
  const kev = new Map([[CVE, { dateAdded: '2026-10-27', dueDate: '2026-11-10' }]]);
  const cov = await checkCoverage({ cves: [CVE], terms: ['Widgetry'], sources: ['https://news.example.test/story', 'https://www.cisa.gov/news-events/alerts/x'], kev, fetchImpl: net, now: Date.parse('2026-10-28T12:00:00Z'), githubToken: '' });
  assert.equal(cov.checked_at, '2026-10-28T12:00:00.000Z');
  assert.equal(byId(cov, 'vendor').status, 'published'); assert.match(byId(cov, 'vendor').detail, /cisa\.gov/);
  assert.equal(byId(cov, `kev:${CVE}`).status, 'published'); assert.match(byId(cov, `kev:${CVE}`).detail, /listed 2026-10-27, federal due 2026-11-10/);
  assert.equal(byId(cov, `nvd:${CVE}`).status, 'published'); assert.match(byId(cov, `nvd:${CVE}`).detail, /CVSS 3\.1 9\.8/);
  assert.equal(byId(cov, `rapid7:${CVE}`).status, 'published'); assert.match(byId(cov, `rapid7:${CVE}`).detail, /InsightVM coverage stated/);
  assert.equal(byId(cov, `tenable:${CVE}`).status, 'not checkable');
  assert.equal(byId(cov, `qualys:${CVE}`).status, 'nothing found');
  assert.equal(byId(cov, `redhat:${CVE}`).status, 'published'); assert.match(byId(cov, `redhat:${CVE}`).detail, /RHSA-2026:7/);
  assert.equal(byId(cov, `debian:${CVE}`).status, 'published');
  assert.equal(byId(cov, `nuclei:${CVE}`).status, 'nothing found');
  assert.equal(byId(cov, `et:${CVE}`).status, 'published'); assert.match(byId(cov, `et:${CVE}`).detail, /sid 2099001/);
  assert.equal(byId(cov, 'cloudflare_waf').status, 'published'); assert.match(byId(cov, 'cloudflare_waf').detail, /Emergency/);
  assert.equal(byId(cov, 'cloudflare_waf').url, 'https://developers.cloudflare.com/waf/change-log/2026-10-25/', 'the name links to the matching post');
  assert.equal(byId(cov, 'unit42').status, 'nothing found', 'a product-name mention is not a match when the campaign has a CVE');
  assert.equal(byId(cov, 'crowdstrike').status, 'check failed', 'an unreachable feed says so');
  assert.equal(byId(cov, 'sigma').status, 'not checkable'); assert.match(byId(cov, 'sigma').detail, /GITHUB_TOKEN/);
  assert.equal(cov.lanes.filter((l) => !['published', 'nothing found', 'not checkable', 'check failed'].includes(l.status)).length, 0);
  assert.equal(cov.summary.published, 8, JSON.stringify(cov.summary));
  // categories print vendor first
  assert.equal(cov.lanes[0].category, 'Vendor');
  // the three Emerging Threats files were fetched once each, not once per lane
  assert.equal(net.calls.filter((u) => u.includes('emergingthreats')).length, 3);
  // the exposure queries ride on the same check, built from the NVD record it already fetched
  assert.deepEqual(cov.exposure.products, ['widgetry:widget_server']);
  assert.ok(cov.exposure.items.some((i) => i.query === `vuln:${CVE}`));
  assert.ok(cov.exposure.items.some((i) => i.query === 'cpe:"cpe:/a:widgetry:widget_server"'));
  assert.equal(net.calls.filter((u) => u.includes('services.nvd.nist.gov')).length, 1, 'NVD is asked once');
});

test('checkCoverage: without NVD CPEs the exposure block says so and carries only the CVE query', async () => {
  const cov = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ nvd: false }), githubToken: '' });
  assert.deepEqual(cov.exposure.products, []);
  assert.equal(cov.exposure.items.length, 1);
  assert.match(cov.exposure.note, /NVD has not published CPE/);
});

test('checkCoverage: a no-CVE campaign is matched by name; a token unlocks the rule-repo lanes; QIDs are read from Qualys posts', async () => {
  const net = fakeNet({ qualysItems: [{ title: `Widgetry flaw (${CVE})`, link: 'https://threatprotect.qualys.com/2026/10/x/', body: `Qualys customers can scan with QID 389117` }] });
  const noCve = await checkCoverage({ cves: [], terms: ['Widgetry'], fetchImpl: net, githubToken: 'tok' });
  assert.equal(byId(noCve, 'unit42').status, 'published');
  assert.equal(byId(noCve, 'kev').status, 'not checkable');
  assert.equal(byId(noCve, 'sigma').status, 'published'); assert.match(byId(noCve, 'sigma').detail, /rules\/web\/x\.yml/);
  assert.ok(!noCve.lanes.some((l) => l.id.startsWith('nvd:')), 'no per-CVE lanes without a CVE');
  const withQid = await checkCoverage({ cves: [CVE], fetchImpl: net, githubToken: '' });
  assert.equal(byId(withQid, `qualys:${CVE}`).status, 'published'); assert.match(byId(withQid, `qualys:${CVE}`).detail, /QID 389117/);
});

test('diff, staleness and the rendered table', () => {
  const a = { checked_at: '2026-10-27T12:00:00Z', lanes: [{ id: 'x', name: 'X', status: 'nothing found', detail: '' }, { id: 'y', name: 'Y', status: 'check failed', detail: '' }, { id: 'z', name: 'Z', status: 'published', detail: '' }] };
  const b = { checked_at: '2026-10-28T12:00:00Z', lanes: [{ id: 'x', name: 'X', status: 'published', detail: 'rule 7' }, { id: 'y', name: 'Y', status: 'nothing found', detail: '' }, { id: 'z', name: 'Z', status: 'published', detail: '' }], summary: { published: 2, nothing: 1, failed: 0, unchecked: 0 } };
  assert.deepEqual(diffCoverage(a, b), ['X: nothing found → published (rule 7)'], 'a lane recovering from a failed check is not a change');
  assert.deepEqual(diffCoverage(null, b), []);
  assert.deepEqual(diffCoverage({ ...a, exposure: { products: [] } }, { ...b, lanes: a.lanes, exposure: { products: ['widgetry:widget_server'] } }), ['Exposure queries: NVD now names widgetry:widget_server (Shodan and Censys product queries added)']);
  assert.equal(coverageStale(null), true);
  assert.equal(coverageStale(b, Date.parse('2026-10-28T13:00:00Z')), false);
  assert.equal(coverageStale(b, Date.parse('2026-10-28T12:00:00Z') + RECHECK_MS), true);
  const html = coverageTable({ ...b, lanes: [{ id: 'x', category: 'WAF / edge', name: 'Cloudflare', status: 'published', detail: 'rule <7>', url: 'https://cf.example.test/' }, { id: 'q', category: 'VM scanners', name: 'Qualys', status: 'nothing found', detail: 'none', url: 'https://q.example.test/' }] });
  assert.match(html, /<a href="https:\/\/cf\.example\.test\/">Cloudflare<\/a>/);
  assert.match(html, /rule &lt;7&gt;/);
  assert.doesNotMatch(html, /<a href="https:\/\/q\.example\.test\/">/, '"nothing found" rows stay unlinked');
  assert.match(html, /2 published, 1 nothing found/);
});
