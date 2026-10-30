// The automated coverage check: parsers on canned source text, and the lane runner on a fake
// network. No model, no real fetch. Every lane ends in one of the four statuses; a source that
// fails says so rather than reading as "nothing found".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  nicknameTerms, tenablePlugins,
  feedItems, matchItems, qids, rapid7Flags, redhatSummary, nvdSummary, etSids, coverageTerms,
  checkCoverage, diffCoverage, coverageStale, staleDiscovered, coverageTable, RECHECK_MS, ghFailure, ghTerm, aliases,
} from '../lib/coverage.js';

const CVE = 'CVE-2026-424242';
const rss = (items) => `<?xml version="1.0"?><rss><channel><title>feed</title>${items.map((i) => `<item><title>${i.title}</title><link>${i.link}</link>${i.date ? `<pubDate>${i.date}</pubDate>` : ''}<description><![CDATA[${i.body || ''}]]></description></item>`).join('')}</channel></rss>`;
const quick = { ghMinGapMs: 0, sleep: async () => {} }; // no real waits between GitHub calls in the lab

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
  assert.deepEqual(coverageTerms({ title: 'UAT-11473 exploits Cisco SD-WAN', malware_family: 'KeyDrift (PolyFlame, LittleFilch)' }), ['KeyDrift', 'PolyFlame', 'LittleFilch', 'UAT-11473', 'Cisco', 'SD-WAN'], 'a bracketed alias list becomes one term per alias');
  assert.deepEqual(aliases('Storm-0940 / Water Curse aka Lemon Sandstorm'), ['Storm-0940', 'Water Curse', 'Lemon Sandstorm']);
  assert.equal(ghTerm('KeyDrift (PolyFlame, LittleFilch)'), '"KeyDrift PolyFlame LittleFilch"', 'operators stripped, spaces quoted');
  assert.equal(ghTerm('UAT-11473'), 'UAT-11473'); assert.equal(ghTerm('Node.js'), 'Node.js'); assert.equal(ghTerm('(,)'), '');
});

/** Fake network: a router over the URLs the lanes ask. */
function fakeNet({ nvd = true, rapid7 = 'covered', redhat = 'errata', nuclei = false, et = true, cfHit = true, qualysItems = [], qualysBlogItems = [], qualysBlogDown = false, tenable = 'plugins', s1BlogItems = [], ghLimit = 0, ghStatus = 0 } = {}) {
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
    if (u.includes('blog.qualys.com')) return qualysBlogDown ? new Response('', { status: 503 }) : ok(rss(qualysBlogItems), 'application/rss+xml');
    if (u.includes('developers.cloudflare.com')) return ok(rss(cfHit ? [{ title: `WAF Release - Emergency - ${CVE}`, link: 'https://developers.cloudflare.com/waf/change-log/2026-10-25/' }] : [{ title: 'WAF Release - routine', link: 'https://developers.cloudflare.com/waf/change-log/x/' }]), 'application/xml');
    if (u.includes('unit42')) return ok(rss([{ title: 'A post about Widgetry', link: 'https://unit42.example.test/w' }]), 'application/rss+xml');
    if (u.includes('api.github.com/search/code')) {
      if (!(opts.headers || {}).Authorization) return new Response('{"message":"Requires authentication"}', { status: 401 });
      if (ghStatus === 422) return new Response(JSON.stringify({ message: 'Validation Failed', errors: [{ message: 'The listed users and repositories cannot be searched either because the resources do not exist or you do not have permission to view them.' }] }), { status: 422 });
      if (ghLimit && calls.filter((x) => x.includes('api.github.com/search/code')).length <= ghLimit) return new Response('{"message":"API rate limit exceeded"}', { status: 403, headers: { 'retry-after': '2' } });
      return ok(JSON.stringify({ total_count: 2, items: [{ path: 'rules/web/x.yml', repository: { full_name: 'SigmaHQ/sigma' } }, { path: 'detections/web/x.yml', repository: { full_name: 'splunk/security_content' } }] }));
    }
    if (u.includes('tenable.com/plugins/search')) return ok(tenable === 'none' ? '<html><p>No results found.</p></html>' : tenable === 'blank' ? '<html><p>loading</p></html>'
      : `<html><table><tr><td><a class="no-break" href="/plugins/nessus/369521">369521</a></td><td>GLSA-202610-02 : Widgetry: Multiple Vulnerabilities</td><td>Nessus</td><td><a href="/plugins/nessus/families/x">Gentoo Local Security Checks</a></td><td>10/21/2026</td></tr><tr><td><a class="no-break" href="/plugins/was/114747">114747</a></td><td>Widgetry &lt; 24.3.1 RCE</td><td>Web App Scanning</td><td>x</td></tr></table></html>`);
    if (u.includes('sentinelone.com/blog/feed')) return ok(rss(s1BlogItems), 'application/rss+xml');
    if (u.startsWith('https://api.shodan.io/api-info')) return ok(JSON.stringify({ plan: 'plus', query_credits: 100 }), 'application/json');
    if (u.startsWith('https://api.shodan.io/')) { const q = new URL(u).searchParams.get('query') || ''; return ok(JSON.stringify({ total: q.startsWith('vuln:') ? 1200 : q.startsWith('product:') ? 48000 : 0, matches: [], facets: {} }), 'application/json'); }
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
  assert.equal(byId(cov, `tenable:${CVE}`).status, 'published'); assert.match(byId(cov, `tenable:${CVE}`).detail, /^2 plugins: 369521 GLSA-202610-02 : Widgetry: Multiple Vulnerabilities; 114747 Widgetry < 24\.3\.1 RCE$/);
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
  assert.equal(cov.summary.published, 9, JSON.stringify(cov.summary));
  // categories print vendor first
  assert.equal(cov.lanes[0].category, 'Vendor');
  // the three Emerging Threats files were fetched once each, not once per lane
  assert.equal(net.calls.filter((u) => u.includes('emergingthreats')).length, 3);
  // the exposure queries ride on the same check, built from the NVD record it already fetched
  assert.deepEqual(cov.exposure.products, ['widgetry:widget_server']);
  assert.ok(cov.exposure.items.some((i) => i.query === `vuln:${CVE}`));
  assert.ok(cov.exposure.items.some((i) => i.query === 'cpe:"cpe:/a:widgetry:widget_server"'));
  assert.equal(net.calls.filter((u) => u.includes('services.nvd.nist.gov')).length, 1, 'NVD is asked once');
  // without a Shodan key the block says so and asks Shodan nothing
  assert.equal(cov.exposure.shodan.status, 'unset');
  assert.equal(net.calls.filter((u) => u.includes('api.shodan.io')).length, 0);
});

test('checkCoverage: with a Shodan key every Shodan query is counted after NVD names the products, the trend is carried from the previous check, and the first counts are a change', async () => {
  const net = fakeNet();
  const now = Date.parse('2026-10-28T12:00:00Z');
  const prev = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet(), githubToken: '', now: now - 3600_000, ...quick });
  const cov = await checkCoverage({ cves: [CVE], fetchImpl: net, githubToken: '', shodanKey: 'test-key-not-real', shodanMinGapMs: 0, prev, now, ...quick });
  const by = (q) => cov.exposure.items.find((i) => i.query === q);
  assert.equal(by(`vuln:${CVE}`).total, 1200); assert.equal(by(`vuln:${CVE}`).check, 'counted');
  assert.equal(by('product:"Widget Server"').total, 48000);
  assert.equal(by('cpe:"cpe:/a:widgetry:widget_server"').check, 'empty');
  assert.equal(cov.exposure.shodan.status, 'ok');
  assert.deepEqual(cov.exposure.trend.map((t) => t.at), ['2026-10-28']);
  assert.ok(!JSON.stringify(cov).includes('test-key-not-real'), 'the key is in no stored text');
  assert.ok(net.calls.some((u) => u.includes('api.shodan.io')) && net.calls.every((u) => !u.includes('api.shodan.io') || u.includes('query=') || u.includes('/api-info')), 'Shodan asked through its API');
  const changes = diffCoverage(prev, cov);
  assert.ok(changes.some((c) => /Shodan counts on \(2 queries counted\)/.test(c)), changes.join('\n'));
  const again = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet(), githubToken: '', shodanKey: 'test-key-not-real', shodanMinGapMs: 0, prev: cov, now: now + 86400_000, ...quick });
  assert.deepEqual(again.exposure.trend.map((t) => t.at), ['2026-10-28', '2026-10-29']);
  assert.equal(diffCoverage(cov, again).length, 0, 'a count moving day to day is not news');
  // a key set after a check ran makes that check stale at once, so the counts arrive at the next tick
  assert.equal(coverageStale(prev, now, { shodanKey: 'k' }), true);
  assert.equal(coverageStale(prev, now, { shodanKey: '' }), false);
  assert.equal(coverageStale(cov, now + 3600_000, { shodanKey: 'k' }), false);
  // a check from before counting existed (no shodan block at all) is stale too once a key is set
  assert.equal(coverageStale({ ...cov, exposure: { ...cov.exposure, shodan: undefined } }, now + 3600_000, { shodanKey: 'k' }), true);
  assert.equal(coverageStale({ ...cov, exposure: { ...cov.exposure, shodan: undefined } }, now + 3600_000, { shodanKey: '' }), false);
  // counted before the vuln: probe existed: stale once; a probe that ran and failed (null) is not
  const { vuln, ...noProbe } = cov.exposure.shodan;
  assert.equal(coverageStale({ ...cov, exposure: { ...cov.exposure, shodan: noProbe } }, now + 3600_000, { shodanKey: 'k' }), true);
  assert.equal(coverageStale({ ...cov, exposure: { ...cov.exposure, shodan: { ...noProbe, vuln: null } } }, now + 3600_000, { shodanKey: 'k' }), false);
  const { aliases, ...noAliases } = cov.exposure.shodan;
  assert.equal(coverageStale({ ...cov, exposure: { ...cov.exposure, shodan: noAliases } }, now + 3600_000, { shodanKey: 'k' }), true, 'counted before banner spellings existed');
  // a discovered spelling the stricter relevance test refuses is re-asked now
  const junk = { ...cov, exposure: { ...cov.exposure, items: [...cov.exposure.items, { engine: 'shodan', kind: 'discovered', for: 'beyondtrust:remote_support', query: 'product:"Remote Desktop Protocol"', check: 'counted', total: 1769388 }] } };
  assert.equal(staleDiscovered(junk.exposure), true); assert.equal(staleDiscovered(cov.exposure), false);
  assert.equal(coverageStale(junk, now + 3600_000, { shodanKey: 'k' }), true); assert.equal(coverageStale(junk, now + 3600_000, { shodanKey: '' }), false);
});

test('checkCoverage: without NVD CPEs the exposure block says so and carries only the CVE query', async () => {
  const cov = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ nvd: false }), githubToken: '' });
  assert.deepEqual(cov.exposure.products, []);
  assert.equal(cov.exposure.items.length, 1);
  assert.match(cov.exposure.note, /NVD has not published CPE/);
});

test('checkCoverage: a no-CVE campaign is matched by name; a token unlocks the rule-repo lanes; QIDs are read from Qualys posts', async () => {
  const net = fakeNet({ qualysItems: [{ title: `Widgetry flaw (${CVE})`, link: 'https://threatprotect.qualys.com/2026/10/x/', body: `Qualys customers can scan with QID 389117` }] });
  const noCve = await checkCoverage({ cves: [], terms: ['Widgetry'], fetchImpl: net, githubToken: 'tok', ...quick });
  assert.equal(byId(noCve, 'unit42').status, 'published');
  assert.equal(byId(noCve, 'kev').status, 'not checkable');
  assert.equal(byId(noCve, 'sigma').status, 'published'); assert.match(byId(noCve, 'sigma').detail, /rules\/web\/x\.yml/);
  assert.equal(byId(noCve, 'splunk_escu').status, 'published'); assert.match(byId(noCve, 'splunk_escu').detail, /detections\/web\/x\.yml/);
  assert.equal(byId(noCve, 'elastic_rules').status, 'nothing found', 'one search call covers the three repos; a repo with no hit says so');
  assert.equal(net.calls.filter((u) => u.includes('api.github.com/search/code')).length, 1, 'one code-search call per term, not one per repo');
  assert.ok(!noCve.lanes.some((l) => l.id.startsWith('nvd:')), 'no per-CVE lanes without a CVE');
  const withQid = await checkCoverage({ cves: [CVE], fetchImpl: net, githubToken: '' });
  assert.equal(byId(withQid, `qualys:${CVE}`).status, 'published'); assert.match(byId(withQid, `qualys:${CVE}`).detail, /^QID 389117 · ThreatPROTECT: Widgetry flaw/);
});

test('checkCoverage: QIDs printed on the Qualys Security Blog count too, and the row links the post that prints them', async () => {
  // the knowledge base needs a login; the product blog is where the QIDs for PHP2Shell and Node2Shell were actually printed
  const blog = [
    { title: `Can't patch Widgetry yet? (${CVE})`, link: 'https://blog.qualys.com/product-tech/2026/10/25/stopgap', body: 'Build a stopgap with the controls you own.' },
    { title: `Two Widgetry flaws: find, mitigate, patch (${CVE})`, link: 'https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/widgetry', body: 'Use QID 45110 for discovery, then QID 389102 and the unauthenticated check, QID 39033. Rescan with QIDs 533086 and 533068.' },
  ];
  const cov = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ qualysBlogItems: blog }), githubToken: '' });
  const q = byId(cov, `qualys:${CVE}`);
  assert.equal(q.status, 'published');
  assert.match(q.detail, /^QID 45110, 389102, 39033, 533086, 533068 · Security Blog: Two Widgetry flaws/);
  assert.match(q.detail, /\(\+1 more post\)/);
  assert.equal(q.url, 'https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/widgetry');
  // one feed down: still 'nothing found' from the other, and the detail says a feed failed
  const half = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ qualysBlogDown: true }), githubToken: '' });
  assert.equal(byId(half, `qualys:${CVE}`).status, 'nothing found'); assert.match(byId(half, `qualys:${CVE}`).detail, /one feed failed/);
});

test('nicknameTerms keeps campaign nicknames and product names, drops capitalised plain words', () => {
  assert.deepEqual(nicknameTerms(['PHP2Shell', 'Node.js', 'GitLab', 'BeyondTrust', 'Remote', 'Support', 'LiteLLM', 'ConnectWise', 'Backup', 'Widgetry']), ['PHP2Shell', 'Node.js', 'GitLab', 'BeyondTrust', 'LiteLLM', 'ConnectWise']);
});

test('feed items match on a nickname in the title inside the campaign window, and say the CVE id was not in the feed', async () => {
  // CrowdStrike, Akamai, Wiz and SentinelOne all titled their PHP2Shell posts by the nickname and
  // never printed the CVE id in the feed text: a CVE-only match called every one of them "nothing found"
  const s1 = [
    { title: 'Stopping Widget2Shell: how we protect customers', link: 'https://s1.example.test/stop', date: 'Tue, 21 Oct 2026 10:00:00 GMT', body: 'no cve id here' },
    { title: 'Widget2Shell from 2024, a retrospective', link: 'https://s1.example.test/old', date: 'Mon, 01 Jan 2024 10:00:00 GMT', body: 'old' },
    { title: 'Weekly roundup', link: 'https://s1.example.test/weekly', date: 'Tue, 21 Oct 2026 10:00:00 GMT', body: 'Widget2Shell mentioned in passing in the body only' },
  ];
  const now = Date.parse('2026-10-28T12:00:00Z');
  const cov = await checkCoverage({ cves: [CVE], terms: ['Widget2Shell', 'Remote'], fetchImpl: fakeNet({ s1BlogItems: s1 }), now, githubToken: '' });
  const l = byId(cov, 'sentinelone_blog');
  assert.equal(l.status, 'published');
  assert.equal(l.url, 'https://s1.example.test/stop');
  assert.match(l.detail, /^Stopping Widget2Shell: how we protect customers \(names Widget2Shell in the title; the feed text carries no CVE id\)$/, 'the 2024 post and the body-only mention are not coverage of this campaign');
  // a plain capitalised word from the title never matches by name
  const plain = await checkCoverage({ cves: [CVE], terms: ['Stopping'], fetchImpl: fakeNet({ s1BlogItems: s1 }), now, githubToken: '' });
  assert.equal(byId(plain, 'sentinelone_blog').status, 'nothing found');
  // matchItems: dates are parsed, the window applies to names only, a CVE id matches regardless of date
  const items = feedItems(rss(s1));
  assert.equal(items[0].date, '2026-10-21T10:00:00.000Z');
  assert.deepEqual(matchItems(items, { cves: [], titleTerms: ['Widget2Shell'], since: Date.parse('2026-09-13') }).map((i) => i.how), ['name']);
  assert.deepEqual(matchItems(feedItems(rss([{ title: `x ${CVE}`, link: 'https://s1.example.test/x', date: 'Mon, 01 Jan 2024 10:00:00 GMT' }])), { cves: [CVE], since: now }).map((i) => i.how), ['cve']);
});

test('Tenable: the plugin search page is parsed; "No results found" is a finding; a page without the table is a failed check', async () => {
  assert.deepEqual(tenablePlugins('<p>No results found.</p>'), []);
  assert.equal(tenablePlugins('<html>spinner</html>'), null);
  const none = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ tenable: 'none' }), githubToken: '' });
  assert.equal(byId(none, `tenable:${CVE}`).status, 'nothing found');
  const blank = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ tenable: 'blank' }), githubToken: '' });
  assert.equal(byId(blank, `tenable:${CVE}`).status, 'check failed'); assert.match(byId(blank, `tenable:${CVE}`).detail, /did not render/);
});

test('GitHub code search: a 403 with retry-after is waited out once and retried; terms are the CVE ids plus the nickname', async () => {
  const waits = [];
  const net = fakeNet({ ghLimit: 1 });
  const cov = await checkCoverage({ cves: [CVE], terms: ['Widget2Shell', 'Remote'], fetchImpl: net, githubToken: 'tok', ghMinGapMs: 0, sleep: async (ms) => { waits.push(ms); } });
  assert.deepEqual(waits, [2000], 'slept for the retry-after the API asked for');
  assert.equal(byId(cov, 'sigma').status, 'published');
  const q = net.calls.filter((u) => u.includes('api.github.com/search/code')).map((u) => decodeURIComponent(u));
  assert.equal(q.length, 3, 'the rate-limited call, its retry, then the CVE term');
  assert.ok(q[0].includes(`Widget2Shell repo:SigmaHQ/sigma repo:elastic/detection-rules repo:splunk/security_content`), 'the nickname is searched first (Splunk and Elastic name rules by the campaign, not the CVE; a three-CVE card must not push it out)');
  assert.ok(q[2].includes(`${CVE} repo:`), q[2]);
  assert.ok(!q.some((u) => u.includes('Remote repo:')), 'a plain word is not searched');
  assert.match(byId(cov, 'sigma').detail, /^1 file names Widget2Shell: rules\/web\/x\.yml/, 'the detail says which term found the files');
  assert.match(byId(cov, 'elastic_rules').detail, /^no rule file names Widget2Shell \/ CVE-2026-424242/);
});

test('GitHub code search: a bracketed alias list is split and quoted before it reaches the query parser (whole, it was a 422); at most three terms a card', async () => {
  const net = fakeNet();
  const cov = await checkCoverage({ cves: ['CVE-2026-20127'], terms: coverageTerms({ title: 'UAT-11473 exploits Cisco SD-WAN', malware_family: 'KeyDrift (PolyFlame, LittleFilch)' }), fetchImpl: net, githubToken: 'tok', ...quick });
  const q = net.calls.filter((u) => u.includes('api.github.com/search/code')).map((u) => decodeURIComponent(u).replace(/.*[?&]q=/, '').replace(/&.*/, ''));
  assert.deepEqual(q.map((s) => s.replace(/ repo:.*/, '')), ['KeyDrift', 'CVE-2026-20127', 'PolyFlame']);
  assert.ok(!q.some((s) => /[(),]/.test(s)), 'no parser operator in any query');
  assert.equal(byId(cov, 'sigma').status, 'published');
});

test('GitHub code search: a 422 from the parser says so rather than blaming the token', () => {
  assert.match(ghFailure({ status: 422, text: '{"message":"ERROR_TYPE_QUERY_PARSING_FATAL unable to parse query!"}' }), /unable to parse query.*could not parse the query/);
});

test('GitHub code search: a 422 names GitHub\'s reason and the token kind to fix it, on every rule-repo lane', async () => {
  const cov = await checkCoverage({ cves: [CVE], fetchImpl: fakeNet({ ghStatus: 422 }), githubToken: 'tok', ...quick });
  for (const id of ['sigma', 'elastic_rules', 'splunk_escu']) {
    const l = byId(cov, id);
    assert.equal(l.status, 'check failed');
    assert.match(l.detail, /HTTP 422 — Validation Failed; The listed users and repositories cannot be searched/, l.detail);
    assert.match(l.detail, /classic token/, 'says what kind of token code search accepts');
  }
  assert.equal(ghFailure({ status: 403, text: '{"message":"API rate limit exceeded"}' }), 'HTTP 403 — API rate limit exceeded (code search rate limit; re-asked next sweep)');
  assert.equal(ghFailure({ status: 500, text: '<html>' }), 'HTTP 500');
});

test('diff, staleness and the rendered table', () => {
  const a = { checked_at: '2026-10-27T12:00:00Z', lanes: [{ id: 'x', name: 'X', status: 'nothing found', detail: '' }, { id: 'y', name: 'Y', status: 'check failed', detail: '' }, { id: 'z', name: 'Z', status: 'published', detail: '' }] };
  const b = { checked_at: '2026-10-28T12:00:00Z', lanes: [{ id: 'x', name: 'X', status: 'published', detail: 'rule 7' }, { id: 'y', name: 'Y', status: 'nothing found', detail: '' }, { id: 'z', name: 'Z', status: 'published', detail: '' }], summary: { published: 2, nothing: 1, failed: 0, unchecked: 0 } };
  assert.deepEqual(diffCoverage(a, b), ['X: nothing found → published (rule 7)'], 'a lane recovering from a failed check is not a change');
  assert.deepEqual(diffCoverage(null, b), []);
  assert.deepEqual(diffCoverage({ ...a, exposure: { products: [] } }, { ...b, lanes: a.lanes, exposure: { products: ['widgetry:widget_server'] } }), ['Exposure queries: NVD now names widgetry:widget_server (Shodan and Censys product queries added)']);
  assert.equal(coverageStale(null), true);
  assert.equal(coverageStale(b, Date.parse('2026-10-28T13:00:00Z')), true, 'a check stored before the exposure block existed is re-asked');
  assert.equal(coverageStale({ ...b, exposure: null }, Date.parse('2026-10-28T13:00:00Z')), false);
  assert.equal(coverageStale({ ...b, exposure: null }, Date.parse('2026-10-28T12:00:00Z') + RECHECK_MS), true);
  const html = coverageTable({ ...b, lanes: [{ id: 'x', category: 'WAF / edge', name: 'Cloudflare', status: 'published', detail: 'rule <7>', url: 'https://cf.example.test/' }, { id: 'q', category: 'VM scanners', name: 'Qualys', status: 'nothing found', detail: 'none', url: 'https://q.example.test/' }] });
  assert.match(html, /<a href="https:\/\/cf\.example\.test\/">Cloudflare<\/a>/);
  assert.match(html, /rule &lt;7&gt;/);
  assert.doesNotMatch(html, /<a href="https:\/\/q\.example\.test\/">/, '"nothing found" rows stay unlinked');
  assert.match(html, /2 published, 1 nothing found/);
});
