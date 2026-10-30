// Exposure queries: the generic half of an EASM alert, built from the CVE ids and NVD's CPE
// configurations. No model, no network. The scope half (ranges, org, domains) is never generated:
// the only scope the output ever carries is a placeholder.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nvdCpes, productName, exposureQueries, exposureTable, namedProducts, countHtml, SCOPE_NOTE } from '../lib/exposure.js';

const CVE = 'CVE-2026-424242';
const nvd = (cpeMatch) => ({ vulnerabilities: [{ cve: { id: CVE, configurations: [{ nodes: [{ operator: 'OR', cpeMatch }] }] } }] });

test('nvdCpes: vulnerable products with their version ranges, one entry per vendor:product', () => {
  const cpes = nvdCpes(nvd([
    { vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionStartIncluding: '22.0.0', versionEndExcluding: '22.9.1' },
    { vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionStartIncluding: '24.0.0', versionEndExcluding: '24.3.1' },
    { vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:25.0.0:*:*:*:*:*:*:*' },
    { vulnerable: false, criteria: 'cpe:2.3:o:widgetry:widget_os:-:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:a:other:thing\\:colon:*:*:*:*:*:*:*:*' },
  ]));
  assert.equal(cpes.length, 2, 'the non-vulnerable platform entry is skipped');
  assert.deepEqual(cpes[0], { part: 'a', vendor: 'widgetry', product: 'widget_server', cpe23: 'cpe:2.3:a:widgetry:widget_server', ranges: ['>= 22.0.0 < 22.9.1', '>= 24.0.0 < 24.3.1', '= 25.0.0'] });
  assert.equal(cpes[1].product, 'thing:colon', 'escaped colons are unescaped');
  assert.deepEqual(nvdCpes({ vulnerabilities: [] }), []);
  assert.deepEqual(nvdCpes(null), []);
  assert.equal(productName('node.js'), 'Node.js');
  assert.equal(productName('widget_server'), 'Widget Server');
});

test('exposureQueries: a CVE query per CVE, three product queries per CPE, a scope placeholder and never a range', () => {
  const ex = exposureQueries({ cves: [CVE, 'not-a-cve'], cpes: nvdCpes(nvd([{ vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionEndExcluding: '24.3.1' }])), now: Date.parse('2026-10-28T12:00:00Z') });
  assert.equal(ex.built_at, '2026-10-28T12:00:00.000Z');
  assert.deepEqual(ex.products, ['widgetry:widget_server']);
  assert.equal(ex.note, null);
  assert.deepEqual(ex.items.map((i) => [i.engine, i.query]), [
    ['shodan', `vuln:${CVE}`],
    ['shodan', 'cpe:"cpe:/a:widgetry:widget_server"'],
    ['shodan', 'product:"Widget Server"'],
    ['censys', 'host.services: (software.product = "Widget Server")'],
  ]);
  assert.match(ex.items[1].note, /Affected per NVD: < 24\.3\.1/);
  assert.equal(ex.items[0].url, `https://www.shodan.io/search?query=${encodeURIComponent(`vuln:${CVE}`)}`);
  const text = JSON.stringify(ex);
  assert.doesNotMatch(text, /\b(net|org|hostname):(?!<)/, 'no scope filter is ever generated');
  assert.doesNotMatch(text, /\d{1,3}(\.\d{1,3}){3}/, 'no IP address');

  // NVD lists the library first and every embedder after it: the product the campaign names leads, platforms are skipped, four at most
  const many = nvdCpes(nvd([
    { vulnerable: true, criteria: 'cpe:2.3:a:lib:brotlish:*:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:a:widgetry:widget_server:*:*:*:*:*:*:*:*', versionEndExcluding: '24.3.1' },
    { vulnerable: true, criteria: 'cpe:2.3:a:v3:embedder_three:*:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:a:v4:embedder_four:*:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:a:v5:embedder_five:*:*:*:*:*:*:*:*' },
  ]));
  const ranked = exposureQueries({ cves: [CVE], cpes: many, terms: ['Widget-Server', 'Nothing'] });
  assert.deepEqual(ranked.products, ['widgetry:widget_server', 'lib:brotlish', 'v3:embedder_three', 'v4:embedder_four']);
  assert.match(ranked.note, /1 more affected product \(/);
  assert.ok(!JSON.stringify(ranked).includes('debian'), 'operating systems are the platform, not the service');

  const noCpe = exposureQueries({ cves: [CVE], cpes: [] });
  assert.equal(noCpe.items.length, 1); assert.match(noCpe.note, /NVD has not published CPE/);
  // no CPE but the campaign names the software: product + http.component + Censys rows under the name, with the card's own affected text
  const named = exposureQueries({ cves: [CVE], cpes: [], named: ['Drupal', 'Commerce', 'Third'], affected: ['Drupal Commerce Core 8.x-2.x before 2.40', 'Drupal 10.x and 11.x sites with Commerce'] });
  assert.deepEqual(named.items.map((i) => i.query), [`vuln:${CVE}`, 'product:"Drupal"', 'http.component:"Drupal"', 'host.services: (software.product = "Drupal")', 'product:"Commerce"', 'http.component:"Commerce"', 'host.services: (software.product = "Commerce")']);
  assert.ok(named.items.slice(1).every((i) => i.kind === 'named' && i.for.startsWith('named:') && /Affected per the card: Drupal Commerce Core 8\.x-2\.x before 2\.40; Drupal 10/.test(i.note)));
  assert.match(named.note, /name the campaign gives \(Drupal, Commerce\)/);
  assert.deepEqual(named.products, [], 'named rows are not NVD products');
  // with a CPE the names are not used (NVD's spelling wins), and a name that is not a word is dropped
  assert.ok(!exposureQueries({ cves: [CVE], cpes: many.slice(0, 1), named: ['Drupal'] }).items.some((i) => i.kind === 'named'));
  assert.equal(exposureQueries({ cves: [CVE], cpes: [], named: ['a', 'x"y', 'UAT-11473'] }).items.filter((i) => i.kind === 'named').length, 3, 'UAT-11473 is a word by shape; the caller strips actor names');
  const noCve = exposureQueries({ cves: [], cpes: [] });
  assert.equal(noCve.items.length, 0); assert.match(noCve.note, /No CVE/);
});

test('exposureTable: queries rendered verbatim, escaped, with the scope note', () => {
  const html = exposureTable(exposureQueries({ cves: [CVE], cpes: [{ part: 'a', vendor: 'v', product: 'p<x>', cpe23: 'cpe:2.3:a:v:p<x>', ranges: [] }], now: Date.parse('2026-10-28T12:00:00Z') }));
  assert.match(html, /<pre style="margin:4px 0">vuln:CVE-2026-424242<\/pre>/);
  assert.ok(!/<table>/.test(html), 'queries are blocks, not table cells (a pre in a cell collapses on a phone)');
  assert.match(html, /product:&quot;P&lt;x&gt;&quot;/);
  assert.match(html, /your_ranges/);
  assert.match(html, /2026-10-28 12:00Z/);
  assert.match(SCOPE_NOTE, /never in a shared document/);
  assert.match(exposureTable(null), /No exposure query/);
});

test('namedProducts: the card\'s affected lines first, then capitalised runs in the title; never a headline\'s first word for being first, an actor, a quoted name or a stop word', () => {
  // the Oracle EBS card: "Attackers" opened the story title and became product:"Attackers"
  assert.deepEqual(namedProducts({ title: 'Attackers probe patched Oracle EBS flaw CVE-2026-101767 on decoys', affected: ['Oracle E-Business Suite: Application Object Library component per SecurityWeek [S3]', 'Thin Client Framework servlet per BleepingComputer [S1]'] }),
    ['Oracle E-Business Suite', 'Thin Client Framework']);
  assert.deepEqual(namedProducts({ title: 'Attackers probe patched Oracle EBS flaw CVE-2026-101767 on decoys' }), ['Oracle EBS']);
  assert.deepEqual(namedProducts({ title: 'Probing of patched Oracle EBS flaw CVE-2026-101767 observed on decoys; no confirmed compromises' }), ['Oracle EBS']);
  // actor excluded, the quoted campaign name skipped, the products kept
  assert.deepEqual(namedProducts({ title: "Volt Typhoon reportedly uses 'Silent Train' relay chain to hide zero-day exploitation of VeloCloud Orchestrator and Cisco Catalyst SD-WAN", exclude: ['Volt Typhoon', 'VOLTZITE'] }),
    ['VeloCloud Orchestrator', 'Cisco Catalyst SD-WAN']);
  assert.deepEqual(namedProducts({ title: 'Drupal Commerce Core access bypass CVE-2026-118539 exploited' }), ['Drupal Commerce Core']);
  assert.deepEqual(namedProducts({ title: 'Trojanized Claude Code extension 2.1.313 on Cursor' }), ['Claude Code', 'Cursor']);
  assert.deepEqual(namedProducts({ title: 'Gotenberg CVE-2026-42589 RCE reportedly exploited' }), [], 'a plain first word on its own is not trusted even when it is the product: NVD\'s CPE or the model\'s banner spellings carry that case');
});

test('namedProducts: generic phrases, nationalities and a vendor alone are not products', () => {
  assert.deepEqual(namedProducts({ title: 'Cisco ASA/FTD SSL VPN zero-day CVE-2026-76418 exploited' }), [], 'SSL VPN is generic; ASA/FTD is lost to the slash and NVD carries it');
  assert.deepEqual(namedProducts({ title: 'Warp Panda reported exploiting ESXi logging flaw, China-nexus', exclude: ['Warp Panda'] }), ['ESXi']);
  assert.deepEqual(namedProducts({ title: 'Probing of patched Oracle flaw observed', affected: ['Oracle: Application Object Library'] }), [], 'a vendor alone counts every banner that vendor ever shipped');
});

test('countHtml: the number is a badge, a hit in accent and a zero muted, the trend coloured by direction', () => {
  const hit = { engine: 'shodan', kind: 'product', query: 'product:"X"', check: 'counted', total: 1200, counted_at: '2026-10-30T12:00:00Z' };
  const trend = [{ at: '2026-10-28', totals: { 'product:"X"': 1000 } }, { at: '2026-10-29', totals: { 'product:"X"': 1100 } }];
  const h = countHtml(hit, trend);
  assert.match(h, /^<p class="cnt hit"><span class="num">1,200<\/span><span class="lbl">services internet-wide on Shodan · 2026-10-30<\/span><span class="trd up">▲ 1,000 on 2026-10-28 \(\+200 \+20%\) · 1,100 on 2026-10-29 \(\+100 \+9%\)<\/span><\/p>$/);
  assert.match(countHtml({ ...hit, total: 900 }, trend), /class="trd down">▼/);
  assert.match(countHtml({ ...hit, check: 'empty', total: 0, check_note: 'a text search for "X" matches nothing on Shodan' }), /^<p class="cnt zero"><span class="num">0<\/span><span class="lbl">match this spelling on Shodan · 2026-10-30 — a text search for &quot;X&quot; matches nothing on Shodan<\/span><\/p>$/);
  assert.match(countHtml({ ...hit, check: 'plan', check_note: 'the vuln: filter returns nothing for this key' }), /^<p class="cnt off"><span class="lbl">Shodan count: the vuln: filter returns nothing for this key<\/span><\/p>$/);
  assert.equal(countHtml({ engine: 'censys', query: 'q' }), '');
  const table = exposureTable({ items: [hit], trend, built_at: '2026-10-30T12:00:00Z' });
  assert.match(table, /<span class="num">1,200<\/span>/); assert.doesNotMatch(table, /<b>Shodan: /);
});

test('namedProducts: version numbers in an affected line are the range, not the name', () => {
  assert.deepEqual(namedProducts({ title: 'Drupal Commerce Core access bypass CVE-2026-118539', affected: ['Drupal Commerce Core 0.0.0 through 2.39', 'Drupal Commerce Core 3.0.0 before 3.0.5'] }), ['Drupal Commerce Core']);
  assert.deepEqual(namedProducts({ title: 'GitLab 19.5.1 critical release' }), ['GitLab']);
});
