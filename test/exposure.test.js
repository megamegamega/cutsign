// Exposure queries: the generic half of an EASM alert, built from the CVE ids and NVD's CPE
// configurations. No model, no network. The scope half (ranges, org, domains) is never generated:
// the only scope the output ever carries is a placeholder.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nvdCpes, productName, exposureQueries, exposureTable, SCOPE_NOTE } from '../lib/exposure.js';

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
