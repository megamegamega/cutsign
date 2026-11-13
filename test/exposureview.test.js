// The Exposure tab: one report from every active card's stored exposure block, as a page, JSON and
// a tab-separated table; the sample script the page prints is run here against stubs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exposureReport, exposureTsv, exposureBody, selfCheckScript, TSV_COLUMNS, SCOPE } from '../lib/exposureview.js';

const shodan = (q) => `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
const AT = '2026-11-12T15:00:00.000Z';
const item = (kind, forKey, query, check, total, extra = {}) => ({ engine: 'shodan', kind, for: forKey, query, note: 'Banner product name. Affected per NVD: < 24.3.1; >= 25.0.0 < 25.1.2.', url: shodan(query), check, total, counted_at: AT, check_note: '', ...extra });

const CARDS = [
  { slug: 'widget-rce-2026', title: 'Widget Server RCE exploited', date: '2026-11-10', lane: 'Patch now + Hunt / IR', source: 'ai', status: 'active', url: '/cards/widget-rce-2026', cves: ['CVE-2026-1000', 'CVE-2026-1001'] },
  { slug: 'gizmo-2026', title: 'Gizmo auth bypass', date: '2026-11-12', lane: 'Patch', source: 'hand', status: 'active', url: '/cards/gizmo-2026.html', cves: ['CVE-2026-2000'] },
  { slug: 'phish-2026', title: 'Help desk impersonation', date: '2026-11-11', lane: 'Hunt / IR', source: 'ai', status: 'active', url: '/cards/phish-2026', cves: [] },
  { slug: 'old-2026', title: 'Archived thing', date: '2026-09-01', lane: 'Patch', source: 'hand', status: 'archived', url: '/cards/old-2026.html', cves: ['CVE-2026-3000'] },
  { slug: 'new-2026', title: 'Card not checked yet', date: '2026-11-12', lane: 'Patch', source: 'ai', status: 'active', url: '/cards/new-2026', cves: ['CVE-2026-4000'] },
];
const COVERAGE = {
  'widget-rce-2026': { checked_at: AT, exposure: {
    note: null, shodan: { status: 'ok' },
    items: [
      item('cve', 'CVE-2026-1000', 'vuln:CVE-2026-1000', 'counted', 120),
      item('cve', 'CVE-2026-1001', 'vuln:CVE-2026-1001', 'plan', undefined, { check_note: 'the key\'s plan does not include this filter' }),
      item('cpe', 'acme:widget_server', 'cpe:"cpe:/a:acme:widget_server"', 'empty', 0),
      item('product', 'acme:widget_server', 'product:"Widget Server"', 'counted', 9000),
      { engine: 'censys', kind: 'product', for: 'acme:widget_server', query: 'host.services: (software.product = "Widget Server")', note: 'Censys Platform host search.', url: null },
      item('alias', 'acme:widget_server', 'http.title:"Widget\tConsole"', 'counted', 50000, { note: '' }),
    ],
    trend: [
      { at: '2026-11-01', totals: { 'vuln:CVE-2026-1000': 80, 'product:"Widget Server"': 9500 } },
      { at: '2026-11-04', totals: { 'vuln:CVE-2026-1000': 100, 'product:"Widget Server"': 9400 } },
      { at: '2026-11-09', totals: { 'vuln:CVE-2026-1000': 110, 'product:"Widget Server"': 9100 } },
      { at: '2026-11-12', totals: { 'vuln:CVE-2026-1000': 120, 'product:"Widget Server"': 9000, 'http.title:"Widget\tConsole"': 50000 } },
    ],
  } },
  'gizmo-2026': { checked_at: AT, exposure: { note: 'NVD has not published CPE configurations for these CVEs yet.', shodan: { status: 'ok' },
    items: [item('cve', 'CVE-2026-2000', 'vuln:CVE-2026-2000', 'empty', 0, { note: 'Exact for this CVE.' })], trend: [] } },
  'phish-2026': { checked_at: AT, exposure: { note: 'No CVE in this campaign: nothing an internet scanner keys on. Scope by product in your own tool.', items: [], shodan: { status: 'ok' } } },
  'old-2026': { checked_at: AT, exposure: { items: [item('cve', 'CVE-2026-3000', 'vuln:CVE-2026-3000', 'counted', 7)] } },
};
const report = () => exposureReport(CARDS, {
  coverageOf: (c) => COVERAGE[c.slug] || null,
  kevOf: (c) => (c.slug === 'widget-rce-2026' ? { 'CVE-2026-1000': { date_added: '2026-11-11' } } : {}),
  base: 'https://cutsign.example.test', now: Date.parse('2026-11-13T12:00:00Z'),
});

test('exposureReport: active cards with queries, newest first; cards without queries listed apart; archived cards left out', () => {
  const r = report();
  assert.equal(r.kind, 'cutsign.exposure');
  assert.deepEqual(r.cards.map((c) => c.card), ['gizmo-2026', 'widget-rce-2026']);
  assert.deepEqual(r.without_queries.map((c) => c.card).sort(), ['new-2026', 'phish-2026']);
  assert.match(r.without_queries.find((c) => c.card === 'phish-2026').why, /No CVE in this campaign/);
  assert.equal(r.without_queries.find((c) => c.card === 'new-2026').why, 'Not checked yet.');
  assert.ok(!JSON.stringify(r).includes('old-2026'));
  assert.deepEqual(r.totals, { cards: 2, queries: 7, counted: 3, cards_without_queries: 2 });
  assert.equal(r.cards[1].url, 'https://cutsign.example.test/cards/widget-rce-2026');
  assert.deepEqual(r.cards[1].kev, ['CVE-2026-1000']);
  assert.deepEqual(r.tsv_columns, TSV_COLUMNS);
});

test('exposureReport: a count only where Shodan gave one; the week-ago point; the headline is the most specific counted query', () => {
  const w = report().cards.find((c) => c.card === 'widget-rce-2026');
  const q = (query) => w.queries.find((x) => x.query === query);
  const cve = q('vuln:CVE-2026-1000');
  assert.equal(cve.count, 120);
  assert.deepEqual(cve.week_ago, { at: '2026-11-04', count: 100 }); // the newest point at least seven days before 11-12
  assert.equal(cve.change_7d, 20);
  assert.deepEqual(cve.first, { at: '2026-11-01', count: 80 });
  assert.equal(cve.trend.length, 4);
  assert.equal(q('vuln:CVE-2026-1001').count, null); // the plan lacks the filter: no number, never a zero
  assert.equal(q('vuln:CVE-2026-1001').check, 'plan');
  assert.equal(q('cpe:"cpe:/a:acme:widget_server"').count, 0);
  assert.equal(q('cpe:"cpe:/a:acme:widget_server"').check, 'empty');
  const censys = w.queries.find((x) => x.engine === 'censys');
  assert.equal(censys.check, 'not_counted'); assert.equal(censys.count, null); assert.equal(censys.url, null);
  assert.equal(q('product:"Widget Server"').affected, '< 24.3.1; >= 25.0.0 < 25.1.2');
  assert.equal(q('product:"Widget Server"').change_7d, -400);
  // the alias matches far more services, the CVE tag is the exact one
  assert.deepEqual(w.headline, { query: 'vuln:CVE-2026-1000', kind: 'cve', count: 120, counted_at: AT, change_7d: 20 });
  // a card whose only query matched nothing has no headline
  assert.equal(report().cards.find((c) => c.card === 'gizmo-2026').headline, null);
});

test('exposureReport: the week-ago point is a week old, not whatever older point exists after a gap in counting', () => {
  const cov = { checked_at: AT, exposure: { items: [item('cve', 'CVE-2026-2000', 'vuln:CVE-2026-2000', 'counted', 300)],
    trend: [{ at: '2026-10-01', totals: { 'vuln:CVE-2026-2000': 10 } }, { at: '2026-11-12', totals: { 'vuln:CVE-2026-2000': 300 } }] } };
  const r = exposureReport([CARDS[1]], { coverageOf: () => cov, kevOf: () => ({}), base: 'https://cutsign.example.test', now: Date.parse('2026-11-13T12:00:00Z') });
  const q = r.cards[0].queries[0];
  assert.equal(q.week_ago, null, 'six weeks ago is not a week ago'); assert.equal(q.change_7d, null);
  assert.deepEqual(q.first, { at: '2026-10-01', count: 10 }, 'the trend still starts where it starts');
  assert.equal(exposureTsv(r).trimEnd().split('\n')[1].split('\t')[10], '-');
  // fourteen days is the limit, and counts
  cov.exposure.trend[0].at = '2026-10-29';
  const r2 = exposureReport([CARDS[1]], { coverageOf: () => cov, kevOf: () => ({}), base: 'https://cutsign.example.test', now: Date.parse('2026-11-13T12:00:00Z') });
  assert.deepEqual(r2.cards[0].queries[0].week_ago, { at: '2026-10-29', count: 10 });
});

test('exposureTsv: no control character reaches the table, whatever a counted host put in its page title', () => {
  const q = 'http.title:"Admin\u001b[2J\u001b]0;x\u0007 Console\u009b31m"';
  const cov = { checked_at: AT, exposure: { items: [item('alias', 'acme:widget_server', q, 'counted', 5, { note: 'Title\u0000 match.\u2028Affected per NVD: < 1.2\u001b[0m.' })], trend: [] } };
  const tsv = exposureTsv(exposureReport([CARDS[1]], { coverageOf: () => cov, kevOf: () => ({}), base: 'https://cutsign.example.test', now: Date.parse('2026-11-13T12:00:00Z') }));
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/.test(tsv), JSON.stringify(tsv));
  const f = tsv.trimEnd().split('\n')[1].split('\t');
  assert.equal(f.length, TSV_COLUMNS.length);
  assert.equal(f[12], 'http.title:"Admin [2J ]0;x  Console 31m"'); // the bytes that made them sequences are spaces
});

test('exposureTsv: a header, one line per query, the same number of fields on every line and never an empty one', () => {
  const tsv = exposureTsv(report());
  assert.ok(tsv.endsWith('\n'));
  const lines = tsv.trimEnd().split('\n');
  assert.equal(lines[0], TSV_COLUMNS.join('\t'));
  assert.equal(lines.length, 1 + 7);
  for (const l of lines) {
    const f = l.split('\t');
    assert.equal(f.length, TSV_COLUMNS.length, l);
    assert.ok(f.every((x) => x !== '' && x === x.trim()), l);
  }
  const row = (query) => Object.fromEntries(lines.map((l) => l.split('\t')).find((f) => f[12] === query).map((v, i) => [TSV_COLUMNS[i], v]));
  assert.deepEqual(row('vuln:CVE-2026-1000'), {
    card: 'widget-rce-2026', date: '2026-11-10', lane: 'Patch now + Hunt / IR', cves: 'CVE-2026-1000,CVE-2026-1001', kev: 'CVE-2026-1000',
    engine: 'shodan', kind: 'cve', product: 'CVE-2026-1000', check: 'counted', count: '120', count_7d_ago: '100', counted_at: '2026-11-12',
    query: 'vuln:CVE-2026-1000', url: shodan('vuln:CVE-2026-1000'), affected: '< 24.3.1; >= 25.0.0 < 25.1.2',
  });
  const plan = row('vuln:CVE-2026-1001');
  assert.equal(plan.count, '-'); assert.equal(plan.count_7d_ago, '-');
  const censys = row('host.services: (software.product = "Widget Server")');
  assert.equal(censys.url, '-'); assert.equal(censys.count, '-'); assert.equal(censys.counted_at, '-');
  // a tab inside a value would shift every later column: it becomes a space
  assert.equal(row('http.title:"Widget Console"').affected, '-');
  assert.equal(row('vuln:CVE-2026-2000').kev, '-');
});

test('no scope anywhere: the report, the table and the page carry placeholders only', () => {
  const r = report();
  const out = [JSON.stringify(r), exposureTsv(r), exposureBody(r, { base: 'https://cutsign.example.test' })];
  for (const text of out) {
    for (const m of text.matchAll(/\b(net|org|hostname|host\.ip|host\.dns\.names):\s*(\\?"|&quot;)?(.{0,12})/g)) {
      assert.match(m[3], /^(<|&lt;)your_/, `${m[0]} is not a placeholder`);
    }
  }
  assert.deepEqual(SCOPE.shodan, ['net:<your_ranges>', 'org:"<your_org>"', 'hostname:<your_domain>']);
  for (const q of r.cards.flatMap((c) => c.queries)) assert.ok(!/\b(net|org|hostname):/.test(q.query), q.query);
});

test('exposureBody: the script block, the ranking by count, a block per card with its counts, the cards without queries', () => {
  const html = exposureBody(report(), { base: 'https://cutsign.example.test' });
  assert.match(html, /GET https:\/\/cutsign\.example\.test\/exposure\.tsv/);
  assert.match(html, /GET https:\/\/cutsign\.example\.test\/exposure\.json/);
  for (const c of TSV_COLUMNS) assert.ok(html.includes(` ${c}`), c);
  assert.ok(html.includes('#!/usr/bin/env bash'));
  // ranking: only cards with a counted query, by the headline count
  const rank = html.slice(html.indexOf('Most widespread'), html.indexOf('By card, newest first'));
  assert.match(rank, /<td class="n">120<\/td><td><span class="up">▲ \+20<\/span><\/td><td><a href="#widget-rce-2026">/);
  assert.ok(!rank.includes('#gizmo-2026'));
  assert.match(rank, /CVE-2026-1000 \(KEV\)/);
  // card blocks: newest first, anchored, the count badge from the card's own renderer
  assert.ok(html.indexOf('id="gizmo-2026"') < html.indexOf('id="widget-rce-2026"'));
  assert.match(html, /<span class="num">9,000<\/span>/);
  assert.match(html, /9,500 on 2026-11-01/); // the trend's first point
  assert.match(html, /2 more queries Shodan matched nothing for, or could not count/); // the plan row and the empty CPE row
  assert.match(html, /paste into Censys search/);
  assert.match(html, /affected: &lt; 24\.3\.1/);
  assert.match(html, /2 active cards with nothing an internet scanner keys on/);
  assert.ok(!html.includes('Archived thing'));
  // an empty report still renders
  const empty = exposureBody(exposureReport([], {}));
  assert.match(empty, /No card carries an exposure query yet/);
});

// The script the page prints, run as printed: curl and sleep are replaced by shell functions, so
// nothing leaves the machine. It needs bash and jq, as the page says; without them the test is skipped.
const has = (cmd, args) => { try { execFileSync(cmd, args, { stdio: 'ignore' }); return true; } catch { return false; } };
test('the printed self-check script reads every counted Shodan row and sends the query plus the scope only to Shodan', { skip: !(has('bash', ['--version']) && has('jq', ['--version'])) }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'cutsign-exposure-'));
  const tsv = join(dir, 'exposure.tsv'); const sent = join(dir, 'sent'); const script = join(dir, 'selfcheck.sh'); const stub = join(dir, 'stub.sh');
  writeFileSync(tsv, exposureTsv(report()));
  writeFileSync(script, `${selfCheckScript('https://cutsign.example.test')}\n`);
  writeFileSync(stub, [
    'curl() {',
    '  case "$*" in',
    '    *cutsign.example.test/exposure.tsv*) cat "$TSV" ;;',
    '    *api.shodan.io/shodan/host/count*) for a in "$@"; do case "$a" in query=*) printf \'%s\\n\' "$a" >> "$SENT" ;; esac; done; echo \'{"total": 3}\' ;;',
    '    *) echo "unexpected: $*" >> "$SENT"; return 1 ;;',
    '  esac',
    '}',
    'sleep() { :; }',
    'export -f curl sleep',
    'bash "$1"',
  ].join('\n'));
  const env = { PATH: process.env.PATH, TSV: tsv, SENT: sent, SHODAN_API_KEY: 'test-key', SCOPE: 'net:<your_ranges>' };
  const out = execFileSync('bash', [stub, script], { env, encoding: 'utf8' }).trimEnd().split('\n').map((l) => l.split('\t'));
  assert.deepEqual(out[0], ['mine', 'internet', 'card', 'cves', 'query']);
  assert.deepEqual(out.slice(1), [
    ['3', '120', 'widget-rce-2026', 'CVE-2026-1000,CVE-2026-1001', 'vuln:CVE-2026-1000'],
    ['3', '9000', 'widget-rce-2026', 'CVE-2026-1000,CVE-2026-1001', 'product:"Widget Server"'],
    ['3', '50000', 'widget-rce-2026', 'CVE-2026-1000,CVE-2026-1001', 'http.title:"Widget Console"'],
  ]);
  assert.deepEqual(readFileSync(sent, 'utf8').trimEnd().split('\n'), [
    'query=vuln:CVE-2026-1000 net:<your_ranges>', 'query=product:"Widget Server" net:<your_ranges>', 'query=http.title:"Widget Console" net:<your_ranges>',
  ]);
  // without a scope the script stops before it asks anything
  const dir2 = mkdtempSync(join(tmpdir(), 'cutsign-exposure-'));
  const sent2 = join(dir2, 'sent');
  assert.throws(() => execFileSync('bash', [stub, script], { env: { PATH: process.env.PATH, TSV: tsv, SENT: sent2, SHODAN_API_KEY: 'test-key' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }), /set SCOPE/);
  assert.ok(!existsSync(sent2));
});

test('wiring: every tab bar has the Exposure tab, and the three routes exist', () => {
  const page = readFileSync(new URL('../api/page.js', import.meta.url), 'utf8');
  const navs = page.split('\n').filter((l) => l.includes('<nav class="tabs">') && /view=analyst|tabLink\('analyst'/.test(l)); // the search results' back link is not a tab bar
  assert.ok(navs.length >= 7, `tab bars found: ${navs.length}`);
  for (const l of navs) assert.ok(/>Exposure<\/(a|span)>/.test(l), `a tab bar without Exposure: ${l.trim().slice(0, 80)}`);
  const rewrites = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8')).rewrites;
  const dest = (src) => rewrites.find((r) => r.source === src)?.destination;
  assert.equal(dest('/exposure'), '/api/page?view=exposure');
  assert.equal(dest('/exposure.json'), '/api/page?view=exposure&format=json');
  assert.equal(dest('/exposure.tsv'), '/api/page?view=exposure&format=tsv');
});
