import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderDigest, MAX_HTML_BYTES } from '../lib/render.js';

const behavior = (i) => ({ pattern_kind: 'discovery_burst', parent: 'w3wp.exe', children: ['whoami', 'net user', `cmd${i}`], log_source: 'Sysmon EID 1',
  attack_technique: 'T1082', vendor_stated: true, source_quote_ref: 'S1: "a fairly long quote from the vendor write-up that explains what happened"', novel: true });
const story = (n, selected) => ({
  id: `s${n}`, ordinal: n, selected, priority: selected ? 1 : 2, title: `Story ${n}`, section: 'Actively exploited', severity: 'High',
  summary: 'A summary sentence that is not short. '.repeat(4), priority_reason: 'reason', attack_techniques: ['T1082'], cves: [],
  raw_iocs: { selection: { score: 20, why: ['+9 3 behaviors'] } }, suspicious_sources: [],
  behaviors: Array.from({ length: 10 }, (_, i) => behavior(i)),
  samples: Array.from({ length: 5 }, () => ({ kind: 'command_line', raw: 'powershell -enc '.padEnd(1500, 'A'), log_source: 'EDR', attack_technique: 'T1059.001' })),
  guidance: [{ kind: 'guidance', raw: 'Hunt for X\nindex=* sourcetype=… | stats count', publisher_tier: 'A', log_source: 'EDR', url: 'https://vendor.test/x' }],
  newIocs: Array.from({ length: 8 }, (_, i) => ({ id: `i${n}-${i}`, type: 'domain', value_norm: `bad${n}-${i}.example-c2.net`, role: 'c2', context: 'callback domain from the report' })),
  repeatIocs: [], sources: [{ url: 'https://vendor.test/a', publisher: 'Vendor', outcome: 'ok' }], updateOf: null,
});

test('a heavy day stays under Gmail\'s clip limit and keeps deep stories whole', () => {
  const analyzed = [story(0, true), story(1, true), ...Array.from({ length: 28 }, (_, i) => story(i + 2, false))];
  const d = { run: { id: 'r', dry: false }, brief: { subject: 'brief' }, date: '2026-10-16', analyzed, failed: [], notAnalyzed: [],
    newIocCount: 240, restatedIocCount: 0, novelBehaviorCount: 300, updateCount: 0 };
  const { html } = renderDigest(d);
  assert.ok(Buffer.byteLength(html) <= MAX_HTML_BYTES, `html is ${Buffer.byteLength(html)} bytes`);
  // deep stories still carry their evidence samples in full
  const deepPart = html.slice(html.indexOf('Story 0'), html.indexOf('Story 2'));
  assert.ok((deepPart.match(/<pre>/g) || []).length >= 10, 'deep evidence kept');
  assert.match(html, /to fit Gmail/);
  assert.match(html, /Story 29/, 'every story still appears');
});

test('a normal day renders in full', () => {
  const d = { run: { id: 'r', dry: false }, brief: { subject: 'b' }, date: '2026-10-16', analyzed: [story(0, true), story(1, false)],
    failed: [], notAnalyzed: [], newIocCount: 16, restatedIocCount: 0, novelBehaviorCount: 20, updateCount: 0 };
  const { html } = renderDigest(d);
  assert.doesNotMatch(html, /to fit Gmail/);
  assert.match(html, /<style>/);
});

test('exposure check renders only stated conditions', () => {
  const s = story(0, true);
  s.raw_iocs.exposure = { affected: ['Nextcloud richdocumentscode < 26.4.303'], only_if: ['Built-in CODE app installed'], not_affected_if: [], fixed_in: '26.4.303' };
  const d = { run: { id: 'r', dry: false }, brief: { subject: 'b' }, date: '2026-10-15', analyzed: [s], failed: [], notAnalyzed: [],
    newIocCount: 0, restatedIocCount: 0, novelBehaviorCount: 0, updateCount: 0 };
  const { html } = renderDigest(d);
  assert.match(html, /EXPOSURE CHECK/);
  assert.match(html, /<b>Only if<\/b>Built-in CODE app installed/);
  assert.match(html, /<b>Fixed in<\/b>26\.4\.303/);
  assert.doesNotMatch(html, /Not affected if/, 'empty rows are left out');
});
