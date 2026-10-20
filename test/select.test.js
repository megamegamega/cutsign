import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreStory, pickDeep } from '../lib/select.js';

const base = { brief_text: '', severity: 'High', priority: 2, sector_relevance: [] };

test('behaviors and evidence outrank headline severity', () => {
  const rich = scoreStory({ story: { ...base, severity: 'Medium' }, behaviors: [{ vendor_stated: true }, { vendor_stated: true }], evidence: [{ kind: 'command_line' }, { kind: 'guidance' }] });
  const loud = scoreStory({ story: { ...base, severity: 'Critical', priority: 1 } });
  assert.ok(rich.score > loud.score, `${rich.score} > ${loud.score}`);
});

test('KEV and primary source boost; unconfirmed roundups are penalized', () => {
  const kev = scoreStory({ story: { ...base, brief_text: 'KEV-listed auth bypass' }, sources: [{ url: 'https://unit42.paloaltonetworks.com/x' }] });
  assert.ok(kev.why.includes('+3 KEV') && kev.why.includes('+2 primary source'));
  const unconf = scoreStory({ story: { ...base, brief_text: 'Unconfirmed - SiteGuard: this roundup is the only source' } });
  assert.ok(unconf.why.includes('-3 unconfirmed/roundup'));
});

test('pickDeep: top N above the floor, ties by brief order', () => {
  const s = (ordinal, score) => ({ story: { ordinal }, score, why: [] });
  assert.deepEqual(pickDeep([s(0, 5), s(1, 9), s(2, 9), s(3, 12)], { max: 2, min: 6 }).map((x) => x.story.ordinal), [3, 1]);
  assert.deepEqual(pickDeep([s(0, 5)], { max: 6, min: 6 }), [], 'a thin day sends nothing to the deep model');
});

test('P3 awareness stories and same-campaign duplicates do not take deep slots', () => {
  const p3 = { story: { ordinal: 9, priority: 3, cves: [] }, score: 16, why: [] };
  assert.deepEqual(pickDeep([p3], { max: 6, min: 6 }), [], 'P3 never gets a deep read, whatever it scores');
  const a = { story: { ordinal: 0, cves: ['CVE-2026-102764'] }, score: 38, why: [] };
  const b = { story: { ordinal: 5, cves: ['cve-2026-102764'] }, score: 15, why: [] };
  const c = { story: { ordinal: 3, cves: ['CVE-2026-110447'] }, score: 12, why: [] };
  assert.deepEqual(pickDeep([a, b, c], { max: 6, min: 6 }).map((x) => x.story.ordinal), [0, 3]);
});
