import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findUpdatedStory, isNovelBehavior, fingerprint } from '../lib/diff.js';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { fixtureMessage, withHeaders, fakeFetch, installFakeLLM, defaultResponder, captureOutputs, NETSCALER_EXTRACTION } from './helpers.js';

const prior = (o) => ({ story: { id: o.id, created_at: o.at || '2026-10-18T12:00:00Z', cves: [], threat_actor: null, malware_family: null, ...o }, iocIds: new Set(o.iocs || []) });

test('update matching: shared CVE, specific malware, or actor + shared IoC', () => {
  const today = { cves: ['CVE-2026-88779'], threat_actor: 'APT28', malware_family: 'Hookedge' };
  assert.equal(findUpdatedStory(today, new Set(), [prior({ id: 'a', cves: ['cve-2026-88779'] })])?.id, 'a');
  assert.equal(findUpdatedStory({ malware_family: 'Hookedge' }, new Set(), [prior({ id: 'b', malware_family: 'HookEdge' })])?.id, 'b');
  // actor alone is not enough…
  assert.equal(findUpdatedStory({ threat_actor: 'APT28' }, new Set(['x']), [prior({ id: 'c', threat_actor: 'apt28' })]), null);
  // …actor plus a shared IoC is
  assert.equal(findUpdatedStory({ threat_actor: 'APT28' }, new Set(['x']), [prior({ id: 'd', threat_actor: 'APT28', iocs: ['x'] })])?.id, 'd');
  // generic malware names never match
  assert.equal(findUpdatedStory({ malware_family: 'XMRig' }, new Set(), [prior({ id: 'e', malware_family: 'xmrig' })]), null);
  // most recent wins
  const two = [prior({ id: 'old', cves: ['CVE-1-1'], at: '2026-10-10T00:00:00Z' }), prior({ id: 'new', cves: ['CVE-1-1'], at: '2026-10-19T00:00:00Z' })];
  assert.equal(findUpdatedStory({ cves: ['CVE-1-1'] }, new Set(), two).id, 'new');
  assert.equal(fingerprint({ cves: ['CVE-2026-1'], threat_actor: 'UNC5820', malware_family: 'ransomware' }), 'cve:CVE-2026-1|actor:unc5820');
});

test('behavior novelty tolerates small changes in the command list', () => {
  const was = { pattern_kind: 'discovery_burst', parent: 'nsppe', children: ['whoami', 'id', 'uname -a', 'cat /etc/passwd'] };
  assert.equal(isNovelBehavior({ ...was, children: ['whoami', 'id', 'uname -a'] }, [was]), false);
  assert.equal(isNovelBehavior({ ...was, parent: 'httpd' }, [was]), true);
  assert.equal(isNovelBehavior({ ...was, pattern_kind: 'download_cradle' }, [was]), true);
  assert.equal(isNovelBehavior({ ...was, children: ['net user', 'nltest'] }, [was]), true);
});

test('day two of the same campaign: marked as an update, restated IoCs and known behaviors folded', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  // day 2 adds one new IoC and one new behavior to the same story
  const day2 = structuredClone(NETSCALER_EXTRACTION);
  day2.iocs.push({ type: 'domain', value: 'fresh-c2[.]org', role: 'c2', confidence: 'vendor_stated', context: 'new callback' });
  day2.behaviors.push({ attack_technique: 'T1053.003', pattern_kind: 'persistence_artifact', parent: 'nsppe', children: ['crontab'],
    log_source: 'cron log', time_window: null, vendor_stated: true, source_quote_ref: 'S1: "added a cron entry"' });
  let day = 1;
  installFakeLLM((user) => (/nsppe/.test(user) ? (day === 1 ? NETSCALER_EXTRACTION : day2) : { ...defaultResponder(user) }));

  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const first = out.emails[0].html;
  assert.match(first, /<b>New today:<\/b> 2 IoCs · 2 never-seen behaviors/);
  assert.match(first, /★ NEW/);
  assert.doesNotMatch(first, /update to/);

  day = 2;
  await intake(store, { messages: [withHeaders('netscaler-style.eml', { 'Message-ID': '<d2@x>', Subject: '[PIPELINE] Cyber Threat Brief - 2026-10-22' })] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const t = store._tables;
  const ns2 = t.stories.find((s) => s.run_id === t.runs[1].id && s.title.startsWith('NetScaler'));
  const ns1 = t.stories.find((s) => s.run_id === t.runs[0].id && s.title.startsWith('NetScaler'));
  assert.equal(ns2.updates_story_id, ns1.id, 'linked to yesterday\'s story via the shared CVE');
  assert.equal(t.runs[1].counts.story_updates >= 1, true);
  const second = out.emails[1].html;
  assert.match(second, /update to \d{4}-\d{2}-\d{2}'s story/);
  assert.match(second, /<b>New today:<\/b> 1 IoCs · 1 never-seen behaviors/);
  assert.match(second, /<b>Restated:<\/b> 2 IoCs/);
  assert.match(second, /fresh-c2\[\.\]org/, 'the new IoC is shown');
  assert.match(second, /Behaviors already reported \(2\)/, 'yesterday\'s behaviors fold away');
  assert.match(second, />Persistence</, 'the new behavior shows with its readable label');
});
