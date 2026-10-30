import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findUpdatedStory, isNovelBehavior, fingerprint, linkSiblings } from '../lib/diff.js';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { fixtureMessage, withHeaders, fakeFetch, installFakeLLM, defaultResponder, captureOutputs, NETSCALER_EXTRACTION, emptyExtraction } from './helpers.js';

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

test('same-brief siblings: the later item updates the earlier, the group takes its strongest priority, unrelated items untouched', () => {
  const row = (id, o) => ({ id, ordinal: 0, created_at: '2026-10-29T11:30:00Z', cves: [], threat_actor: null, malware_family: null, priority: 3, priority_reason: 'r', first_published_at: null, updates_story_id: null, ...o });
  // two outlets' takes on one campaign: the one published first is the original, whatever the brief order
  const thn = row('thn', { ordinal: 2, cves: ['CVE-2026-41709'], threat_actor: 'Warp Panda', priority: 1, first_published_at: '2026-10-29' });
  const sw = row('sw', { ordinal: 7, cves: ['CVE-2026-41709', 'CVE-2026-59309'], threat_actor: 'Warp Panda', priority: 2, priority_reason: 'no huntable patterns', first_published_at: '2026-10-29' });
  const other = row('other', { ordinal: 4, cves: ['CVE-2026-1'], priority: 2 });
  const p = linkSiblings([sw, other, thn]);
  assert.deepEqual(p.get('sw'), { updates_story_id: 'thn', priority: 1, priority_reason: 'no huntable patterns (raised to P1: the same brief carries a P1 item on this campaign)' }, 'brief order breaks the tie on the same publication day');
  assert.equal(p.has('thn'), false, 'the original keeps its row');
  assert.equal(p.has('other'), false);
  // a third item chains to the nearest earlier sibling; an item that already updates yesterday's row keeps that link only when no sibling precedes it
  const late = row('late', { ordinal: 9, cves: ['CVE-2026-59309'], first_published_at: '2026-10-29', updates_story_id: 'yesterday' });
  const q = linkSiblings([thn, sw, late]);
  assert.equal(q.get('late').updates_story_id, 'sw', 'links to the sibling it shares a CVE with, keeping the chain linear');
  assert.equal(q.get('late').priority, 1, 'the whole chain is one group');
  // actor alone never links siblings either
  assert.equal(linkSiblings([row('a', { threat_actor: 'APT28' }), row('b', { ordinal: 1, threat_actor: 'APT28' })]).size, 0);
  // level priorities: nothing to change (a second pass is a no-op)
  assert.equal(linkSiblings([thn, { ...sw, priority: 1 }]).get('sw').priority, undefined);
});

test('two items in one brief on one campaign: linked, labelled, and the P2 rises to its sibling\'s P1', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  // the retailer item is a second outlet's take on the NetScaler campaign (shares the CVE), rated P2 on its own
  installFakeLLM((user, n, req) => /Some retailer/.test(user) && req?.schemaName !== 'proposal'
    ? { ...emptyExtraction('Retailer outlet on the NetScaler campaign', 2), story: { ...emptyExtraction('x', 2).story, title: 'Retailer outlet on the NetScaler campaign', cves: ['CVE-2026-88779'], earliest_published: '2026-10-21' } }
    : defaultResponder(user, n, req));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const t = store._tables;
  const ns = t.stories.find((s) => s.title.startsWith('NetScaler'));
  const rt = t.stories.find((s) => s.title.startsWith('Retailer outlet'));
  assert.equal(rt.updates_story_id, ns.id, 'the later-published item updates the earlier one');
  assert.equal(ns.updates_story_id, null);
  assert.equal(rt.priority, 1, 'takes the sibling\'s P1');
  assert.match(rt.priority_reason, /raised to P1: the same brief carries a P1 item/);
  assert.equal(t.runs[0].counts.story_siblings, 1);
  assert.match(out.emails[0].html, /continues an earlier item in today's brief/, 'labelled as a same-brief continuation, not as an update to today\'s date');
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
  assert.match(second, /update to 2026-10-21's story/, 'labelled with the earlier brief\'s date');
  assert.match(second, /<b>New today:<\/b> 1 IoCs · 1 never-seen behaviors/);
  assert.match(second, /<b>Restated:<\/b> 2 IoCs/);
  assert.match(second, /fresh-c2\[\.\]org/, 'the new IoC is shown');
  assert.match(second, /Behaviors already reported \(2\)/, 'yesterday\'s behaviors fold away');
  assert.match(second, /★ NEW<\/span>Persistence/, 'the new behavior shows with its readable label');
});
