// Deep-read reuse: only when nothing could be new. Anything changed → fresh Opus read.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { fixtureMessage, withHeaders, fakeFetch, installFakeLLM, defaultResponder, captureOutputs, readFixture, NETSCALER_EXTRACTION } from './helpers.js';

const day2 = () => withHeaders('netscaler-style.eml', { 'Message-ID': '<day2@x>', Subject: '[PIPELINE] Cyber Threat Brief - 2026-10-22' });

async function twoDays({ fetchDay2 = fakeFetch(), responderDay2 = defaultResponder } = {}) {
  const out = captureOutputs();
  const store = memoryStore();
  let responder = defaultResponder;
  const calls = installFakeLLM((u, n, req) => responder(u, n, req));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const deepDay1 = calls.filter((c) => c.tier === 'deep').length;
  responder = responderDay2;
  // a day passes: yesterday's fetches are older than the 12 h page cache
  for (const src of store._tables.sources) src.fetched_at = new Date(Date.now() - 24 * 3600000).toISOString();
  await intake(store, { messages: [day2()] });
  await driveRuns(store, { fetchImpl: fetchDay2 });
  const deepDay2 = calls.filter((c) => c.tier === 'deep').length - deepDay1;
  const ns2 = store._tables.stories.find((s) => s.run_id === store._tables.runs[1].id && /NetScaler/.test(s.title));
  return { store, out, deepDay1, deepDay2, ns2, run2: store._tables.runs[1] };
}

test('unchanged sources and nothing new → deep read reused, no Opus call, labelled in the email', async () => {
  const { deepDay1, deepDay2, ns2, run2, out } = await twoDays();
  assert.ok(deepDay1 >= 1);
  assert.equal(deepDay2, 0, 'no deep call on day 2');
  assert.equal(run2.counts.deep_reused, 1);
  assert.equal(ns2.raw_iocs.selection.deep_done, 'reused');
  assert.ok(ns2.selected, 'still shown as a deep story');
  assert.ok(ns2.raw_iocs.iocs.length > 0, 'carries the earlier deep extraction');
  assert.match(out.emails.at(-1).html, /Deep read reused from 2026-10-21 — sources unchanged, no new indicators/);
  assert.match(out.discord.at(-1), /1 deep read reused/);
});

test('advisory updated in place (same URL, new content) → fresh deep read', async () => {
  const base = fakeFetch();
  const updated = async (url, opts) => {
    if (String(url).endsWith('/netscaler-post-exploitation')) {
      return new Response(readFixture('sources/netscaler.html').replace('No file hashes were recovered.', 'Update Oct 22: the actor now also drops /tmp/.x.'),
        { status: 200, headers: { 'content-type': 'text/html' } });
    }
    return base(url, opts);
  };
  const { deepDay2, ns2 } = await twoDays({ fetchDay2: updated });
  assert.equal(deepDay2, 1, 'changed page → read again');
  assert.equal(ns2.raw_iocs.selection.deep_done, 'fresh');
});

test('quick read finds a new IoC → fresh deep read', async () => {
  const withNew = structuredClone(NETSCALER_EXTRACTION);
  withNew.iocs.push({ type: 'ipv4', value: '91[.]92[.]93[.]94', role: 'c2', confidence: 'vendor_stated', context: 'new' });
  const { deepDay2, ns2 } = await twoDays({ responderDay2: (u, n, req) => (/nsppe/.test(u) && req.tier === 'light' ? withNew : defaultResponder(u)) });
  assert.equal(deepDay2, 1);
  assert.equal(ns2.raw_iocs.selection.deep_done, 'fresh');
});

test('a reused deep read passes its slot down the ranked list', async () => {
  process.env.MAX_STORIES = '1';
  try {
    const rich = structuredClone(NETSCALER_EXTRACTION);
    rich.story = { ...rich.story, title: 'Dead link story, but the quick read found behaviors', cves: ['CVE-2026-55555'] };
    rich.evidence_samples = []; rich.detection_guidance = []; rich.iocs = [];
    // day 2: the "Dead link" item (brief text "Source is gone") becomes a worthy second candidate
    const responderDay2 = (u) => (/Source is gone/.test(u) ? rich : defaultResponder(u));
    const { store, deepDay2, ns2 } = await twoDays({ responderDay2 });
    assert.equal(ns2.raw_iocs.selection.deep_done, 'reused');
    const dead = store._tables.stories.find((s) => s.run_id === store._tables.runs[1].id && /Source is gone/.test(s.brief_text));
    assert.equal(dead.raw_iocs.selection.deep_done, 'fresh', 'the next story got the freed slot');
    assert.ok(dead.selected);
    assert.equal(deepDay2, 1, 'still exactly MAX_STORIES fresh deep reads');
  } finally { delete process.env.MAX_STORIES; }
});
