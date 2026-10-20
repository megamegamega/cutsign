// Deep vs light tiers: the right model per story, every item read, light sources capped.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { fixtureMessage, fakeFetch, installFakeLLM, defaultResponder, captureOutputs } from './helpers.js';

test('deep stories use the deep model, everything else the light model, all items read', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  const fetchImpl = fakeFetch();
  await intake(store, { messages: [fixtureMessage('2026-10-20-pipeline.eml')] });
  await driveRuns(store, { fetchImpl });
  const t = store._tables;
  assert.equal(t.runs[0].stage, 'sent');
  assert.ok(t.stories.every((s) => s.status === 'extracted'), 'every brief item is read');
  const deep = t.stories.filter((s) => s.selected).length;
  assert.equal(calls.filter((c) => c.tier === 'light').length, t.stories.length, 'every item gets a light read first');
  assert.equal(calls.filter((c) => c.tier === 'deep').length, deep, 'then only the selected ones get the deep read');
  assert.ok(calls.filter((c) => c.tier === 'deep').every((c) => c.model === 'claude-opus-5-5'));
  assert.ok(calls.filter((c) => c.tier === 'light').every((c) => c.model === 'claude-haiku-5-5'));
  // light-read stories fetch only their first link (the rest are kept in case of a deep read)
  for (const s of t.stories.filter((x) => !x.selected)) {
    for (const u of s.source_urls.slice(1)) assert.ok(!fetchImpl.calls.includes(u), `light story fetched extra link ${u}`);
  }
  assert.equal(out.emails.length, 1);
  assert.match(out.discord.at(-1), /stories \(\d+ deep\)/);
});

test('deep slots go to what the sources contained, not the brief section', async () => {
  captureOutputs();
  const store = memoryStore();
  // the NetScaler item has rich content; everything else (incl. other "Actively exploited" items) is thin
  const calls = installFakeLLM(defaultResponder);
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const t = store._tables;
  const deep = t.stories.filter((s) => s.selected);
  assert.deepEqual(deep.map((s) => s.title.slice(0, 9)), ['NetScaler'], 'only the story with behaviors/evidence earns a deep read');
  const sel = deep[0].raw_iocs.selection;
  assert.ok(sel.score >= 6 && sel.why.some((w) => /behavior/.test(w)));
  // its second-pass sources were fetched for the deep read
  assert.ok(calls.some((c) => c.tier === 'deep' && /nsppe/.test(c.messages[0].content)));
  assert.ok(t.stories.filter((s) => !s.selected).every((s) => s.raw_iocs?.selection && s.raw_iocs.selection.deep === false));
});
