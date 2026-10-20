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
  assert.equal(calls.filter((c) => c.tier === 'deep').length, deep);
  assert.equal(calls.filter((c) => c.tier === 'light').length, t.stories.length - deep);
  assert.ok(calls.filter((c) => c.tier === 'deep').every((c) => c.model === 'claude-sonnet-5-5'));
  assert.ok(calls.filter((c) => c.tier === 'light').every((c) => c.model === 'claude-haiku-5-5'));
  // light stories fetch only their first link
  const rankMath = t.stories.find((s) => /Rank Math/.test(s.brief_text));
  if (!rankMath.selected) assert.ok(rankMath.source_urls.length <= 1);
  assert.equal(out.emails.length, 1);
  assert.match(out.discord.at(-1), /stories \(\d+ deep\)/);
});
