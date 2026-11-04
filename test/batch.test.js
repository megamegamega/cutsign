// The Batches API seam (lib/llm.js): what a submitted request carries, and how an answer — or the lack
// of one — is read back. The fake API lives in this file; the pipeline-level batched flows are covered
// in test/queries.test.js (proposals) and test/hype.test.js (card drafts).

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { submitStructured, collectStructured, costOf, _setBatchAPI } from '../lib/llm.js';
import { memoryStore } from '../lib/store-memory.js';
import { collectJobs } from '../lib/jobs.js';
import { batchMode, _resetBatchMode } from '../lib/batchmode.js';

after(() => { _setBatchAPI(null); _resetBatchMode(); });

test('batch: a submitted request carries the model, the cached system prompt, effort and the output format, and no server-side fallback', async () => {
  const seen = [];
  _setBatchAPI({ async create(p) { seen.push(p); return { id: 'msgbatch_1', processing_status: 'in_progress' }; } });
  const r = await submitStructured({ tier: 'light', system: 'S', messages: [{ role: 'user', content: 'u' }], schema: z.object({ a: z.string() }), schemaName: 'thing', effort: 'low', maxTokens: 100 });
  assert.equal(r.batch_id, 'msgbatch_1'); assert.match(r.custom_id, /^thing-[0-9a-f-]{36}$/); assert.equal(r.model, 'claude-haiku-5-5');
  assert.equal(seen[0].requests.length, 1); assert.equal(seen[0].requests[0].custom_id, r.custom_id);
  const p = seen[0].requests[0].params;
  assert.equal(p.model, 'claude-haiku-5-5'); assert.equal(p.max_tokens, 100); assert.deepEqual(p.messages, [{ role: 'user', content: 'u' }]);
  assert.equal(p.output_config.effort, 'low'); assert.ok(p.output_config.format, 'structured output');
  assert.equal(p.system[0].text, 'S'); assert.equal(p.system[0].cache_control.type, 'ephemeral');
  assert.ok(!('fallbacks' in p) && !('betas' in p), 'the Batches API rejects the server-side fallback');
});

test('batch: collecting maps a running batch, a succeeded answer, an error, an expiry, a refusal and a truncation; cost is half the list price', async () => {
  let status = 'in_progress'; let out = [];
  _setBatchAPI({ async retrieve() { return { processing_status: status }; }, async results() { return (async function* () { yield* out; })(); } });
  const job = { batch_id: 'b', custom_id: 'c' };
  assert.deepEqual(await collectStructured(job), { status: 'pending' });
  status = 'ended';
  const ok = (over = {}) => ({ type: 'succeeded', message: { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: '{"a":"b"}' }], usage: { input_tokens: 1000, output_tokens: 500 }, ...over } });
  out = [{ custom_id: 'other', result: ok() }, { custom_id: 'c', result: ok() }];
  const got = await collectStructured(job);
  assert.equal(got.status, 'ok'); assert.deepEqual(got.data, { a: 'b' }); assert.equal(got.model, 'claude-opus-5-5');
  assert.equal(costOf('claude-opus-5-5', { input_tokens: 1000, output_tokens: 500 }), 0.014);
  assert.equal(got.cost, 0.007, 'half of the live price');
  out = [{ custom_id: 'c', result: { type: 'errored', error: { type: 'invalid_request', message: 'The compiled grammar is too large' } } }];
  assert.deepEqual(await collectStructured(job), { status: 'failed', error: 'invalid_request: The compiled grammar is too large' });
  out = [{ custom_id: 'c', result: { type: 'expired' } }];
  assert.equal((await collectStructured(job)).error, 'expired');
  out = [{ custom_id: 'c', result: ok({ stop_reason: 'refusal', stop_details: { category: 'cyber' } }) }];
  assert.match((await collectStructured(job)).error, /model refused \(cyber\)/);
  out = [{ custom_id: 'c', result: ok({ stop_reason: 'max_tokens' }) }];
  assert.match((await collectStructured(job)).error, /max_tokens/);
  out = [];
  assert.match((await collectStructured(job)).error, /without an answer/);
});

test('batch mode: on by default where the jobs table exists, off with LLM_BATCH=0 or the table missing; the collector is a no-op without the table', async (t) => {
  const before = process.env.LLM_BATCH;
  t.after(() => { process.env.LLM_BATCH = before; _resetBatchMode(); });
  const store = memoryStore();
  delete process.env.LLM_BATCH; _resetBatchMode();
  assert.equal(await batchMode(store), true);
  process.env.LLM_BATCH = '0';
  assert.equal(await batchMode(store), false);
  delete process.env.LLM_BATCH; _resetBatchMode();
  const bare = memoryStore(); bare.listJobs = async () => { throw new Error('relation "llm_jobs" does not exist'); };
  assert.equal(await batchMode(bare), false);
  assert.deepEqual(await collectJobs(bare), { checked: 0, pending: 0, landed: 0, live: 0, failed: 0, abandoned: 0, errors: 0, cost: 0, runs: [] });
});
