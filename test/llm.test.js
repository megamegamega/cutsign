// The structured-output call: when the API refuses a schema's compiled grammar as too large, the
// same call is retried without the grammar (schema in the prompt) and the JSON is still parsed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { callStructured, parseJsonText, _setClient, _setLLM } from '../lib/llm.js';

const Schema = z.object({ title: z.string(), items: z.array(z.string()) });
const GRAMMAR_400 = '400 {"type":"error","error":{"type":"invalid_request_error","message":"The compiled grammar is too large, which would cause performance issues. Simplify your tool schemas or reduce the number of strict tools."}}';

function fakeClient(log) {
  return { beta: { messages: { create: async (req) => {
    log.push(req);
    if (req.output_config?.format) throw Object.assign(new Error(GRAMMAR_400), { status: 400 });
    return { stop_reason: 'end_turn', model: 'claude-opus-5-5', usage: { input_tokens: 10, output_tokens: 5 },
      content: [{ type: 'text', text: 'Here you go:\n```json\n{"title":"t","items":["a"]}\n```' }] };
  } } } };
}

test('grammar-too-large falls back to a grammarless call with the schema in the system prompt', async () => {
  const prev = process.env.LLM_MODE; process.env.LLM_MODE = 'live';
  const log = []; _setLLM(null); _setClient(fakeClient(log));
  try {
    const r = await callStructured({ tier: 'deep', system: 'sys', messages: [{ role: 'user', content: 'go' }], schema: Schema, schemaName: 't' });
    assert.equal(log.length, 2);
    assert.ok(log[0].output_config.format, 'first attempt carries the grammar');
    assert.equal(log[1].output_config.format, undefined, 'retry has no grammar');
    assert.match(log[1].system[0].text, /JSON Schema/); assert.match(log[1].system[0].text, /"items"/);
    assert.deepEqual(r.data, { title: 't', items: ['a'] }); assert.equal(r.grammarless, true);
    assert.ok(Schema.safeParse(r.data).success);
  } finally { process.env.LLM_MODE = prev; _setClient(undefined); }
});

test('other API errors are not retried', async () => {
  const prev = process.env.LLM_MODE; process.env.LLM_MODE = 'live';
  const log = [];
  _setLLM(null); _setClient({ beta: { messages: { create: async (req) => { log.push(req); throw new Error('500 overloaded'); } } } });
  try {
    await assert.rejects(() => callStructured({ tier: 'deep', system: 'sys', messages: [{ role: 'user', content: 'go' }], schema: Schema, schemaName: 't' }), /overloaded/);
    assert.equal(log.length, 1);
  } finally { process.env.LLM_MODE = prev; _setClient(undefined); }
});

test('parseJsonText tolerates fences and surrounding prose', () => {
  assert.deepEqual(parseJsonText('{"a":1}'), { a: 1 });
  assert.deepEqual(parseJsonText('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(parseJsonText('Sure. {"a":{"b":[1,2]}} Done.'), { a: { b: [1, 2] } });
  assert.equal(parseJsonText('no json here'), null);
});
