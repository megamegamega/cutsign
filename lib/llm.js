// Claude calls with structured output, cost accounting, and record/replay for offline tests.
//
//   LLM_MODE=live    call the API (default in production)
//   LLM_MODE=record  call the API and save each response to fixtures/llm/<key>.json
//   LLM_MODE=replay  never touch the network; load fixtures/llm/<key>.json or fail loudly
//
// The key is a hash of (model, system, user, schema name), so a prompt edit invalidates recordings
// on purpose — re-record after tuning the prompt.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';

// deep: the exploited/TTP stories most likely to carry huntable behavior. light: everything else.
export const MODELS = {
  deep: () => process.env.LLM_MODEL_DEEP || 'claude-opus-5-5',
  light: () => process.env.LLM_MODEL_LIGHT || 'claude-haiku-5-5',
};

// $ per million tokens: [input, output, cache read, cache write (5-min)]
const PRICES = {
  'claude-opus-5-5': [4, 20, 0.2, 5],
  'claude-sonnet-5-5': [2, 10, 0.2, 2.5],
  'claude-haiku-5-5': [0.1, 0.5, 0.01, 0.125],
};

export function costOf(model, u = {}) {
  const p = PRICES[model] || PRICES['claude-opus-5-5'];
  return ((u.input_tokens || 0) * p[0] + (u.output_tokens || 0) * p[1]
    + (u.cache_read_input_tokens || 0) * p[2] + (u.cache_creation_input_tokens || 0) * p[3]) / 1e6;
}

const FIXTURE_DIR = new URL('../fixtures/llm/', import.meta.url);
const keyOf = (o) => createHash('sha256').update(JSON.stringify(o)).digest('hex').slice(0, 20);

let _client;
const client = () => (_client ||= new Anthropic({ timeout: 170_000, maxRetries: 1 }));

// Tests may inject a fake: (request) => ({ text, usage, model })
let override = null;
export function _setLLM(fn) { override = fn; }

/**
 * One structured-output call. Returns { data (unvalidated JSON), text, usage, model, cost }.
 * `messages` is the full conversation (for the retry turn); `system` is cached.
 */
export async function callStructured({ tier = 'deep', system, messages, schema, schemaName, effort = 'medium', maxTokens = 16000 }) {
  const model = MODELS[tier]();
  const key = keyOf({ model, system, messages, schemaName });
  const mode = process.env.LLM_MODE || 'live';
  let res;
  if (override) {
    res = await override({ model, tier, system, messages, schemaName });
  } else if (mode === 'replay') {
    const f = new URL(`${key}.json`, FIXTURE_DIR);
    if (!existsSync(f)) throw new Error(`LLM_MODE=replay: no recording ${key}.json for ${schemaName} (re-record with LLM_MODE=record)`);
    res = JSON.parse(readFileSync(f, 'utf8'));
  } else {
    // Security write-ups can trip the cyber classifier; route declines to the server's fallback chain
    // (Haiku has no server-side fallback — a refusal there just fails that one story).
    const fallback = /haiku/.test(model) ? {} : { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' };
    const r = await client().beta.messages.create({
      model,
      max_tokens: maxTokens,
      ...fallback,
      system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
      messages,
      output_config: { effort, format: zodOutputFormat(schema) },
    });
    if (r.stop_reason === 'refusal') throw new Error(`model refused (${r.stop_details?.category || 'unknown'})`);
    if (r.stop_reason === 'max_tokens') throw new Error('model output hit max_tokens (truncated JSON)');
    const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
    res = { text, usage: r.usage, model: r.model };
    if (mode === 'record') {
      mkdirSync(FIXTURE_DIR, { recursive: true });
      writeFileSync(new URL(`${key}.json`, FIXTURE_DIR), JSON.stringify({ schemaName, ...res }, null, 2));
    }
  }
  let data = null;
  try { data = JSON.parse(res.text); } catch { /* caller treats null as a schema failure */ }
  return { data, text: res.text, usage: res.usage || {}, model: res.model || model, cost: costOf(res.model || model, res.usage) };
}
