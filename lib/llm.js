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
import * as z from 'zod/v4';

// deep: the exploited/TTP stories most likely to carry huntable behavior. light: everything else.
// propose: the hunt-query proposer (lib/queries.js), 2–4 calls a day on the deep-read P1/P2 stories;
// it falls back to `deep` when month-to-date spend passes 80% of the cap.
export const MODELS = {
  deep: () => process.env.LLM_MODEL_DEEP || 'claude-opus-5-5',
  light: () => process.env.LLM_MODEL_LIGHT || 'claude-haiku-5-5',
  propose: () => process.env.LLM_MODEL_PROPOSE || 'claude-fable-5-1',
};

// $ per million tokens: [input, output, cache read, cache write (5-min)]
// Source: platform.claude.com/docs/en/about-claude/pricing, read 2026-10-28.
export const PRICES = {
  'claude-fable-5-1': [10, 50, 0.25, 12.5],
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
export function _setClient(c) { _client = c; }

// Tests may inject a fake: (request) => ({ text, usage, model })
let override = null;
export function _setLLM(fn) { override = fn; }

// The API compiles a structured-output schema into a grammar and refuses one it judges too large
// ("The compiled grammar is too large… Simplify your tool schemas"). A rich schema such as the card
// draft can trip it. The fallback is the same call without the grammar: the schema goes into the
// system prompt as text and the JSON is validated by the caller's zod schema exactly as before.
const GRAMMAR_TOO_LARGE = /grammar is too large|compiled grammar/i;
const jsonSchemaText = (schema) => { try { return JSON.stringify(z.toJSONSchema(schema)); } catch { return ''; } };
/** Best-effort JSON from model text: strips code fences and any prose around the outermost object. */
export function parseJsonText(text) {
  const t = String(text || '').replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
  try { return JSON.parse(t); } catch { /* fall through */ }
  const a = t.indexOf('{'); const b = t.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try { return JSON.parse(t.slice(a, b + 1)); } catch { return null; }
}

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
    const base = { model, max_tokens: maxTokens, ...fallback, messages };
    const sys = (text) => [{ type: 'text', text, cache_control: { type: 'ephemeral' } }];
    let r; let grammarless = false;
    try {
      r = await client().beta.messages.create({ ...base, system: sys(system), output_config: { effort, format: zodOutputFormat(schema) } });
    } catch (e) {
      if (!GRAMMAR_TOO_LARGE.test(String(e?.message || e))) throw e;
      grammarless = true;
      const schemaText = jsonSchemaText(schema);
      r = await client().beta.messages.create({
        ...base,
        system: sys(`${system}\n\nOutput format: reply with one JSON object only — no prose, no code fences — that validates against this JSON Schema:\n${schemaText}`),
        output_config: { effort },
      });
    }
    if (r.stop_reason === 'refusal') throw new Error(`model refused (${r.stop_details?.category || 'unknown'})`);
    if (r.stop_reason === 'max_tokens') throw new Error('model output hit max_tokens (truncated JSON)');
    const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
    res = { text, usage: r.usage, model: r.model, grammarless };
    if (mode === 'record') {
      mkdirSync(FIXTURE_DIR, { recursive: true });
      writeFileSync(new URL(`${key}.json`, FIXTURE_DIR), JSON.stringify({ schemaName, ...res }, null, 2));
    }
  }
  const data = parseJsonText(res.text); // null → the caller treats it as a schema failure
  return { data, text: res.text, usage: res.usage || {}, model: res.model || model, cost: costOf(res.model || model, res.usage), grammarless: !!res.grammarless };
}
