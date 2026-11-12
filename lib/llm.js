// Claude calls with structured output, cost accounting, and record/replay for offline tests.
//
//   LLM_MODE=live    call the API (default in production)
//   LLM_MODE=record  call the API and save each response to fixtures/llm/<key>.json
//   LLM_MODE=replay  never touch the network; load fixtures/llm/<key>.json or fail loudly
//
// The key is a hash of (model, system, user, schema name), so a prompt edit invalidates recordings
// on purpose — re-record after tuning the prompt.

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import * as z from 'zod/v4';

// deep: the exploited/TTP stories most likely to carry huntable behavior. light: everything else.
// propose: the hunt-query proposer (lib/queries.js), 2–4 calls a day on the deep-read P1/P2 stories;
// it falls back to `deep` when month-to-date spend passes 80% of the cap. It ran on Claude Fable 5.1
// until 2026-11-04 (about $0.90 a day at effort high); the proposals are lint-gated either way, and
// Opus 5.5 was already the fallback, so it became the default (LLM_MODEL_PROPOSE=claude-fable-5-1 restores it).
// 2026-11-12, cost cut: deep and propose default to Claude Sonnet 5.5, half Opus 5.5's price per token.
// The outputs are gated the same either way (schema, lint, card validators). LLM_MODEL_DEEP and
// LLM_MODEL_PROPOSE=claude-opus-5-5 restore Opus without a deploy of code.
export const MODELS = {
  deep: () => process.env.LLM_MODEL_DEEP || 'claude-sonnet-5-5',
  light: () => process.env.LLM_MODEL_LIGHT || 'claude-haiku-5-5',
  propose: () => process.env.LLM_MODEL_PROPOSE || 'claude-sonnet-5-5',
};

// $ per million tokens: [input, output, cache read, cache write (5-min)]
// Source: platform.claude.com/docs/en/about-claude/pricing, read 2026-10-28.
export const PRICES = {
  'claude-fable-5-1': [10, 50, 0.25, 12.5],
  'claude-opus-5-5': [4, 20, 0.2, 5],
  'claude-sonnet-5-5': [2, 10, 0.2, 2.5],
  'claude-haiku-5-5': [0.1, 0.5, 0.01, 0.125],
};

/** Dollars for one answer's usage; the Batches API bills every token at half the list price. */
export function costOf(model, u = {}, { batch = false } = {}) {
  // an id the table does not carry (a dated snapshot, a newer point release) is priced as its family;
  // only a name from no known family falls back to the Opus row
  const family = Object.keys(PRICES).find((k) => String(model || '').includes(k.split('-')[1]));
  const p = PRICES[model] || PRICES[family] || PRICES['claude-opus-5-5'];
  const usd = ((u.input_tokens || 0) * p[0] + (u.output_tokens || 0) * p[1]
    + (u.cache_read_input_tokens || 0) * p[2] + (u.cache_creation_input_tokens || 0) * p[3]) / 1e6;
  return batch ? usd / 2 : usd;
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

// The system prompt is the stable prefix of every call and is cached; the story text after it is unique.
const sys = (text) => [{ type: 'text', text, cache_control: { type: 'ephemeral' } }];
/** The request body of one structured call. The Batches API takes the same shape (minus the server-side fallback, which it rejects). */
function requestOf({ model, system, messages, schema, effort, maxTokens, grammarless = false }) {
  const base = { model, max_tokens: maxTokens, messages };
  if (!grammarless) return { ...base, system: sys(system), output_config: { effort, format: zodOutputFormat(schema) } };
  return {
    ...base,
    system: sys(`${system}\n\nOutput format: reply with one JSON object only — no prose, no code fences — that validates against this JSON Schema:\n${jsonSchemaText(schema)}`),
    output_config: { effort },
  };
}
// Security write-ups can trip the cyber classifier; route declines to the server's fallback chain
// (Haiku has no server-side fallback — a refusal there just fails that one story).
const fallbackFor = (model) => (/haiku/.test(model) ? {} : { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' });
/** The answer's text, or the reason there is none. */
function textOf(r) {
  if (r.stop_reason === 'refusal') throw new Error(`model refused (${r.stop_details?.category || 'unknown'})`);
  if (r.stop_reason === 'max_tokens') throw new Error('model output hit max_tokens (truncated JSON)');
  return r.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
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
    res = await override({ model, tier, system, messages, schemaName, effort });
  } else if (mode === 'replay') {
    const f = new URL(`${key}.json`, FIXTURE_DIR);
    if (!existsSync(f)) throw new Error(`LLM_MODE=replay: no recording ${key}.json for ${schemaName} (re-record with LLM_MODE=record)`);
    res = JSON.parse(readFileSync(f, 'utf8'));
  } else {
    const req = { model, system, messages, schema, effort, maxTokens };
    let r; let grammarless = false;
    try {
      r = await client().beta.messages.create({ ...requestOf(req), ...fallbackFor(model) });
    } catch (e) {
      if (!GRAMMAR_TOO_LARGE.test(String(e?.message || e))) throw e;
      grammarless = true;
      r = await client().beta.messages.create({ ...requestOf({ ...req, grammarless }), ...fallbackFor(model) });
    }
    const text = textOf(r);
    res = { text, usage: r.usage, model: r.model, grammarless };
    if (mode === 'record') {
      mkdirSync(FIXTURE_DIR, { recursive: true });
      writeFileSync(new URL(`${key}.json`, FIXTURE_DIR), JSON.stringify({ schemaName, ...res }, null, 2));
    }
  }
  const data = parseJsonText(res.text); // null → the caller treats it as a schema failure
  return { data, text: res.text, usage: res.usage || {}, model: res.model || model, cost: costOf(res.model || model, res.usage), grammarless: !!res.grammarless };
}

// ---- the Batches API: the same call at half price, answered within a day -----------------------------
// Work that can wait an hour goes this way (hunt proposals, card drafts); lib/jobs.js keeps the rows and
// collects the answers on the watch tick. One request per batch keeps every answer independent.

let batchApi = null;
/** Tests inject a fake { create, retrieve, results, cancel }. */
export function _setBatchAPI(api) { batchApi = api; }
const batches = () => batchApi || client().beta.messages.batches;

/** Submit one structured call. Returns { batch_id, custom_id, model }. Throws when the API refuses the request. */
export async function submitStructured({ tier = 'deep', system, messages, schema, schemaName, effort = 'medium', maxTokens = 16000 }) {
  const model = MODELS[tier]();
  const custom_id = `${schemaName}-${randomUUID()}`;
  const b = await batches().create({ requests: [{ custom_id, params: requestOf({ model, system, messages, schema, effort, maxTokens }) }] });
  return { batch_id: b.id, custom_id, model };
}

/**
 * Look for the answer: { status: 'pending' } while the batch runs; { status: 'ok', data, text, usage, model, cost }
 * (cost at the batch rate); { status: 'failed', error } when the API could not answer (an error, a refusal,
 * an expired or cancelled request) — the caller then makes the call live, once.
 */
export async function collectStructured({ batch_id, custom_id }) {
  const b = await batches().retrieve(batch_id);
  if (b.processing_status !== 'ended') return { status: 'pending' };
  for await (const r of await batches().results(batch_id)) {
    if (r.custom_id !== custom_id) continue;
    if (r.result.type !== 'succeeded') {
      const e = r.result.error;
      return { status: 'failed', error: r.result.type === 'errored' ? `${e?.type || 'error'}: ${String(e?.message || '').slice(0, 200)}` : r.result.type };
    }
    const m = r.result.message;
    let text;
    try { text = textOf(m); } catch (e) { return { status: 'failed', error: String(e.message) }; }
    return { status: 'ok', data: parseJsonText(text), text, usage: m.usage || {}, model: m.model || 'unknown', cost: costOf(m.model, m.usage, { batch: true }) };
  }
  return { status: 'failed', error: 'the batch ended without an answer for this request' };
}

/** Stop a batch nobody will wait for any longer; already-ended batches are left alone. */
export async function cancelBatch(batch_id) {
  try { await batches().cancel(batch_id); } catch { /* ended, or gone */ }
}
