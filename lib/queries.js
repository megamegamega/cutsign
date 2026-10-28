// Stage `queried`: the hunt-query proposer. For each deep-read P1/P2 story a model reads the public
// story record and proposes the SHAPE of a hunt — including multi-source correlations a template
// library cannot invent. Proposals are published in the agent JSON as `proposed_queries[]`, tier
// `proposed`: candidates, never detections. bluesign's lab validates them and a person admits them.
// Nothing here runs against any SIEM.
//
// The boundary is absolute: inputs are the story's public record only; outputs carry placeholders
// (`index=<key>`, `FROM <key>`), never an index, sourcetype, data stream, host or user name. Every
// proposal passes lib/lint.js or is dropped with the reason recorded; a literal in a query must be
// one the story record prints and must be listed in `params`.

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { callStructured } from './llm.js';
import { ProposalSchema } from './schemas.js';
import { LOG_SOURCE_KEYS, logSourceKeys } from './logsources.js';
import { lintSpl, lintEsql } from './lint.js';

export const SYSTEM_PROMPT = readFileSync(new URL('../prompts/propose.system.md', import.meta.url), 'utf8');
export const PROPOSAL_TIER = 'proposed';
const CAP_FRACTION = 0.8; // past this share of MAX_MONTHLY_USD the proposer runs on the deep tier

const trunc = (s, n) => (String(s || '').length > n ? String(s).slice(0, n) + '…' : String(s || ''));

/** Deep-read, extracted, P1/P2: the stories worth a proposal. */
export const eligible = (s) => !!s.selected && s.status === 'extracted' && (s.priority ?? 3) <= 2;

/** The vocabulary keys the story's own record names (behaviors, guidance, samples), minus `other`. */
export function storyTelemetryKeys({ behaviors = [], guidance = [], samples = [] }) {
  const keys = new Set();
  for (const x of [...behaviors, ...guidance, ...samples]) for (const k of logSourceKeys(x.log_source || x.log_source_guess)) if (k !== 'other') keys.add(k);
  return [...keys];
}

/** The user message: the story record, indexed so `from` can cite it, plus the vocabulary. Nothing fetched live. */
export function buildProposeInput({ story, behaviors = [], guidance = [], samples = [], iocs = [] }) {
  const lines = [];
  lines.push(`<story>\ntitle: ${story.title}\nsummary: ${trunc(story.summary, 1500)}\npriority: P${story.priority ?? 3}${story.priority_reason ? ` — ${trunc(story.priority_reason, 300)}` : ''}`
    + (story.cves?.length ? `\ncves: ${story.cves.join(', ')}` : '') + (story.threat_actor ? `\nactor: ${story.threat_actor}` : '') + (story.malware_family ? `\nmalware: ${story.malware_family}` : '')
    + (story.attack_techniques?.length ? `\nattack: ${story.attack_techniques.join(', ')}` : '') + '\n</story>');
  lines.push('<behaviors>');
  behaviors.forEach((b, i) => lines.push(`[behaviors[${i}]] ${b.attack_technique || ''} ${b.pattern_kind}: parent=${b.parent || '?'} children=${(b.children || []).join(',')} log_source=${b.log_source || '?'} keys=${logSourceKeys(b.log_source).join(',')} ${b.vendor_stated ? 'vendor-stated' : 'inferred'}${b.time_window ? ` window=${b.time_window}` : ''}${b.source_quote_ref ? ` quote: ${trunc(b.source_quote_ref, 200)}` : ''}`));
  lines.push('</behaviors>', '<detection_guidance>');
  guidance.forEach((g, i) => lines.push(`[detection_guidance[${i}]]${g.publisher_tier ? ` tier ${g.publisher_tier}` : ''} log_source=${g.log_source || '?'} keys=${logSourceKeys(g.log_source).join(',')}: ${trunc(g.raw, 1200)}`));
  lines.push('</detection_guidance>', '<evidence_samples>');
  samples.slice(0, 12).forEach((e, i) => lines.push(`[evidence_samples[${i}]] ${e.kind}${e.log_source ? ` (${e.log_source})` : ''}: ${trunc(e.raw, 400)}`));
  lines.push('</evidence_samples>', '<iocs>');
  iocs.slice(0, 60).forEach((x, i) => lines.push(`[iocs[${i}]] ${x.type}: ${x.value_norm || x.value}${x.role ? ` (${x.role})` : ''}`));
  lines.push('</iocs>');
  const ex = story.raw_iocs?.exposure;
  if (ex) lines.push(`<exposure>${trunc(JSON.stringify(ex), 1500)}</exposure>`);
  lines.push(`<vocabulary>${LOG_SOURCE_KEYS.filter((k) => k !== 'other').join(', ')}</vocabulary>`);
  lines.push(`<story_telemetry>${storyTelemetryKeys({ behaviors, guidance, samples }).join(', ') || 'none'}</story_telemetry>`);
  return lines.join('\n');
}

/** A literal is allowed in a query when the story record prints it (case-insensitive). */
export function literalAllower(record) {
  const text = JSON.stringify(record).toLowerCase();
  return (lit) => { const v = String(lit).toLowerCase().replace(/^"|"$/g, ''); return v.length >= 2 && text.includes(v); };
}

const QUOTED = /"((?:[^"\\]|\\.)+)"|'((?:[^'\\]|\\.)+)'/g;
const FIELDISH = /^[a-z_][\w.]*$/i;
/** Quoted literals in the queries that look like values (not placeholders, wildcards or bare field names). */
export function queryLiterals(...queries) {
  const out = new Set();
  for (const q of queries) for (const m of String(q || '').matchAll(QUOTED)) {
    const v = m[1] ?? m[2];
    if (!v || v === '*' || /^<[a-z0-9_]+>$/i.test(v) || /^\*?[\w.-]*\*$/.test(v) && !/[0-9]/.test(v) || (FIELDISH.test(v) && !/[0-9-]/.test(v))) continue;
    out.add(v);
  }
  return [...out];
}

/**
 * Validate, lint and finish the model's proposals. Returns { proposals, dropped: [{ name, reasons }] }.
 * @param record  the story record the input was built from (literal allow-list)
 */
export function finishProposals(raw, { record, model, model_tier, cost }) {
  const allowed = literalAllower(record);
  const list = raw?.proposed_queries || [];
  const share = list.length ? Number((cost / list.length).toFixed(4)) : 0;
  const proposals = []; const dropped = [];
  for (const p of list) {
    const reasons = [];
    const stages = p.stages || [];
    if (!stages.length) reasons.push('no stages');
    for (const st of stages) if (!LOG_SOURCE_KEYS.includes(st.log_source_key) || st.log_source_key === 'other') reasons.push(`stage key not in vocabulary: ${st.log_source_key}`);
    if (p.shape === 'single_source' && stages.length !== 1) reasons.push('single_source needs exactly one stage');
    if (p.shape !== 'single_source' && (stages.length < 2 || !p.join)) reasons.push(`${p.shape} needs two or more stages and a join`);
    if (!String(p.noise_hint || '').trim()) reasons.push('noise_hint required');
    if (!(p.from || []).length) reasons.push('from citations required');
    const ls = lintSpl(p.splunk, { allowed }); if (!ls.ok) reasons.push(...ls.reasons.map((r) => `splunk: ${r}`));
    const le = lintEsql(p.elastic, { allowed }); if (!le.ok) reasons.push(...le.reasons.map((r) => `elastic: ${r}`));
    // every quoted value in the queries must be one the story record prints (the lint catches
    // hosts, IPs, emails and users by shape; this catches everything else, an invented appId included)
    const lits = queryLiterals(p.splunk, p.elastic);
    for (const lit of lits) if (!allowed(lit)) reasons.push(`literal not in the story record: ${lit}`);
    if (reasons.length) { dropped.push({ name: p.name, reasons }); continue; }
    // params: what the model listed, plus any quoted literal in the queries it forgot to list
    const params = {};
    for (const x of p.params || []) if (x?.name) params[x.name] = String(x.value ?? '');
    const have = new Set(Object.values(params));
    let n = 0;
    for (const lit of lits) if (!have.has(lit)) { while (params[`p${++n}`] !== undefined); params[`p${n}`] = lit; }
    proposals.push({
      id: randomUUID(), shape: p.shape, name: String(p.name).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 60),
      hypothesis: p.hypothesis, stages, join: p.join || null, splunk: p.splunk, elastic: p.elastic, params,
      noise_hint: p.noise_hint, from: p.from, confidence: p.confidence,
      tier: PROPOSAL_TIER, model_tier, model, cost_usd: share,
    });
  }
  return { proposals, dropped };
}

/**
 * Propose hunts for one story. Returns { proposals, dropped, skipped, cost, usage, model, model_tier }.
 * `skipped` is set (and no model is called) when the story's telemetry is `other` only or names a
 * single family — correlations across families are the proposer's whole value.
 * @param spent  month-to-date spend; @param cap MAX_MONTHLY_USD — at ≥80% the deep tier is used instead
 */
export async function generateQueries({ story, behaviors = [], guidance = [], samples = [], iocs = [], spent = 0, cap = Infinity }) {
  const keys = storyTelemetryKeys({ behaviors, guidance, samples });
  const skip = (why) => ({ proposals: [], dropped: [], skipped: why, cost: 0, usage: null, model: null, model_tier: null });
  if (!keys.length) return skip('telemetry is other only');
  // one telemetry family is template territory (bluesign's library); the proposer earns its cost
  // only where a hunt has to cross families — issuance → use, exploit → shell, download → execution
  if (keys.length < 2) return skip(`one telemetry family (${keys[0]}); single-source hunts are template territory`);
  const model_tier = cap > 0 && spent >= CAP_FRACTION * cap ? 'deep' : 'propose';
  const record = { story: { title: story.title, summary: story.summary, cves: story.cves, threat_actor: story.threat_actor, malware_family: story.malware_family, exposure: story.raw_iocs?.exposure }, behaviors, guidance, samples, iocs };
  const messages = [{ role: 'user', content: buildProposeInput({ story, behaviors, guidance, samples, iocs }) }];
  const call = () => callStructured({ tier: model_tier, effort: 'high', system: SYSTEM_PROMPT, messages, schema: ProposalSchema, schemaName: 'proposal', maxTokens: 6000 });
  const total = { uncached: 0, cache_read: 0, cache_write: 0, out: 0, cost: 0 };
  const take = (r) => { total.uncached += r.usage.input_tokens || 0; total.cache_read += r.usage.cache_read_input_tokens || 0; total.cache_write += r.usage.cache_creation_input_tokens || 0; total.out += r.usage.output_tokens || 0; total.cost += r.cost || 0; };
  let r = await call(); take(r);
  let parsed = ProposalSchema.safeParse(r.data);
  if (!parsed.success) {
    messages.push({ role: 'assistant', content: r.text }, { role: 'user', content: `The proposals failed validation: ${parsed.error.issues.slice(0, 8).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}. Return the corrected object only.` });
    r = await call(); take(r);
    parsed = ProposalSchema.safeParse(r.data);
    if (!parsed.success) throw new Error('proposals failed validation twice: ' + parsed.error.issues.slice(0, 3).map((i) => i.path.join('.')).join(', '));
  }
  const { proposals, dropped } = finishProposals(parsed.data, { record, model: r.model, model_tier, cost: total.cost });
  const usage = { in: total.uncached + total.cache_read + total.cache_write, out: total.out, uncached: total.uncached, cache_read: total.cache_read, cache_write: total.cache_write };
  return { proposals, dropped, skipped: null, cost: total.cost, usage, model: r.model, model_tier };
}
