// AI-generated verdict-card drafts shaped on the DAIR model (Joshua Wright, Dynamic Incident
// Response: Detect, Verify and Triage, the Scope/Contain/Eradicate/Recover loop, Debrief). One
// Opus call assembles a draft from a story thread's stored summaries, behaviors, published guidance,
// evidence samples, IoCs and sources; when the thread's evidence changes, the draft is revised from
// the prior version with a change list. Drafts are scrubbed with the repo's hygiene rules, stored
// (card_drafts) and shown at /?view=draft&id=… behind an "AI-generated, unreviewed" banner.
// Promotion to public/cards/ is a human edit.

import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { callStructured } from './llm.js';

export const SYSTEM_PROMPT = readFileSync(new URL('../prompts/carddraft.system.md', import.meta.url), 'utf8');
export const DAIR_URL = 'https://dynamicincidentresponse.com/';

const nstr = z.string().nullable();
const strs = (max) => z.array(z.string()).max(max);
export const DraftSchema = z.object({
  title: z.string().max(110).describe('Headline; claim outcomes only as strongly as the sources confirm'),
  verdict: z.string().describe('One or two sentences: what it is and what to do today'),
  lane: z.string().max(40).describe('Patch now | Patch | Hunt / IR | Hunt + harden | Prepare, or a short combination'),
  confidence: z.enum(['low', 'medium', 'high']),
  confidence_reason: z.string(),
  what_happened: z.array(z.string()).min(2).max(6).describe('Bullets, each ending with its [S#] reference'),
  timeline: z.array(z.object({ date: z.string(), event: z.string(), source: nstr })).max(12),
  detect: z.array(z.object({
    name: z.string(), log_source: z.string(),
    spl: z.string().describe('One Splunk search; index=* only'),
    hit_means: z.string(),
  })).max(4),
  verify: strs(6).describe('How to confirm a hit is real; known benign look-alikes'),
  triage: z.object({ priority: z.enum(['P1', 'P2', 'P3']), why: z.string() }),
  scope: z.object({
    affected: strs(8), only_if: strs(8), not_affected_if: strs(8), fixed_in: nstr,
    enumerate: strs(6).describe('What to enumerate to learn the full extent'),
  }),
  contain: strs(8).describe('Ordered; stop new harm first; say what cannot be undone'),
  eradicate: strs(6),
  recover: strs(6),
  reenter_when: strs(6).describe('Concrete triggers that send the team back to Scope'),
  debrief: strs(6).describe('What to record; gaps the sources leave'),
  coverage_checks: z.array(z.object({ category: z.string(), check: z.string() })).max(6)
    .describe('What the analyst should look up per product category; never a coverage claim'),
  open_questions: strs(8),
  changes_since_prior: strs(10).describe('Empty for a first draft'),
  sources: z.array(z.object({ ref: z.string(), url: z.string(), publisher: nstr })),
});

const trunc = (s, n) => (String(s || '').length > n ? String(s).slice(0, n) + '…' : String(s || ''));

/** The user message: the thread's stored facts, numbered sources, the prior draft when revising. Nothing fetched live. */
export function buildDraftInput({ story, thread, data, score, reasons, prior = null, changes = [] }) {
  const sources = []; const refOf = new Map();
  const ref = (url, publisher) => {
    if (!url) return null;
    if (!refOf.has(url)) { refOf.set(url, `S${sources.length + 1}`); sources.push({ ref: refOf.get(url), url, publisher: publisher || null }); }
    return refOf.get(url);
  };
  for (const r of thread) for (const s of r.sources || []) ref(s.url, s.publisher);
  for (const r of thread) for (const u of r.source_urls || []) ref(u, null);
  for (const g of story.guidance || []) ref(g.url, null);

  const lines = [];
  lines.push(`<context>Brief date ${data.date}. Hype score ${score}: ${reasons.join('; ')}. The thread below is oldest first; the last story is today's.</context>`);
  if (prior) {
    lines.push(`<prior_draft version="${prior.version || 1}">${trunc(JSON.stringify(prior.draft), 12000)}</prior_draft>`);
    lines.push(`<changes>${changes.length ? changes.join('; ') : 'evidence changed'}</changes>`);
  }
  for (const r of thread) {
    const day = r.brief_date || r.day || (r === story ? data.date : String(r.created_at || '').slice(0, 10));
    lines.push(`<story date="${day}"${r === story ? ' today="true"' : ''}>`);
    lines.push(`title: ${r.title}`);
    if (r.summary) lines.push(`summary: ${trunc(r.summary, 1200)}`);
    if (r.priority) lines.push(`priority: P${r.priority}${r.priority_reason ? ` — ${trunc(r.priority_reason, 300)}` : ''}`);
    if (r.cves?.length) lines.push(`cves: ${r.cves.join(', ')}`);
    if (r.threat_actor) lines.push(`actor: ${r.threat_actor}`);
    if (r.malware_family) lines.push(`malware: ${r.malware_family}`);
    const srcs = [...(r.sources || []).map((s) => s.url), ...(r.source_urls || [])].filter(Boolean);
    if (srcs.length) lines.push(`sources: ${[...new Set(srcs)].map((u) => `[${refOf.get(u)}] ${u}`).join(' ')}`);
    lines.push('</story>');
  }
  const ex = story.raw_iocs?.exposure;
  if (ex) lines.push(`<exposure>${trunc(JSON.stringify(ex), 1500)}</exposure>`);
  const behs = story.behaviors || [];
  if (behs.length) {
    lines.push('<behaviors>');
    for (const b of behs) lines.push(`- ${b.attack_technique || ''} ${b.pattern_kind}: parent=${b.parent || '?'} children=${(b.children || []).join(',')} log_source=${b.log_source || '?'} ${b.vendor_stated ? 'vendor-stated' : 'inferred'}${b.source_quote_ref ? ` (${trunc(b.source_quote_ref, 160)})` : ''}`);
    lines.push('</behaviors>');
  }
  const guid = story.guidance || [];
  if (guid.length) {
    lines.push('<published_guidance>');
    for (const g of guid) lines.push(`[${refOf.get(g.url) || '?'}]${g.publisher_tier ? ` tier ${g.publisher_tier}` : ''}${g.log_source ? ` ${g.log_source}` : ''}: ${trunc(g.raw, 1200)}`);
    lines.push('</published_guidance>');
  }
  const samples = (story.samples || []).slice(0, 12);
  if (samples.length) {
    lines.push('<evidence_samples>');
    for (const e of samples) lines.push(`- ${e.kind}${e.log_source ? ` (${e.log_source})` : ''}: ${trunc(e.raw, 400)}`);
    lines.push('</evidence_samples>');
  }
  const iocs = [...(story.newIocs || []), ...(story.repeatIocs || [])].slice(0, 60);
  if (iocs.length) lines.push(`<iocs>${iocs.map((i) => `${i.type}:${i.value_norm}`).join(' ')}</iocs>`);
  lines.push(`<sources>${sources.map((s) => `[${s.ref}] ${s.url}${s.publisher ? ` (${s.publisher})` : ''}`).join('\n')}</sources>`);
  return { text: lines.join('\n'), sources };
}

// The repo's hygiene rules, applied to machine text before it is stored.
const INTERNAL_HOST = /\b[a-z0-9-]+\.(corp|internal|intranet|lan)(\.[a-z0-9-]+)+\b/gi;
const LISTS = ['what_happened', 'verify', 'contain', 'eradicate', 'recover', 'reenter_when', 'debrief', 'open_questions', 'changes_since_prior'];
export function scrub(draft) {
  const fixSpl = (s) => String(s).replace(/\bindex\s*=\s*(?!\*)[a-z_][\w-]*/gi, 'index=*')
    .replace(/\b(sourcetype)\s*=\s*"?([a-z]+):([a-z][\w:]*)"?/gi, '$1=<$2:$3>')
    .replace(INTERNAL_HOST, '<host>');
  const fixText = (s) => String(s).replace(INTERNAL_HOST, '<host>');
  const out = structuredClone(draft);
  out.detect = (out.detect || []).map((h) => ({ ...h, spl: fixSpl(h.spl), hit_means: fixText(h.hit_means), log_source: fixText(h.log_source) }));
  for (const k of LISTS) out[k] = (out[k] || []).map(fixText);
  if (out.scope) for (const k of ['affected', 'only_if', 'not_affected_if', 'enumerate']) out.scope[k] = (out.scope[k] || []).map(fixText);
  out.verdict = fixText(out.verdict); out.title = fixText(out.title);
  return out;
}

/**
 * One deep call, validated against DraftSchema, scrubbed. `prior` is the draft row being revised
 * (its version and draft JSON) and `changes` the evidence deltas, both optional.
 * Throws when the model cannot produce a valid draft after one correction turn.
 */
export async function draftCard({ story, thread, data, score, reasons, prior = null, changes = [] }) {
  const input = buildDraftInput({ story, thread, data, score, reasons, prior, changes });
  const messages = [{ role: 'user', content: input.text }];
  const call = () => callStructured({ tier: 'deep', effort: 'medium', system: SYSTEM_PROMPT, messages, schema: DraftSchema, schemaName: 'card_draft', maxTokens: 10000 });
  let r = await call();
  let cost = r.cost || 0; let parsed = DraftSchema.safeParse(r.data);
  if (!parsed.success) {
    messages.push({ role: 'assistant', content: r.text }, { role: 'user', content: `The draft failed validation: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}. Return the corrected object only.` });
    r = await call(); cost += r.cost || 0; parsed = DraftSchema.safeParse(r.data);
    if (!parsed.success) throw new Error('card draft failed validation twice: ' + parsed.error.issues.slice(0, 3).map((i) => i.path.join('.')).join(', '));
  }
  const draft = scrub(parsed.data);
  // keep only sources the input actually offered (the model may not invent URLs)
  const offered = new Set(input.sources.map((s) => s.url));
  draft.sources = draft.sources.filter((s) => offered.has(s.url));
  for (const s of input.sources) if (!draft.sources.some((x) => x.url === s.url)) draft.sources.push(s);
  if (!prior) draft.changes_since_prior = [];
  return { draft, cost, model: r.model };
}

// ---- web rendering (api/page.js wraps this in the site chrome) ------------------------------

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeHref = (u) => (/^https?:\/\//i.test(String(u || '')) ? esc(u) : '');

/** Inner HTML for one draft row ({ id, created_at, version, score, reasons, draft, status, surfaced_at, supersedes }). */
export function draftBody(row) {
  const d = row.draft;
  const srcLink = (ref) => { const s = (d.sources || []).find((x) => x.ref === ref); return s && safeHref(s.url) ? `<a href="${safeHref(s.url)}">${esc(ref)}</a>` : esc(ref); };
  const withRefs = (t) => esc(t).replace(/\[(S\d+)\]/g, (m, r) => `[${srcLink(r)}]`);
  const list = (arr, empty = 'None stated by the sources.') => (arr?.length ? `<ul>${arr.map((x) => `<li>${withRefs(x)}</li>`).join('')}</ul>` : `<p class="s">${esc(empty)}</p>`);
  const v = row.version || 1;
  const parts = [];
  parts.push(`<div class="exec" style="border-color:var(--bad)"><b>AI-generated draft, unreviewed.</b> Version ${v}, written by a model from the stored public sources on ${esc(String(row.created_at).slice(0, 10))}; hype score ${esc(String(row.score))}. It is regenerated when the evidence changes and becomes a verdict card only after a person has checked every line and published it under <code>/cards/</code>. Status: ${esc(row.status || 'draft')}.${row.supersedes ? ` Supersedes <a href="/?view=draft&id=${esc(row.supersedes)}">version ${v - 1}</a>.` : ''}</div>`);
  parts.push(`<div class="card"><div class="chead"><h3>${esc(d.title)}</h3></div><div><span class="c">${esc(d.lane)}</span><span class="c">${esc(d.triage?.priority || '')}</span><span class="c">confidence: ${esc(d.confidence)}</span>${(row.reasons || []).map((r) => `<span class="c">${esc(r)}</span>`).join('')}</div>`
    + `<p style="margin:8px 0"><b>${withRefs(d.verdict)}</b></p><p class="s"><b>Triage:</b> ${withRefs(d.triage?.why || '')}</p><p class="s">${esc(d.confidence_reason)}</p></div>`);
  if (d.changes_since_prior?.length) parts.push(`<h3>Changed since version ${v - 1}</h3>${list(d.changes_since_prior)}`);
  parts.push(`<h3>What happened</h3>${list(d.what_happened)}`);
  if (d.timeline?.length) parts.push(`<h3>Timeline</h3><table>${d.timeline.map((t) => `<tr><td>${esc(t.date)}</td><td>${withRefs(t.event)}${t.source ? ` ${srcLink(t.source)}` : ''}</td></tr>`).join('')}</table>`);
  parts.push(`<h3>Detect</h3>` + (d.detect?.length ? d.detect.map((h) => `<p class="k">${esc(h.name)} <span class="s">· ${esc(h.log_source)}</span></p><pre>${esc(h.spl)}</pre><p class="s">A hit means: ${withRefs(h.hit_means)}</p>`).join('') : '<p class="s">No hunt the sources support yet.</p>'));
  parts.push(`<h3>Verify</h3>${list(d.verify)}`);
  parts.push(`<h3>Scope</h3><p class="k">Affected</p>${list(d.scope?.affected)}<p class="k">Only if</p>${list(d.scope?.only_if)}<p class="k">Not affected if</p>${list(d.scope?.not_affected_if)}${d.scope?.fixed_in ? `<p class="s">Fixed in: ${esc(d.scope.fixed_in)}</p>` : ''}<p class="k">Enumerate</p>${list(d.scope?.enumerate)}`);
  parts.push(`<h3>Contain</h3>${list(d.contain)}`);
  parts.push(`<h3>Eradicate</h3>${list(d.eradicate)}`);
  parts.push(`<h3>Recover</h3>${list(d.recover)}`);
  parts.push(`<h3>Re-enter the loop when</h3>${list(d.reenter_when)}`);
  parts.push(`<h3>Debrief</h3>${list(d.debrief)}`);
  parts.push(`<h3>Detection coverage, to check</h3>${d.coverage_checks?.length ? `<table>${d.coverage_checks.map((c) => `<tr><td>${esc(c.category)}</td><td>${esc(c.check)}</td></tr>`).join('')}</table>` : '<p class="s">None listed.</p>'}<p class="s">The draft never claims coverage; the analyst fills this from vendor sources at promotion.</p>`);
  parts.push(`<h3>Open questions</h3>${list(d.open_questions, 'None.')}`);
  parts.push(`<h3>Sources</h3><ul class="s">${(d.sources || []).map((s) => `<li>[${esc(s.ref)}] ${safeHref(s.url) ? `<a href="${safeHref(s.url)}">${esc(s.url)}</a>` : esc(s.url)}${s.publisher ? ` · ${esc(s.publisher)}` : ''}</li>`).join('')}</ul>`);
  parts.push(`<p class="s" style="margin-top:28px">Public OSINT only. AI-generated by the pipeline; structure follows the DAIR model from <a href="${DAIR_URL}">Dynamic Incident Response</a> (Joshua Wright). Promotion to a verdict card is a human edit to the repository.</p>`);
  return parts.join('\n');
}
