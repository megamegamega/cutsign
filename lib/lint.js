// Deterministic query linter. Every proposed hunt (lib/queries.js) passes lintSpl / lintEsql or is
// dropped with the reason recorded; nothing here is advisory. The rules enforce the repo's one rule
// at the query level: the only index form is `index=<key>` (or `index=*`), no literal sourcetype,
// data stream, host, user or email, and only read-only commands. Story literals (a CVE, an appId,
// an IP the sources print) are allowed when the caller's `allowed(literal)` says the story carries
// them; everything else that looks like an identifier is rejected.
//
// Both linters return { ok, reasons[] } and never throw.

const PLACEHOLDER = /^<[a-z0-9_]+>$/i;
const isPlaceholder = (v) => PLACEHOLDER.test(String(v).replace(/^"|"$/g, ''));

// Read-only SPL commands a proposal may use. Anything else is rejected — lookup included.
export const SPL_ALLOW = new Set(['search', 'where', 'stats', 'eval', 'rename', 'fields', 'table', 'rex', 'regex',
  'tstats', 'from', 'head', 'sort', 'dedup', 'join', 'append', 'transaction', 'bin', 'timechart']);
// Never, even inside a subsearch or a quoted string
const SPL_DENY = /\|\s*(delete|outputlookup|sendemail|script|run|lookup|inputlookup|collect|outputcsv|rest|map|sendalert|savedsearch|runshellscript)\b/i;

// Read-only ES|QL source and processing commands
export const ESQL_ALLOW = new Set(['FROM', 'WHERE', 'STATS', 'EVAL', 'KEEP', 'DROP', 'RENAME', 'SORT', 'LIMIT', 'DISSECT', 'GROK',
  'MV_EXPAND', 'INLINESTATS', 'LOOKUP', 'CHANGE_POINT', 'SAMPLE']);

// Top-level domains that make a dotted token a hostname rather than an ECS field name
const TLD = /\.(com|net|org|io|gov|mil|edu|co|uk|de|ru|cn|info|biz|xyz|top|local|corp|internal|intranet|lan|cloud|app|dev|me|us|ca|eu|fr|nl|jp|kr|br|in|au|tv|cc|ws|pw|su|onion|int|ch|se|no|fi|pl|it|es)$/i;
const HOSTLIKE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g;
const USERFIELD = /\b(user|username|user_name|src_user|dest_user|userprincipalname|upn|samaccountname|account_name|user\.name|source\.user\.name|user\.email)\s*(?:==?|!=)\s*"?([A-Za-z0-9][\w.@-]*)"?/gi;
const HOSTFIELD = /\b(host|hostname|host\.name|host\.hostname|dvc|computername|dest_host|src_host)\s*(?:==?|!=)\s*"?([A-Za-z0-9][\w.-]*)"?/gi;

/** Rules shared by both languages: identifiers that may only come from the story. */
function literalChecks(q, allowed, reasons) {
  const ok = (v) => isPlaceholder(v) || v === '*' || allowed(v);
  for (const m of q.matchAll(EMAIL)) if (!allowed(m[0])) reasons.push(`email literal: ${m[0]}`);
  for (const m of q.matchAll(IPV4)) if (!allowed(m[0])) reasons.push(`IP literal not in the story: ${m[0]}`);
  for (const m of q.matchAll(HOSTLIKE)) if (TLD.test(m[0]) && !allowed(m[0])) reasons.push(`hostname literal not in the story: ${m[0]}`);
  for (const m of q.matchAll(USERFIELD)) if (!ok(m[2])) reasons.push(`username literal: ${m[1]}=${m[2]}`);
  for (const m of q.matchAll(HOSTFIELD)) if (!ok(m[2])) reasons.push(`host literal: ${m[1]}=${m[2]}`);
}

/** Pipe-separated command names at the top level and inside every [subsearch]; quoted strings ignored. */
function splCommands(text) {
  const out = []; // [{ cmd, first }] — first: the leading segment of a (sub)search, where bare terms mean `search`
  const walk = (t) => {
    let depth = 0; let cur = ''; let sub = ''; const segs = [];
    for (const ch of t) {
      if (ch === '[') { if (depth++ === 0) { sub = ''; continue; } }
      else if (ch === ']') { if (--depth === 0) { walk(sub); continue; } }
      if (depth > 0) { sub += ch; continue; }
      if (ch === '|') { segs.push(cur); cur = ''; } else cur += ch;
    }
    segs.push(cur);
    segs.forEach((s, i) => { const m = s.trim().match(/^([A-Za-z_]+)/); if (m) out.push({ cmd: m[1].toLowerCase(), first: i === 0 }); });
  };
  walk(text.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''"));
  return out;
}

/**
 * Lint one SPL search. @param allowed (literal) => boolean — does the story record carry it?
 */
export function lintSpl(q, { allowed = () => false } = {}) {
  const reasons = [];
  const text = String(q || '');
  if (!text.trim()) return { ok: false, reasons: ['empty query'] };
  if (SPL_DENY.test(text)) reasons.push(`command not allowed: ${text.match(SPL_DENY)[1]}`);
  for (const m of text.matchAll(/\bindex\s*=\s*("?)([^\s"|)]+)\1/gi)) {
    if (m[2] !== '*' && !isPlaceholder(m[2])) reasons.push(`literal index name: ${m[2]} (use index=<key> or index=*)`);
  }
  if (/\bindex\s+in\s*\(/i.test(text)) reasons.push('index IN (...) is not allowed; one index=<key> per stage');
  for (const m of text.matchAll(/\b(sourcetype|source)\s*=\s*("?)([^\s"|)]+)\2/gi)) {
    if (m[3] !== '*' && !isPlaceholder(m[3])) reasons.push(`literal ${m[1]}: ${m[3]}`);
  }
  for (const { cmd, first } of splCommands(text)) {
    if (first && !SPL_ALLOW.has(cmd)) continue; // bare search terms
    if (!SPL_ALLOW.has(cmd)) reasons.push(`command not allowed: ${cmd}`);
  }
  literalChecks(text, allowed, reasons);
  return { ok: reasons.length === 0, reasons: [...new Set(reasons)] };
}

/** Lint one ES|QL query: FROM <key> placeholders only, read-only commands, no identifiers from outside the story. */
export function lintEsql(q, { allowed = () => false } = {}) {
  const reasons = [];
  const text = String(q || '');
  if (!text.trim()) return { ok: false, reasons: ['empty query'] };
  const stripped = text.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/`[^`]*`/g, '``');
  const segs = stripped.split('|').map((s) => s.trim()).filter(Boolean);
  if (!/^FROM\b/i.test(segs[0] || '')) reasons.push('query must start with FROM <key>');
  segs.forEach((s) => {
    const cmd = (s.match(/^([A-Za-z_]+)/) || [])[1]?.toUpperCase();
    if (!cmd || !ESQL_ALLOW.has(cmd)) reasons.push(`command not allowed: ${cmd || s.slice(0, 20)}`);
    if (cmd === 'LOOKUP' && !/^LOOKUP\s+JOIN\b/i.test(s)) reasons.push('only LOOKUP JOIN is allowed');
    if (cmd === 'FROM') {
      const list = s.replace(/^FROM\s+/i, '').replace(/\s+METADATA\b[\s\S]*$/i, '');
      for (const src of list.split(',').map((x) => x.trim()).filter(Boolean)) if (!isPlaceholder(src)) reasons.push(`FROM must use a <key> placeholder, not ${src}`);
    }
  });
  for (const m of text.matchAll(/\b(_index|data_stream\.(?:dataset|namespace|type)|event\.dataset|sourcetype)\s*(?:==|IN|LIKE|RLIKE)\s*\(?\s*"?([^\s")]+)"?/gi)) {
    if (!isPlaceholder(m[2]) && m[2] !== '*') reasons.push(`literal ${m[1]}: ${m[2]}`);
  }
  literalChecks(text, allowed, reasons);
  return { ok: reasons.length === 0, reasons: [...new Set(reasons)] };
}
