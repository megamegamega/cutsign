// Polite fetcher for public sources: 10 s timeout, 1 MB cap, ≤3 redirects, honest UA, robots.txt
// respected, HTML → readable text. Never throws for a bad URL — returns an outcome instead, so one
// dead link can't fail a run.
//
// Also hosts the prompt-injection screen: fetched text is UNTRUSTED. A page that talks to an AI
// ("ignore previous instructions", "you are an AI…") is flagged suspicious and excluded from extraction.

import { createHash } from 'node:crypto';
import { parse as parseHtml } from 'node-html-parser';

export const USER_AGENT = 'Cutsign/0.1 (personal threat-intel reader; contact dispatch@liberto.us)';
const TIMEOUT_MS = 10_000;
const MAX_BYTES = 1_000_000;
const MAX_REDIRECTS = 3;
export const TEXT_CAP = 60_000; // chars stored per source

// Primary-source hosts: a news page linking to one of these gets one hop followed.
export const PRIMARY_HOSTS = [
  'unit42.paloaltonetworks.com', 'security.paloaltonetworks.com', 'cloud.google.com', 'mandiant.com',
  'microsoft.com', 'msrc.microsoft.com', 'cisa.gov', 'nvd.nist.gov', 'research.checkpoint.com',
  'blog.talosintelligence.com', 'crowdstrike.com', 'sentinelone.com', 'elastic.co', 'huntress.com',
  'rapid7.com', 'labs.watchtowr.com', 'news.sophos.com', 'welivesecurity.com', 'proofpoint.com',
  'trendmicro.com', 'fortiguard.com', 'fortinet.com', 'support.citrix.com', 'citrix.com',
  'forescout.com', 'volexity.com', 'redcanary.com', 'securelist.com', 'arcticwolf.com',
  'github.com', 'gist.github.com', 'ivanti.com', 'blog.sekoia.io', 'objective-see.org', 'zscaler.com',
  'cert.gov.ua', 'ncsc.gov.uk', 'cyber.gov.au', 'jpcert.or.jp', 'bsi.bund.de', 'cert.ssi.gouv.fr',
  'censys.com', 'greynoise.io', 'shadowserver.org', 'citizenlab.ca', 'socradar.io', 'wiz.io',
  'datadoghq.com', 'aws.amazon.com', 'akamai.com', 'cloudflare.com', 'trustwave.com', 'eset.com',
];

const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; } };
export const isPrimary = (u) => { const h = hostOf(u); return PRIMARY_HOSTS.some((p) => h === p || h.endsWith('.' + p)); };

// ---- prompt-injection screen -------------------------------------------------

const INJECTION_PATTERNS = [
  /\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?|context)/i,
  /\bdisregard\s+(all\s+|the\s+)?(previous|prior|above|system)\b/i,
  /\byou\s+are\s+(now\s+)?(an?\s+)?(ai|a\.i\.|assistant|language model|llm|chatbot|chatgpt|claude|gpt)\b/i,
  /\b(as\s+an\s+ai|ai\s+assistant)\s*[,:]?\s+(you\s+)?(must|should|will)\b/i,
  /\boutput\s+the\s+following\b/i,
  /\b(new|updated)\s+instructions\s*:/i,
  /<\/?\s*(system|instructions?|assistant)\s*>/i,
  /\[\/?INST\]/,
  /\bpretend\s+(to\s+be|you\s+are)\b|\brole-?play\s+as\b/i,
];

/** Returns the matched phrase if the text contains AI-directed instruction-shaped content. */
export function injectionMatch(text) {
  for (const re of INJECTION_PATTERNS) { const m = String(text || '').match(re); if (m) return m[0]; }
  return null;
}

// ---- robots.txt --------------------------------------------------------------

const robotsCache = new Map();
async function robotsAllows(url, fetchImpl) {
  const u = new URL(url);
  if (!robotsCache.has(u.origin)) {
    let rules = [];
    try {
      const r = await fetchImpl(`${u.origin}/robots.txt`, { headers: { 'User-Agent': USER_AGENT }, signal: AbortSignal.timeout(5000) });
      if (r.ok) rules = parseRobots(await r.text());
    } catch { /* unreachable robots.txt → allow */ }
    robotsCache.set(u.origin, rules);
  }
  const path = u.pathname + u.search;
  // longest matching rule wins (Allow beats Disallow on ties), per RFC 9309
  let best = null;
  for (const r of robotsCache.get(u.origin)) {
    if (r.path && path.startsWith(r.path) && (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow))) best = r;
  }
  return !best || best.allow;
}

export function parseRobots(txt) {
  const groups = []; let cur = null; let lastWasAgent = false;
  for (const raw of txt.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const m = line.match(/^([a-z-]+)\s*:\s*(.*)$/i);
    if (!m) continue;
    const [, k, v] = m; const key = k.toLowerCase();
    if (key === 'user-agent') {
      if (!lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(v.toLowerCase()); lastWasAgent = true;
    } else {
      lastWasAgent = false;
      if (cur && (key === 'allow' || key === 'disallow')) cur.rules.push({ allow: key === 'allow', path: v });
    }
  }
  const mine = groups.filter((g) => g.agents.some((a) => a !== '*' && 'cutsign'.includes(a)));
  return (mine.length ? mine : groups.filter((g) => g.agents.includes('*'))).flatMap((g) => g.rules);
}

// ---- HTML → text -------------------------------------------------------------

const STRIP = 'script,style,noscript,nav,header,footer,aside,form,svg,iframe,button,figure.ad,[role=navigation],.share,.social,.related,.newsletter,.comments';

export function htmlToText(html, baseUrl) {
  const root = parseHtml(html, { blockTextElements: { script: false, style: false, noscript: false, pre: true, code: true } });
  const meta = (sel) => root.querySelector(sel)?.getAttribute('content');
  const published = meta('meta[property="article:published_time"]') || meta('meta[name="date"]')
    || meta('meta[itemprop="datePublished"]') || root.querySelector('time[datetime]')?.getAttribute('datetime') || null;
  const publisher = meta('meta[property="og:site_name"]') || hostOf(baseUrl);
  for (const el of root.querySelectorAll(STRIP)) el.remove();
  const main = root.querySelector('article') || root.querySelector('main') || root.querySelector('[role=main]') || root.querySelector('body') || root;
  const links = [];
  for (const a of main.querySelectorAll('a[href]')) {
    try { links.push(new URL(a.getAttribute('href'), baseUrl).toString()); } catch { /* skip */ }
  }
  // keep <pre>/<code> blocks verbatim and fenced — they carry the printed evidence samples
  for (const pre of main.querySelectorAll('pre')) pre.replaceWith(`\n\`\`\`\n${pre.text.trim()}\n\`\`\`\n`);
  const text = main.structuredText.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const d = published ? new Date(published) : null;
  return { text, links: [...new Set(links)], publisher, publishedAt: d && !isNaN(d) ? d.toISOString().slice(0, 10) : null };
}

// ---- fetch -------------------------------------------------------------------

async function readCapped(res) {
  const reader = res.body?.getReader();
  if (!reader) return { buf: Buffer.alloc(0), truncated: false };
  const chunks = []; let n = 0; let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); n += value.length;
    if (n > MAX_BYTES) { truncated = true; await reader.cancel().catch(() => {}); break; }
  }
  return { buf: Buffer.concat(chunks).subarray(0, MAX_BYTES), truncated };
}

/**
 * Fetch one URL. Returns a `sources` row (always — failures are rows with outcome != 'ok').
 * Pass `fetchImpl` in tests.
 */
export async function fetchSource(url, { fetchImpl = fetch } = {}) {
  const row = { url, fetched_at: new Date().toISOString(), status: 0, outcome: 'error', error: null,
    final_url: null, content_hash: null, clean_text: null, publisher: hostOf(url), published_at: null,
    suspicious: false, suspicious_reason: null, links: [] };
  try {
    if (!(await robotsAllows(url, fetchImpl))) return { ...row, outcome: 'robots', error: 'disallowed by robots.txt' };
    let current = url; let res;
    for (let hop = 0; ; hop++) {
      res = await fetchImpl(current, {
        redirect: 'manual',
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        if (hop >= MAX_REDIRECTS) return { ...row, status: res.status, outcome: 'http_error', error: 'too many redirects' };
        current = new URL(res.headers.get('location'), current).toString();
        continue;
      }
      break;
    }
    row.status = res.status; row.final_url = current;
    if (!res.ok) { await res.body?.cancel?.().catch(() => {}); return { ...row, outcome: 'http_error', error: `HTTP ${res.status}` }; }
    const ctype = (res.headers.get('content-type') || '').toLowerCase();
    if (!/html|text\/plain|xml|json/.test(ctype) && ctype) {
      await res.body?.cancel?.().catch(() => {});
      return { ...row, outcome: 'unsupported', error: `content-type ${ctype.split(';')[0]}` };
    }
    const { buf, truncated } = await readCapped(res);
    const body = buf.toString('utf8');
    let parsed = { text: body, links: [], publisher: row.publisher, publishedAt: null };
    if (/html|xml/.test(ctype) || /^\s*</.test(body)) parsed = htmlToText(body, current);
    const text = parsed.text.slice(0, TEXT_CAP);
    const inj = injectionMatch(text);
    return {
      ...row,
      outcome: truncated ? 'too_large' : 'ok',
      error: truncated ? `truncated at ${MAX_BYTES} bytes` : null,
      content_hash: createHash('sha256').update(text).digest('hex'),
      clean_text: text,
      publisher: parsed.publisher,
      published_at: parsed.publishedAt,
      links: parsed.links.slice(0, 300),
      suspicious: !!inj,
      suspicious_reason: inj ? `instruction-shaped text: "${inj.slice(0, 80)}"` : null,
    };
  } catch (e) {
    const timeout = e?.name === 'TimeoutError' || e?.name === 'AbortError';
    return { ...row, outcome: timeout ? 'timeout' : 'error', error: String(e?.message || e).slice(0, 300) };
  }
}

/** Usable for extraction: fetched OK (or truncated but readable) and not flagged. */
export const usable = (s) => s && (s.outcome === 'ok' || s.outcome === 'too_large') && !s.suspicious && s.clean_text;

export function _resetRobotsCache() { robotsCache.clear(); }
