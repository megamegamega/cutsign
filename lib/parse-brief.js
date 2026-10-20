// MIME → clean text + per-item stories + cleaned URLs.
//
// the sender's brief is a structured list: <h2> section headings, each followed by a <ul> of items,
// each item "<b>[Severity] Label:</b> text … <a>Source</a> (also: <a>…</a>)". So stories are split
// deterministically here — no LLM call for clustering. Two formats exist:
//   • current ("[PIPELINE]", brief@example.test): HTML h2/ul/li
//   • older (briefs@example.test): markdown-ish text, "## Section" + "* item … Source: [X](url)"
// The HTML path is tried first; the text path is the fallback.

import PostalMime from 'postal-mime';
import { parse as parseHtml } from 'node-html-parser';

// Sections that are never stories.
const SKIP_SECTIONS = /^(top things to know|feed health|feed issues)/i;
const SEVERITY_RE = /^\s*\[(critical|high|medium|low)\]\s*/i;

export async function parseMime(raw) {
  const email = await PostalMime.parse(raw);
  return {
    messageId: (email.messageId || '').trim(),
    from: (email.from?.address || '').toLowerCase(),
    subject: email.subject || '',
    date: email.date || null,
    html: email.html || '',
    text: email.text || '',
  };
}

/** "Cyber Threat Brief — 2026-10-20" → "2026-10-20" (null if absent). */
export function briefDateFromSubject(subject) {
  const m = String(subject || '').match(/(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
}

export const isTestBrief = (subject) => /\[test\]/i.test(subject || '');

// ---- URL cleaning ----------------------------------------------------------

const TRACKING_PARAMS = /^(utm_[a-z]+|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|oly_[a-z]+|vero_[a-z]+|ref_src|cmpid|sr_share)$/i;

/** Unwrap SafeLinks / Proofpoint / Google redirect wrappers, drop tracking params and fragments. */
export function cleanUrl(input) {
  let s = String(input || '').trim();
  for (let i = 0; i < 3; i++) {                      // wrappers can nest
    let u;
    try { u = new URL(s); } catch { return null; }
    const host = u.hostname.toLowerCase();
    if (host.endsWith('safelinks.protection.outlook.com') && u.searchParams.get('url')) { s = u.searchParams.get('url'); continue; }
    if (host === 'urldefense.com' && u.pathname.startsWith('/v3/__')) {
      s = decodeURIComponent(u.pathname.slice('/v3/__'.length).split('__;')[0]); continue;
    }
    if (host === 'urldefense.proofpoint.com' && u.searchParams.get('u')) {
      s = decodeURIComponent(u.searchParams.get('u').replace(/-/g, '%').replace(/_/g, '/')); continue;
    }
    if ((host === 'www.google.com' || host === 'google.com') && u.pathname === '/url' && (u.searchParams.get('q') || u.searchParams.get('url'))) {
      s = u.searchParams.get('q') || u.searchParams.get('url'); continue;
    }
    break;
  }
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  for (const k of [...u.searchParams.keys()]) if (TRACKING_PARAMS.test(k)) u.searchParams.delete(k);
  u.hash = '';
  return u.toString();
}

const uniq = (a) => [...new Set(a.filter(Boolean))];

// ---- item parsing ----------------------------------------------------------

function itemFrom(section, rawLabel, text, urls) {
  let label = rawLabel.replace(/:\s*$/, '').trim();
  let severity = null;
  const m = label.match(SEVERITY_RE);
  if (m) { severity = m[1][0].toUpperCase() + m[1].slice(1).toLowerCase(); label = label.replace(SEVERITY_RE, ''); }
  return { section, severity, label, text: text.replace(/\s+/g, ' ').trim(), urls: uniq(urls.map(cleanUrl)) };
}

function parseHtmlItems(html) {
  const root = parseHtml(html);
  const items = [];
  for (const h2 of root.querySelectorAll('h2')) {
    const section = h2.text.trim();
    if (SKIP_SECTIONS.test(section)) continue;
    // the <ul> that follows this heading (skipping whitespace/text nodes)
    let el = h2.nextElementSibling;
    while (el && el.tagName !== 'UL' && el.tagName !== 'H2') el = el.nextElementSibling;
    if (!el || el.tagName !== 'UL') continue;
    for (const li of el.querySelectorAll('li')) {
      const b = li.querySelector('b, strong');
      const urls = li.querySelectorAll('a').map((a) => a.getAttribute('href'));
      items.push(itemFrom(section, b ? b.text : '', li.text, urls));
    }
  }
  return items;
}

function parseTextItems(text) {
  const items = [];
  let section = null;
  for (const line of String(text).split(/\r?\n/)) {
    const h = line.match(/^\s*#{2,3}\s+(.*)$/);
    if (h) { section = h[1].trim(); continue; }
    const b = line.match(/^\s*[*\-•]\s+(.*)$/);
    if (!b || !section || SKIP_SECTIONS.test(section)) continue;
    const body = b[1];
    const urls = [...body.matchAll(/\]\((https?:\/\/[^)\s]+)\)/g)].map((x) => x[1])
      .concat([...body.matchAll(/(?<!\()\bhttps?:\/\/[^\s)<>\]]+/g)].map((x) => x[0]));
    const plain = body.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/\*/g, '');
    const label = (plain.match(/^([^:.]{3,120}):/) || [])[1] || plain.slice(0, 80);
    items.push(itemFrom(section, label, plain, urls));
  }
  return items;
}

/** Clean text for storage: html→text (or the text part), signatures and quoted replies stripped. */
function toCleanText(html, text) {
  let t = html ? parseHtml(html).structuredText : String(text || '');
  t = t.split(/\n-- \n|\n_{5,}\n|\nOn .{5,80} wrote:\n/)[0];       // signature / quoted reply
  t = t.split('\n').filter((l) => !/^\s*>/.test(l)).join('\n');   // quoted lines
  return t.replace(/<\/?content>/gi, '').replace(/\n{3,}/g, '\n\n').trim();
}

// Pages that cover many unrelated stories — two items citing one of these are NOT duplicates.
const ROUNDUP_URL = /roundup|threatsday|weekly|week-in|in-other-news|threat-intelligence-report|newsletter|recap|digest/i;
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];

/** The brief sometimes lists one story in two sections with the same link; keep one item, combine the text. */
function mergeDuplicates(items) {
  const out = [];
  for (const it of items) {
    const key = it.urls[0];
    const dup = key && !ROUNDUP_URL.test(key) && out.find((o) => o.urls[0] === key);
    if (!dup) { out.push({ ...it }); continue; }
    if (!dup.text.includes(it.text)) dup.text = `${dup.text} | ${it.text}`;
    dup.urls = uniq([...dup.urls, ...it.urls]);
    const better = [dup.severity, it.severity].filter(Boolean).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0];
    dup.severity = better || null;
  }
  return out;
}

/** Parse a brief body into { cleanText, urls, items[] }. Items are numbered in brief order. */
export function parseBrief({ html, text }) {
  let items = html ? parseHtmlItems(html) : [];
  if (!items.length) items = parseTextItems(text || (html ? parseHtml(html).structuredText : ''));
  items = mergeDuplicates(items.filter((i) => i.label || i.text)).map((i, n) => ({ ordinal: n, ...i }));
  return {
    cleanText: toCleanText(html, text),
    urls: uniq(items.flatMap((i) => i.urls)),
    items,
  };
}
