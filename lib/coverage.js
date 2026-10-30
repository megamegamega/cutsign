// Automated detection-coverage check: for a campaign (its CVEs, or its names when it has none)
// ask every public, machine-readable source a defender's coverage table is built from, and
// record what each one says. Nothing here is a model: each lane is a fetch and a parse, and the
// result is one of four honest statuses —
//   published      the source has something for this campaign (what, and the link)
//   nothing found  the source answered and had nothing (itself a finding worth a row)
//   not checkable  the source has no public machine-readable form (a JS-only page, a login,
//                  an API that needs a token the host does not have): the row says what a person
//                  would open
//   check failed   the fetch or parse failed; the row says so instead of pretending "nothing"
// Lanes follow the roster a verdict card's coverage table uses: the impacted vendor first, then
// government, scanners, EDR, WAF/edge, cloud, distro errata, IDS, community and MSSP/IR firms.
// Public OSINT only; the host never sends anything but a CVE id or a product name.

import { isPrimary } from './fetch-source.js';
import { nvdCpes, exposureQueries } from './exposure.js';
import { validateExposure } from './shodan.js';

const UA = 'Mozilla/5.0 (compatible; cutsign-coverage/1.0; +https://cutsign.vercel.app)';
const TIMEOUT_MS = 12_000;
const MAX_BYTES = 3_000_000;
export const RECHECK_MS = 20 * 3600_000;   // a lane is re-asked once a day

const CVE_RE = /^CVE-\d{4}-\d+$/;
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const unesc = (s) => String(s ?? '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&#8217;/g, '’').replace(/&amp;/g, '&');

/**
 * Fetch text with the module's limits; cached per call tree so one sweep asks each feed once.
 * Returns { status, text } and never throws on HTTP status; throws on network/timeout.
 */
async function get(url, { fetchImpl = fetch, cache = new Map(), headers = {} } = {}) {
  if (cache.has(url)) return cache.get(url);
  const p = (async () => {
    const r = await fetchImpl(url, { headers: { 'User-Agent': UA, Accept: 'text/html, application/xml, application/json, text/plain;q=0.9, */*;q=0.5', ...headers }, redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) });
    let text = '';
    if (r.body && typeof r.body.getReader === 'function') {
      const reader = r.body.getReader(); const chunks = []; let n = 0;
      for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; chunks.push(value); if (n > MAX_BYTES) { await reader.cancel().catch(() => {}); break; } }
      text = Buffer.concat(chunks).subarray(0, MAX_BYTES).toString('utf8');
    } else text = (await r.text()).slice(0, MAX_BYTES);
    const h = (k) => (r.headers && typeof r.headers.get === 'function' ? r.headers.get(k) : null);
    return { status: r.status, text, retryAfter: h('retry-after'), rateReset: h('x-ratelimit-reset') };
  })();
  cache.set(url, p);
  try { return await p; } catch (e) { cache.delete(url); throw e; }
}

/**
 * GitHub code search, spaced to its own rate limit (10 calls a minute per token, counted across
 * every concurrent check) and retried once after the wait the API asks for. A 403 or 429 that
 * asks for more than a minute is returned as is: the lane says so and is re-asked next sweep.
 */
let ghNext = 0; // module-level: the sweep's checks share one token
async function ghSearch(url, { minGapMs = 7000, sleep = (ms) => new Promise((res) => setTimeout(res, ms)), cache = new Map(), ...opts } = {}) {
  const wait = async () => { const t = Math.max(0, ghNext - Date.now()); ghNext = Math.max(ghNext, Date.now()) + minGapMs; if (t) await sleep(t); };
  await wait();
  let r = await get(url, { ...opts, cache });
  if (r.status === 403 || r.status === 429) {
    const secs = Number(r.retryAfter) || (r.rateReset ? Math.ceil(Number(r.rateReset) - Date.now() / 1000) : 0);
    if (secs > 0 && secs <= 70) { cache.delete(url); await sleep(secs * 1000); ghNext = Date.now() + minGapMs; r = await get(url, { ...opts, cache }); }
  }
  return r;
}

/**
 * Why a code search failed, in the lane's words: GitHub's own message (never swallowed), plus what
 * to do about it. A 422 on public repositories means the token cannot use code search at all: a
 * fine-grained token is refused for any repository it was not granted, so the lane asks for a
 * classic token (no scopes needed for public code). A 403/429 is the per-token rate limit.
 */
export function ghFailure(r) {
  let msg = '';
  try { const b = JSON.parse(r.text || ''); msg = [b.message, ...(b.errors || []).map((e) => e.message)].filter(Boolean).join('; '); } catch { /* not JSON */ }
  const why = r.status === 403 || r.status === 429 ? 'code search rate limit; re-asked next sweep'
    : r.status === 422 ? (/parse/i.test(msg) ? 'GitHub could not parse the query; the search term carries a character its parser treats as an operator'
      : 'GitHub refused the search for this token: code search needs a classic token (public code needs no scope); a fine-grained token is refused for repositories it was not granted')
    : r.status === 401 ? 'GITHUB_TOKEN is not accepted (expired or revoked)' : '';
  return `HTTP ${r.status}${msg ? ` — ${msg.slice(0, 160)}` : ''}${why ? ` (${why})` : ''}`;
}

// ---- parsers (pure; tested on their own) -------------------------------------------------------

/** RSS/Atom items as [{ title, link, text, date }] (title + link + description/content, HTML stripped; date ISO or null). */
export function feedItems(xml) {
  const out = [];
  for (const m of String(xml || '').matchAll(/<(item|entry)\b[\s\S]*?<\/\1>/gi)) {
    const it = m[0];
    const title = unesc((it.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').replace(/<[^>]+>/g, '').trim();
    const link = (it.match(/<link[^>]*href="([^"]+)"/i) || it.match(/<link[^>]*>([\s\S]*?)<\/link>/i) || [])[1]?.trim() || '';
    const raw = (it.match(/<(?:pubDate|published|updated|dc:date)[^>]*>([\s\S]*?)<\/(?:pubDate|published|updated|dc:date)>/i) || [])[1];
    const t = raw ? Date.parse(unesc(raw).trim()) : NaN;
    const body = unesc(it.replace(/<title[^>]*>[\s\S]*?<\/title>/i, '')).replace(/<[^>]+>/g, ' ');
    out.push({ title, link: unesc(link), text: `${title} ${body}`.replace(/\s+/g, ' '), date: Number.isFinite(t) ? new Date(t).toISOString() : null });
  }
  return out;
}

const wordRe = (t) => new RegExp(`\\b${String(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');

/**
 * Items that name the campaign. A CVE id anywhere in the text is a match on its own. A name is a
 * match only inside the campaign window (an item dated before `since` is some older post about
 * the product, not coverage of this campaign; undated items are allowed): `terms` match the whole
 * text, `titleTerms` the title only. Each hit carries `how`: 'cve' or 'name'.
 */
export function matchItems(items, { cves = [], terms = [], titleTerms = [], since = 0 }) {
  const bodyRes = terms.filter(Boolean).map(wordRe);
  const titleRes = titleTerms.filter(Boolean).map(wordRe);
  const inWindow = (it) => !it.date || !since || Date.parse(it.date) >= since;
  const out = [];
  for (const it of items) {
    if (cves.some((c) => it.text.toUpperCase().includes(c.toUpperCase()))) out.push({ ...it, how: 'cve' });
    else if (inWindow(it) && (bodyRes.some((re) => re.test(it.text)) || titleRes.some((re) => re.test(it.title)))) out.push({ ...it, how: 'name' });
  }
  return out;
}

/**
 * The terms distinctive enough to match a post by name even when the campaign has a CVE: a
 * campaign nickname or a product name (a digit, inner capitals, an acronym or a dot), never a
 * capitalised plain word like "Remote" or "Backup". A vendor's feed text often names the
 * campaign ("PHP2Shell") and never the CVE id.
 */
export const nicknameTerms = (terms = []) => terms.filter((t) => /\d/.test(t) || /[a-z][A-Z]/.test(t) || /[A-Z]{2}/.test(t) || /\w\.\w/.test(t));

/** Tenable's plugin search page → [{ id, name, family }] (server-rendered table rows; null when the page is not a result list). */
export function tenablePlugins(html) {
  const s = String(html || '');
  if (/No results found/i.test(s)) return [];
  const out = [];
  for (const m of s.matchAll(/<tr>\s*<td>\s*<a[^>]*href="\/plugins\/([a-z]+)\/(\d{4,7})"[^>]*>\s*\d+\s*<\/a>\s*<\/td>\s*<td>([\s\S]*?)<\/td>\s*<td>([\s\S]*?)<\/td>/g)) {
    out.push({ id: m[2], kind: m[1], name: unesc(m[3]).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim(), product: unesc(m[4]).replace(/<[^>]+>/g, '').trim() });
  }
  return out.length ? out : null;
}

/** Qualys QIDs printed in a text. */
export const qids = (text) => [...new Set([...String(text || '').matchAll(/\bQIDs?\b[^0-9]{0,12}(\d{5,6}(?:\s*(?:,|and|&|\/|or)\s*\d{5,6}\b)*)/gi)].flatMap((m) => m[1].match(/\d{5,6}/g)))];

/** Rapid7's own coverage flags from its vulnerability page (JSON embedded in the HTML). */
export function rapid7Flags(html, cve) {
  const titled = new RegExp(`<title>[^<]*${cve.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^<]*</title>`, 'i').test(html);
  if (!titled) return null;
  const vm = /has_rapid7_vm_coverage\\?":(true|false)/.exec(html)?.[1];
  const msf = /msf_module_count\\?":(\d+)/.exec(html)?.[1];
  return { vm: vm === 'true', msf: Number(msf || 0) };
}

/** Red Hat's security-data record → { errata[], states[] } (errata = released advisories). */
export function redhatSummary(json) {
  const errata = [...new Set((json.affected_release || []).map((r) => r.advisory).filter(Boolean))];
  const states = [...new Set((json.package_state || []).map((p) => p.fix_state).filter(Boolean))];
  return { errata, states, severity: json.threat_severity || null };
}

/** NVD record → { published, cvss } (the highest-version base score present). */
export function nvdSummary(json) {
  const v = json?.vulnerabilities?.[0]?.cve;
  if (!v) return null;
  const m = v.metrics || {};
  const score = m.cvssMetricV40?.[0]?.cvssData?.baseScore ?? m.cvssMetricV31?.[0]?.cvssData?.baseScore ?? m.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;
  const ver = m.cvssMetricV40?.length ? '4.0' : m.cvssMetricV31?.length ? '3.1' : m.cvssMetricV30?.length ? '3.0' : null;
  return { published: String(v.published || '').slice(0, 10), cvss: score, cvssVersion: ver };
}

/** Emerging Threats open rules: the sids whose rule text names the CVE. */
export function etSids(rules, cve) {
  const n = cve.replace(/^CVE-/i, '');
  const out = [];
  for (const line of String(rules || '').split('\n')) {
    if (!line.includes(cve) && !line.includes(`cve,${n}`)) continue;
    const sid = /\bsid:\s*(\d+)/.exec(line)?.[1];
    if (sid) out.push(sid);
  }
  return [...new Set(out)];
}

/**
 * A stated name's aliases as separate terms: "KeyDrift (PolyFlame, LittleFilch)" → KeyDrift, PolyFlame,
 * LittleFilch; "Storm-0940 / Water Curse" → both; "aka"/"a.k.a." split too. A bracketed alias list
 * sent whole to a feed never matches a title, and sent to GitHub's search parser is a 422.
 */
export const aliases = (name) => String(name || '').split(/\s*(?:[(),/;]|\baka\b|\ba\.k\.a\.?)\s*/i).map((s) => s.trim()).filter(Boolean);

/** Terms a no-CVE campaign is searched by: names the record states (each alias on its own), and product-ish words from the title. */
export function coverageTerms({ title = '', malware_family = null, threat_actor = null } = {}) {
  const generic = new Set(['microsoft', 'windows', 'google', 'apple', 'linux', 'security', 'update', 'updates', 'release', 'releases', 'critical', 'emergency',
    'october', 'november', 'december', 'january', 'february', 'march', 'april', 'june', 'july', 'august', 'september', 'exploited', 'campaign', 'supply', 'chain',
    'compromise', 'breach', 'vulnerability', 'vulnerabilities', 'zero-day', 'attack', 'attacks', 'actively', 'patch', 'patches', 'cloud', 'service', 'cisa', 'kev']);
  const words = String(title).replace(/[^\w.-]+/g, ' ').split(' ')
    .filter((w) => w.length >= 5 && /^[A-Z][A-Za-z0-9.-]*$/.test(w) && !generic.has(w.toLowerCase()) && !/^CVE-/i.test(w));
  return [...new Set([...aliases(malware_family), ...aliases(threat_actor), ...words].filter(Boolean))].slice(0, 8);
}

/**
 * A term as GitHub's legacy code-search parser accepts it: letters, digits, dot, dash and spaces only
 * (parentheses, commas and colons are operators to it and a 422), quoted when it has a space.
 * Returns '' for a term with nothing searchable left.
 */
export const ghTerm = (t) => { const s = String(t || '').replace(/[^\w.\- ]+/g, ' ').replace(/\s+/g, ' ').trim(); return !s ? '' : /\s/.test(s) ? `"${s}"` : s; };

// ---- lanes ------------------------------------------------------------------------------------

const FEEDS = [
  { id: 'crowdstrike', category: 'EDR / endpoint VM', name: 'CrowdStrike blog', url: 'https://www.crowdstrike.com/en-us/blog/feed/' },
  { id: 'microsoft_security', category: 'EDR / endpoint VM', name: 'Microsoft Security blog', url: 'https://www.microsoft.com/en-us/security/blog/feed/' },
  { id: 'sentinelone', category: 'EDR / endpoint VM', name: 'SentinelOne Labs', url: 'https://www.sentinelone.com/labs/feed/' },
  { id: 'sentinelone_blog', category: 'EDR / endpoint VM', name: 'SentinelOne blog', url: 'https://www.sentinelone.com/blog/feed/' }, // product-coverage posts live here, not on Labs
  { id: 'cloudflare_waf', category: 'WAF / edge', name: 'Cloudflare WAF managed-ruleset changelog', url: 'https://developers.cloudflare.com/waf/change-log/index.xml' },
  { id: 'akamai', category: 'WAF / edge', name: 'Akamai blog', url: 'https://feeds.feedburner.com/akamai/blog' },
  { id: 'wiz', category: 'Cloud / container', name: 'Wiz blog', url: 'https://www.wiz.io/feed/rss.xml' },
  { id: 'talos', category: 'IDS / research', name: 'Cisco Talos blog', url: 'https://blog.talosintelligence.com/rss/' },
  { id: 'elastic_labs', category: 'Detection content', name: 'Elastic Security Labs', url: 'https://www.elastic.co/security-labs/rss/feed.xml' },
  { id: 'unit42', category: 'Research', name: 'Unit 42', url: 'https://unit42.paloaltonetworks.com/feed/' },
  { id: 'huntress', category: 'MSSP / IR firms', name: 'Huntress blog', url: 'https://www.huntress.com/blog/rss.xml' },
  { id: 'sophos', category: 'MSSP / IR firms', name: 'Sophos threat research', url: 'https://news.sophos.com/en-us/category/threat-research/feed/' },
  { id: 'arctic_wolf', category: 'MSSP / IR firms', name: 'Arctic Wolf blog', url: 'https://arcticwolf.com/feed/' },
  { id: 'rapid7_blog', category: 'MSSP / IR firms', name: 'Rapid7 blog', url: 'https://www.rapid7.com/blog/rss/' },
];
const ET_RULES = ['emerging-exploit', 'emerging-web_server', 'emerging-web_specific_apps'].map((f) => `https://rules.emergingthreats.net/open/suricata-7.0.3/rules/${f}.rules`);
const GH_REPOS = [
  { id: 'sigma', name: 'SigmaHQ rules', repo: 'SigmaHQ/sigma' },
  { id: 'elastic_rules', name: 'Elastic detection rules', repo: 'elastic/detection-rules' },
  { id: 'splunk_escu', name: 'Splunk ESCU', repo: 'splunk/security_content' },
];

const lane = (id, category, name, status, detail, url = null) => ({ id, category, name, status, detail: String(detail || '').slice(0, 400), url: url || null });
const failed = (id, category, name, e, url = null) => lane(id, category, name, 'check failed', String(e?.message || e).slice(0, 160), url);

/** The lane order the table prints in (vendor first, as every card does). */
export const CATEGORY_ORDER = ['Vendor', 'Government', 'Reference', 'VM scanners', 'EDR / endpoint VM', 'WAF / edge', 'Cloud / container', 'Linux distro errata', 'IDS / research', 'Detection content', 'Community', 'MSSP / IR firms', 'Research'];

/**
 * Run every lane. Lanes never throw: a failure is a 'check failed' row.
 * @param cves    the campaign's CVE ids (at most 3 are asked per per-CVE source)
 * @param terms   names for a no-CVE campaign (see coverageTerms)
 * @param sources the thread's source URLs (the vendor lane looks for a primary page among them)
 * @param kev     Map cve → { dateAdded, dueDate } (or → dateAdded) already fetched by the caller
 * @param prev    the previous check for this card, if any (its exposure trend is carried forward)
 */
export async function checkCoverage({ cves = [], terms = [], named = [], affected = [], sources = [], kev = new Map(), fetchImpl = fetch, cache = new Map(), now = Date.now(), githubToken = process.env.GITHUB_TOKEN || '',
  shodanKey = process.env.SHODAN_API_KEY || '', shodanMinGapMs = 1100, prev = null,
  since = now - 45 * 86400_000, ghMinGapMs = 7000, sleep = (ms) => new Promise((res) => setTimeout(res, ms)) } = {}) {
  const ids = [...new Set(cves.filter((c) => CVE_RE.test(c)))].slice(0, 3);
  const opts = { fetchImpl, cache };
  const lanes = [];

  // Vendor: the impacted vendor's own page, if the thread's sources include one
  const primary = sources.find((u) => isPrimary(u));
  lanes.push(primary ? lane('vendor', 'Vendor', 'Impacted vendor / CERT advisory', 'published', `primary source among the thread's sources: ${primary}`, primary)
    : lane('vendor', 'Vendor', 'Impacted vendor / CERT advisory', 'nothing found', 'no vendor or CERT page among the thread sources; secondary reporting only'));

  // Government: CISA KEV from the catalog the caller already holds
  for (const c of ids) {
    const e = kev.get(c); const added = typeof e === 'string' ? e : e?.dateAdded; const due = typeof e === 'object' ? e?.dueDate : null;
    lanes.push(added ? lane(`kev:${c}`, 'Government', `CISA KEV · ${c}`, 'published', `listed ${added}${due ? `, federal due ${due}` : ''}`, 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog')
      : lane(`kev:${c}`, 'Government', `CISA KEV · ${c}`, 'nothing found', 'not in the catalog', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'));
  }
  if (!ids.length) lanes.push(lane('kev', 'Government', 'CISA KEV', 'not checkable', 'no CVE: the catalog is keyed by CVE'));

  const tasks = [];
  const run = (fn) => { const p = fn().catch((e) => lanes.push(failed('lane', 'Reference', 'lane', e))); tasks.push(p); return p; };
  const cpes = []; // the vulnerable products NVD names: the exposure queries are built from these
  const nvdTasks = [];

  for (const c of ids) {
    const y = c.split('-')[1];
    nvdTasks.push(run(async () => { // NVD
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${c}`;
      try {
        const r = await get(url, opts);
        if (r.status !== 200) return lanes.push(lane(`nvd:${c}`, 'Reference', `NVD · ${c}`, r.status === 404 ? 'nothing found' : 'check failed', `HTTP ${r.status}`, `https://nvd.nist.gov/vuln/detail/${c}`));
        const json = JSON.parse(r.text);
        cpes.push(...nvdCpes(json));
        const s = nvdSummary(json);
        lanes.push(s ? lane(`nvd:${c}`, 'Reference', `NVD · ${c}`, 'published', `published ${s.published}${s.cvss != null ? `, CVSS ${s.cvssVersion} ${s.cvss}` : ', no CVSS yet'}`, `https://nvd.nist.gov/vuln/detail/${c}`)
          : lane(`nvd:${c}`, 'Reference', `NVD · ${c}`, 'nothing found', 'no record yet', `https://nvd.nist.gov/vuln/detail/${c}`));
      } catch (e) { lanes.push(failed(`nvd:${c}`, 'Reference', `NVD · ${c}`, e, `https://nvd.nist.gov/vuln/detail/${c}`)); }
    }));
    run(async () => { // Qualys: ThreatPROTECT and the Security Blog (WordPress search feeds; QIDs when a post prints them).
      // The QID knowledge base itself needs a login; these two public blogs are where Qualys prints the QIDs it ships.
      const human = `https://blog.qualys.com/?s=${encodeURIComponent(c)}`;
      const sites = [['ThreatPROTECT', 'https://threatprotect.qualys.com'], ['Security Blog', 'https://blog.qualys.com']];
      try {
        const hits = []; let failedSites = 0;
        await Promise.all(sites.map(async ([name, base]) => {
          const r = await get(`${base}/?s=${encodeURIComponent(c)}&feed=rss2`, opts);
          if (r.status !== 200) { failedSites++; return; }
          for (const it of matchItems(feedItems(r.text), { cves: [c] })) hits.push({ ...it, site: name });
        }));
        if (!hits.length) return lanes.push(lane(`qualys:${c}`, 'VM scanners', `Qualys · ${c}`, failedSites === sites.length ? 'check failed' : 'nothing found', failedSites === sites.length ? 'both blog search feeds failed' : `no ThreatPROTECT or Security Blog post names it${failedSites ? ' (one feed failed)' : ''}; the QID knowledge base needs a login`, human));
        const q = qids(hits.map((i) => i.text).join(' ')).slice(0, 8);
        const first = hits.slice().sort((a, b) => qids(b.text).length - qids(a.text).length)[0]; // link the post that prints the most QIDs
        lanes.push(lane(`qualys:${c}`, 'VM scanners', `Qualys · ${c}`, 'published', `${q.length ? `QID ${q.join(', ')} · ` : ''}${first.site}: ${first.title}${hits.length > 1 ? ` (+${hits.length - 1} more post${hits.length > 2 ? 's' : ''})` : ''}`, first.link || human));
      } catch (e) { lanes.push(failed(`qualys:${c}`, 'VM scanners', `Qualys · ${c}`, e, human)); }
    });
    run(async () => { // Tenable: the plugin search page is server-rendered (the CVE page itself is not)
      const url = `https://www.tenable.com/plugins/search?q=${encodeURIComponent(`cves:("${c}")`)}`;
      try {
        const r = await get(url, opts);
        let p = r.status === 200 ? tenablePlugins(r.text) : null;
        if (!p) return lanes.push(lane(`tenable:${c}`, 'VM scanners', `Tenable · ${c}`, 'check failed', r.status === 200 ? 'plugin search page did not render a result list' : `HTTP ${r.status}`, url));
        // the page is one screen of results (40): plugins named for the campaign's product first, then the distro backports
        const named = (x) => terms.some((t) => wordRe(t).test(x.name)) ? 0 : 1;
        p = p.slice().sort((a, b) => named(a) - named(b));
        lanes.push(p.length ? lane(`tenable:${c}`, 'VM scanners', `Tenable · ${c}`, 'published', `${p.length >= 40 ? '40+' : p.length} plugin${p.length === 1 ? '' : 's'}: ${p.slice(0, 4).map((x) => `${x.id} ${x.name}`).join('; ')}${p.length > 4 ? '; …' : ''}`, url)
          : lane(`tenable:${c}`, 'VM scanners', `Tenable · ${c}`, 'nothing found', 'no plugin names the CVE yet', url));
      } catch (e) { lanes.push(failed(`tenable:${c}`, 'VM scanners', `Tenable · ${c}`, e, url)); }
    });
    run(async () => { // Rapid7: its own coverage flag
      const url = `https://www.rapid7.com/db/vulnerabilities/${c.toLowerCase()}/`;
      try {
        const r = await get(url, opts);
        const f = r.status === 200 ? rapid7Flags(r.text, c) : null;
        if (!f) return lanes.push(lane(`rapid7:${c}`, 'VM scanners', `Rapid7 · ${c}`, r.status === 200 || r.status === 404 ? 'nothing found' : 'check failed', r.status === 200 || r.status === 404 ? 'no vulnerability-database entry' : `HTTP ${r.status}`, url));
        lanes.push(lane(`rapid7:${c}`, 'VM scanners', `Rapid7 · ${c}`, f.vm ? 'published' : 'nothing found', `${f.vm ? 'InsightVM coverage stated' : 'entry exists, no InsightVM coverage stated'}${f.msf ? ` · ${f.msf} Metasploit module${f.msf === 1 ? '' : 's'} (not linked)` : ''}`, url));
      } catch (e) { lanes.push(failed(`rapid7:${c}`, 'VM scanners', `Rapid7 · ${c}`, e, url)); }
    });
    run(async () => { // Red Hat security data
      const url = `https://access.redhat.com/hydra/rest/securitydata/cve/${c}.json`; const human = `https://access.redhat.com/security/cve/${c}`;
      try {
        const r = await get(url, opts);
        if (r.status === 404) return lanes.push(lane(`redhat:${c}`, 'Linux distro errata', `Red Hat · ${c}`, 'nothing found', 'no Red Hat entry', human));
        if (r.status !== 200) return lanes.push(lane(`redhat:${c}`, 'Linux distro errata', `Red Hat · ${c}`, 'check failed', `HTTP ${r.status}`, human));
        const s = redhatSummary(JSON.parse(r.text));
        lanes.push(lane(`redhat:${c}`, 'Linux distro errata', `Red Hat · ${c}`, s.errata.length ? 'published' : 'nothing found',
          `${s.severity ? `${s.severity}; ` : ''}${s.errata.length ? `errata ${s.errata.slice(0, 6).join(', ')}` : `entry exists, no errata yet${s.states.length ? ` (states: ${s.states.join(', ')})` : ''}`}`, human));
      } catch (e) { lanes.push(failed(`redhat:${c}`, 'Linux distro errata', `Red Hat · ${c}`, e, human)); }
    });
    run(async () => { // Debian tracker
      const url = `https://security-tracker.debian.org/tracker/${c}`;
      try {
        const r = await get(url, opts);
        lanes.push(r.status === 200 && r.text.includes(c) ? lane(`debian:${c}`, 'Linux distro errata', `Debian tracker · ${c}`, 'published', `tracker entry${/\bfixed\b/i.test(r.text) ? ' with fixed versions' : ''}`, url)
          : lane(`debian:${c}`, 'Linux distro errata', `Debian tracker · ${c}`, r.status === 404 ? 'nothing found' : r.status === 200 ? 'nothing found' : 'check failed', r.status === 404 || r.status === 200 ? 'no tracker entry' : `HTTP ${r.status}`, url));
      } catch (e) { lanes.push(failed(`debian:${c}`, 'Linux distro errata', `Debian tracker · ${c}`, e, url)); }
    });
    run(async () => { // Nuclei template
      const url = `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/${y}/${c}.yaml`; const human = `https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves/${y}`;
      try {
        const r = await get(url, opts);
        lanes.push(r.status === 200 ? lane(`nuclei:${c}`, 'Community', `Nuclei template · ${c}`, 'published', 'template in nuclei-templates (main)', `https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/${y}/${c}.yaml`)
          : lane(`nuclei:${c}`, 'Community', `Nuclei template · ${c}`, r.status === 404 ? 'nothing found' : 'check failed', r.status === 404 ? 'no template under http/cves' : `HTTP ${r.status}`, human));
      } catch (e) { lanes.push(failed(`nuclei:${c}`, 'Community', `Nuclei template · ${c}`, e, human)); }
    });
    run(async () => { // Emerging Threats open rules
      const human = 'https://rules.emergingthreats.net/open/';
      try {
        const texts = await Promise.all(ET_RULES.map((u) => get(u, opts)));
        const bad = texts.find((t) => t.status !== 200);
        if (bad) return lanes.push(lane(`et:${c}`, 'IDS / research', `Emerging Threats open · ${c}`, 'check failed', `HTTP ${bad.status}`, human));
        const sids = [...new Set(texts.flatMap((t) => etSids(t.text, c)))];
        lanes.push(sids.length ? lane(`et:${c}`, 'IDS / research', `Emerging Threats open · ${c}`, 'published', `${sids.length} Suricata rule${sids.length === 1 ? '' : 's'}: sid ${sids.slice(0, 8).join(', ')}`, human)
          : lane(`et:${c}`, 'IDS / research', `Emerging Threats open · ${c}`, 'nothing found', 'no open rule names it (exploit, web_server, web_specific_apps sets)', human));
      } catch (e) { lanes.push(failed(`et:${c}`, 'IDS / research', `Emerging Threats open · ${c}`, e, human)); }
    });
  }

  // vendor feeds and changelogs, matched on CVE ids anywhere in the item, or on a campaign nickname /
  // product name in the title inside the campaign window (vendor feeds carry a short description
  // that names "PHP2Shell" and never the CVE id). With no CVE at all, the names match the whole text.
  const names = nicknameTerms(terms);
  const match = { cves: ids, terms: ids.length ? [] : terms, titleTerms: ids.length ? names : [], since };
  if (ids.length || terms.length) for (const f of FEEDS) run(async () => {
    try {
      const r = await get(f.url, opts);
      if (r.status !== 200) return lanes.push(lane(f.id, f.category, f.name, 'check failed', `HTTP ${r.status}`, f.url));
      const items = feedItems(r.text);
      if (!items.length) return lanes.push(lane(f.id, f.category, f.name, 'check failed', 'feed had no items', f.url));
      // a post titled for the campaign (CVE id or nickname in the title) ranks ahead of a roundup that mentions it in the body
      const titled = (h) => (ids.some((c) => h.title.toUpperCase().includes(c.toUpperCase())) || names.some((n) => wordRe(n).test(h.title)) ? 0 : 1);
      const hits = matchItems(items, match).sort((a, b) => titled(a) - titled(b));
      const byName = hits.length && hits.every((h) => h.how === 'name');
      lanes.push(hits.length ? lane(f.id, f.category, f.name, 'published', `${hits.slice(0, 3).map((h) => h.title).join(' · ')}${byName ? ` (names ${names.filter((n) => hits.some((h) => wordRe(n).test(h.title))).join(' / ') || 'the campaign'} in the title; the feed text carries no CVE id)` : ''}`, hits[0].link || f.url)
        : lane(f.id, f.category, f.name, 'nothing found', `no post names it among the feed's ${items.length} newest items`, f.url));
    } catch (e) { lanes.push(failed(f.id, f.category, f.name, e, f.url)); }
  });

  // GitHub code search across the rule repositories: needs a token (unauthenticated search is refused).
  // One call per term covers every repo (repo: qualifiers are OR'ed; search terms are not — the
  // legacy parser ANDs them whatever "OR" says, verified against the API — so a card costs one call
  // per term). The nickname goes first so a three-CVE card still searches it (Splunk and Elastic
  // name rules by the campaign); at most three terms a card. Calls are spaced to stay under code
  // search's 10/min across a whole sweep: eight hand cards at 6.5 s tripped it (HTTP 403).
  const ghTerms = [...new Set([names[0], ...ids, ...names.slice(1), ...(ids.length ? [] : terms)].map(ghTerm).filter(Boolean))].slice(0, 3);
  const ghHuman = (g) => `https://github.com/search?q=${encodeURIComponent(`repo:${g.repo} ${ghTerms[0] || ''}`)}&type=code`;
  if (ghTerms.length && !githubToken) for (const g of GH_REPOS) lanes.push(lane(g.id, 'Detection content', g.name, 'not checkable', 'GitHub code search needs GITHUB_TOKEN (a classic token; public code needs no scope); open the search', ghHuman(g)));
  if (ghTerms.length && githubToken) run(async () => {
    const files = Object.fromEntries(GH_REPOS.map((g) => [g.repo, new Map()])); // path → the term that found it
    try {
      for (const term of ghTerms) {
        const q = `${term} ${GH_REPOS.map((g) => `repo:${g.repo}`).join(' ')}`;
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=30`;
        const r = await ghSearch(url, { ...opts, headers: { Authorization: `Bearer ${githubToken}`, Accept: 'application/vnd.github+json' }, minGapMs: ghMinGapMs, sleep });
        if (r.status !== 200) { for (const g of GH_REPOS) lanes.push(lane(g.id, 'Detection content', g.name, 'check failed', ghFailure(r), ghHuman(g))); return; }
        for (const it of JSON.parse(r.text).items || []) { const repo = it.repository?.full_name; if (files[repo] && !files[repo].has(it.path)) files[repo].set(it.path, term.replace(/"/g, '')); }
      }
      for (const g of GH_REPOS) {
        const f = [...files[g.repo].keys()];
        const by = [...new Set(files[g.repo].values())]; // which terms matched: a product name alone is a weaker signal than the CVE id or campaign name
        lanes.push(f.length ? lane(g.id, 'Detection content', g.name, 'published', `${f.length} file${f.length === 1 ? ' names' : 's name'} ${by.join(' / ')}: ${f.slice(0, 4).join(', ')}`, ghHuman(g))
          : lane(g.id, 'Detection content', g.name, 'nothing found', `no rule file names ${ghTerms.map((t) => t.replace(/"/g, '')).join(' / ')}`, ghHuman(g)));
      }
    } catch (e) { for (const g of GH_REPOS) lanes.push(failed(g.id, 'Detection content', g.name, e, ghHuman(g))); }
  });

  // the EASM half the pipeline can write: generic queries from the CVE ids and NVD's CPEs (lib/exposure.js),
  // each Shodan query then counted against Shodan itself (lib/shodan.js) while the GitHub lane waits out its spacing
  let exposure = null;
  run(async () => {
    await Promise.all(nvdTasks);
    exposure = await validateExposure(exposureQueries({ cves: ids, cpes, terms, named, affected, now }), { key: shodanKey, cpes, prev: prev?.exposure || null, fetchImpl, now, minGapMs: shodanMinGapMs, sleep });
  });

  await Promise.all(tasks);
  exposure ??= exposureQueries({ cves: ids, cpes, terms, named, affected, now });
  const order = (l) => CATEGORY_ORDER.indexOf(l.category);
  lanes.sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name));
  const summary = { published: lanes.filter((l) => l.status === 'published').length, nothing: lanes.filter((l) => l.status === 'nothing found').length, failed: lanes.filter((l) => l.status === 'check failed').length, unchecked: lanes.filter((l) => l.status === 'not checkable').length };
  return { checked_at: new Date(now).toISOString(), cves: ids, terms, lanes, summary, exposure };
}

/** Lanes whose status changed between two checks, as readable lines; plus products NVD newly named. */
export function diffCoverage(prev, cur) {
  if (!prev?.lanes) return [];
  const before = new Map(prev.lanes.map((l) => [l.id, l]));
  const out = [];
  for (const l of cur.lanes || []) {
    const p = before.get(l.id);
    if (p && p.status !== l.status && l.status !== 'check failed' && p.status !== 'check failed') out.push(`${l.name}: ${p.status} → ${l.status}${l.status === 'published' ? ` (${l.detail})` : ''}`);
  }
  const had = new Set(prev.exposure?.products || []);
  const added = (cur.exposure?.products || []).filter((p) => !had.has(p));
  if (added.length) out.push(`Exposure queries: NVD now names ${added.join(', ')} (Shodan and Censys product queries added)`);
  // Shodan's answers: a spelling found, counts arriving for the first time, the key failing (a daily count moving is not news)
  const prevQ = new Set((prev.exposure?.items || []).map((i) => i.query));
  const found = (cur.exposure?.items || []).filter((i) => i.kind === 'discovered' && !prevQ.has(i.query));
  if (found.length) out.push(`Exposure queries: Shodan's own spelling found: ${found.map((i) => `${i.query} (${Number(i.total).toLocaleString('en-US')} services)`).join('; ')}`);
  const ps = prev.exposure?.shodan?.status; const cs = cur.exposure?.shodan?.status;
  if (cs === 'ok' && ps !== 'ok') out.push(`Exposure queries: Shodan counts on (${cur.exposure.shodan.counted} quer${cur.exposure.shodan.counted === 1 ? 'y' : 'ies'} counted)`);
  if (cs === 'failed' && ps !== 'failed') out.push(`Exposure queries: Shodan counts failed — ${cur.exposure.shodan.note}`);
  return out;
}

/**
 * Is a check old enough to re-ask? A check stored before the exposure block existed is re-asked at
 * once; so is one made without a Shodan key once the key is set (the counts arrive at the next tick).
 */
export const coverageStale = (cov, now = Date.now(), { shodanKey = process.env.SHODAN_API_KEY || '' } = {}) =>
  // with a key set, any check whose Shodan queries were not counted (made before the key existed, or
  // before counting existed, or a failed round) is stale now rather than at the daily mark
  !cov?.checked_at || cov.exposure === undefined || now - Date.parse(cov.checked_at) >= RECHECK_MS || (!!shodanKey && cov.exposure?.shodan?.status !== 'ok')
  // a counted block from before the vuln: probe existed (no `vuln` field at all; null means the probe ran and failed)
  || (!!shodanKey && cov.exposure?.shodan?.status === 'ok' && cov.exposure.shodan.vuln === undefined);

/** The coverage table as HTML: name linked to its source, status, what was found. */
export function coverageTable(cov) {
  if (!cov?.lanes?.length) return '<p class="s">No coverage check has run yet.</p>';
  const cls = (s) => s === 'published' ? 'ok' : s === 'nothing found' ? 'bad' : 'mut';
  const rows = cov.lanes.map((l) => `<tr><td>${esc(l.category)}</td><td>${l.url && l.status !== 'nothing found' ? `<a href="${esc(l.url)}">${esc(l.name)}</a>` : esc(l.name)}</td><td><span class="${cls(l.status)}">${esc(l.status)}</span> — ${esc(l.detail)}</td></tr>`);
  return `<table><tr><th>Category</th><th>Source</th><th>Status</th></tr>${rows.join('')}</table>`
    + `<p class="s">Checked automatically ${esc(String(cov.checked_at).slice(0, 16).replace('T', ' '))}Z from public sources: ${cov.summary?.published ?? 0} published, ${cov.summary?.nothing ?? 0} nothing found, ${cov.summary?.unchecked ?? 0} not machine-checkable, ${cov.summary?.failed ?? 0} failed. "Nothing found" means the public source answered and had nothing, as of that moment; a feed covers only its newest posts. Re-checked daily.</p>`;
}
