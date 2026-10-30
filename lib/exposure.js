// External attack surface queries, generated automatically for every card. The pipeline's half of
// an EASM alert is the generic half: what the vulnerable software looks like to an internet
// scanner (the CVE id, the NVD CPE configurations, the product name). The other half, the ranges,
// org name and domains that scope the query to one estate, is never generated, stored or rendered
// here; the reader adds it in Shodan Monitor or their EASM product, where that inventory already
// lives. Nothing here is a model: the queries are built from the NVD record the coverage check
// already fetched, so a CPE NVD publishes later shows up on the card at the next daily re-check.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const CVE_RE = /^CVE-\d{4}-\d+$/;

/** Split a CPE 2.3 formatted string on unescaped colons. */
const cpeFields = (s) => String(s || '').split(/(?<!\\):/).map((f) => f.replace(/\\(.)/g, '$1'));

/**
 * The vulnerable products an NVD record names, from its configurations:
 * [{ part, vendor, product, cpe23, ranges: ['< 24.3.1', '>= 22.0.0 < 22.9.1', ...] }], one per vendor:product.
 */
export function nvdCpes(json) {
  const byKey = new Map();
  for (const cfg of json?.vulnerabilities?.[0]?.cve?.configurations || []) for (const node of cfg.nodes || []) for (const m of node.cpeMatch || []) {
    if (!m?.vulnerable || !m.criteria) continue;
    const f = cpeFields(m.criteria);
    if (f[0] !== 'cpe' || f[1] !== '2.3' || !f[3] || !f[4]) continue;
    const key = `${f[2]}:${f[3]}:${f[4]}`;
    const cur = byKey.get(key) || { part: f[2], vendor: f[3], product: f[4], cpe23: `cpe:2.3:${f[2]}:${f[3]}:${f[4]}`, ranges: [] };
    const parts = [];
    if (f[5] && f[5] !== '*' && f[5] !== '-') parts.push(`= ${f[5]}`);
    if (m.versionStartIncluding) parts.push(`>= ${m.versionStartIncluding}`);
    if (m.versionStartExcluding) parts.push(`> ${m.versionStartExcluding}`);
    if (m.versionEndIncluding) parts.push(`<= ${m.versionEndIncluding}`);
    if (m.versionEndExcluding) parts.push(`< ${m.versionEndExcluding}`);
    const r = parts.join(' ') || 'all versions';
    if (!cur.ranges.includes(r)) cur.ranges.push(r);
    byKey.set(key, cur);
  }
  return [...byKey.values()].map((p) => ({ ...p, ranges: p.ranges.slice(0, 8) }));
}

/** "node.js" → "Node.js", "http_server" → "Http Server": the spelling a scanner's product field is most likely to use. */
export const productName = (slug) => String(slug || '').replace(/_/g, ' ').replace(/(^|\s)[a-z]/g, (c) => c.toUpperCase());

// What the reader appends, in their own tool, to scope a query to their estate. Placeholders only.
export const SCOPE_NOTE = 'Scope every query in your own tool, never in a shared document: Shodan `net:<your_ranges>`, `org:"<your_org>"` or `hostname:<your_domain>` (or a Shodan Monitor network alert, which applies the scope for you); Censys `host.ip: <your_ranges>` or `host.dns.names: <your_domain>`. Then compare the banner version with the affected range.';

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

// Words a title capitalises that are not products: how a headline starts, what happened, who did it.
const STOP = new Set(['attackers', 'attacker', 'hackers', 'researchers', 'threat', 'actors', 'actor', 'group', 'campaign', 'probing', 'exploitation', 'exploited', 'exploits',
  'exploit', 'patched', 'patch', 'flaw', 'flaws', 'bug', 'bugs', 'zero-day', 'zero-days', 'critical', 'emergency', 'update', 'updates', 'release', 'releases', 'security',
  'vulnerability', 'vulnerabilities', 'supply', 'chain', 'compromise', 'compromised', 'breach', 'reportedly', 'suspected', 'confirmed', 'observed', 'decoys', 'new', 'multiple',
  'chinese', 'russian', 'iranian', 'north', 'korean', 'state', 'state-backed', 'linked', 'nexus', 'unknown', 'malicious', 'trojanized', 'backdoored', 'hijacked', 'fake',
  'active', 'actively', 'mass', 'widespread', 'ongoing', 'cisa', 'kev', 'nvd', 'cve', 'poc', 'rce', 'access', 'bypass', 'release', 'advisory', 'warns', 'warning', 'alert',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
  'component', 'servlet', 'framework', 'module', 'plugin', 'library', 'package', 'extension', 'version', 'versions', 'instance', 'instances', 'sites', 'users', 'customers']);
const GENERIC_PRODUCT = new Set(['server', 'manager', 'management', 'appliance', 'virtual', 'software', 'platform', 'service', 'services', 'system', 'systems', 'suite', 'cloud', 'web', 'core',
  'edition', 'enterprise', 'ssl', 'vpn', 'tls', 'http', 'https', 'api', 'portal', 'gateway', 'firewall', 'agent', 'client', 'console', 'controller', 'orchestrator', 'director']);
// Vendors whose name alone is not a product (product:"Oracle" counts every Oracle banner on the internet). Shared with lib/scannernames.js.
export const VENDORS = new Set(['cisco', 'microsoft', 'vmware', 'broadcom', 'arista', 'oracle', 'google', 'apple', 'ibm', 'fortinet', 'paloaltonetworks', 'palo', 'alto', 'citrix', 'f5', 'juniper',
  'sonicwall', 'ivanti', 'zyxel', 'netgear', 'dlink', 'd-link', 'tplink', 'tp-link', 'hp', 'hpe', 'dell', 'lenovo', 'huawei', 'zte', 'sap', 'adobe', 'atlassian', 'gitlab', 'github', 'amazon', 'aws',
  'versa', 'quest', 'n-able', 'siemens', 'schneider', 'rockwell', 'samsung', 'intel', 'amd', 'nvidia', 'redhat', 'canonical', 'suse', 'debian', 'ubuntu', 'mozilla', 'meta', 'facebook', 'x', 'twitter']);
const NATION = new Set(['china', 'chinese', 'russia', 'russian', 'iran', 'iranian', 'korea', 'korean', 'north', 'dprk', 'prc', 'nexus', 'aligned', 'backed', 'sponsored', 'state']);
const JOIN = new Set(['of', 'for', 'the']); // "and" separates two products, it never joins one
const TOKEN = /^[A-Z0-9][\w.+-]*$/;

/**
 * The software a card names, for the exposure queries when NVD has no CPE yet: phrases from the
 * card's own affected lines first ("Oracle E-Business Suite: Application Object Library…" →
 * "Oracle E-Business Suite"), then runs of capitalised words in the title ("… patched Oracle EBS
 * flaw CVE-…" → "Oracle EBS"). A headline's first word is capitalised for being first, not for
 * being a product, so it counts only when it looks like a name anyway (digits, inner capitals, an
 * acronym); quoted spans are campaign or malware names; `exclude` holds the actor and malware
 * aliases. At most two phrases.
 */
export function namedProducts({ title = '', affected = [], exclude = [] } = {}) {
  const ex = new Set(exclude.flatMap((e) => String(e).toLowerCase().split(/[^a-z0-9.+-]+/)).filter(Boolean));
  // a word is out when it, or any hyphenated part of it ("China-nexus", "state-backed"), is a stop word, a nationality or an excluded alias
  const bad = (w) => { const parts = w.toLowerCase().split(/[-/]/).concat(w.toLowerCase()); return parts.some((l) => STOP.has(l) || NATION.has(l) || ex.has(l)) || /^cve-/i.test(w); };
  const nameLike = (w) => /\d/.test(w) || /^[A-Z]{2,}[a-z0-9]*$/.test(w) || /^[a-z0-9]+[A-Z]/.test(w) || /^[A-Z][a-z0-9]+[A-Z]/.test(w);
  const out = [];
  const add = (toks) => {
    while (toks.length && JOIN.has(toks[toks.length - 1].toLowerCase())) toks.pop();
    while (toks.length && JOIN.has(toks[0].toLowerCase())) toks.shift();
    if (!toks.length || toks.length > 5) return;
    if (toks.every((w) => JOIN.has(w.toLowerCase()) || GENERIC_PRODUCT.has(w.toLowerCase()) || bad(w))) return;
    if (toks.length === 1 && VENDORS.has(toks[0].toLowerCase())) return; // a vendor alone is not a product
    const phrase = toks.join(' ');
    if (phrase.replace(/[^A-Za-z]/g, '').length < 3) return;
    if (!out.some((p) => p.toLowerCase() === phrase.toLowerCase())) out.push(phrase);
  };
  // affected lines: the leading name, before the detail
  for (const line of affected) {
    const head = String(line || '').replace(/\[S\d+\]/g, '').replace(/\([^)]*\)/g, '').split(/[:;,(]| per | - | – | — /)[0].trim();
    const toks = head.split(/\s+/).filter(Boolean);
    const run = [];
    for (const w of toks) { if (TOKEN.test(w) || JOIN.has(w.toLowerCase())) run.push(w); else break; }
    add(run.filter((w, i) => !(i === 0 && bad(w))));
    if (out.length >= 2) return out.slice(0, 2);
  }
  // the title: runs of capitalised words outside quotes, the first word only when it looks like a name
  const t = String(title || '').replace(/["'‘’“”][^"'‘’“”]{2,60}["'‘’“”]/g, ' ').replace(/[,:;()\[\]]/g, ' , ');
  const toks = t.split(/\s+/).filter(Boolean);
  let run = []; let runStart = 0;
  // a plain first word on its own ("Attackers probe…") is not a name; a first word that opens a
  // capitalised phrase ("Drupal Commerce Core…") or looks like a name (GitLab, PHP2Shell) is kept
  const flush = () => { if (!(runStart === 0 && run.length === 1 && !nameLike(run[0]))) add(run); run = []; };
  toks.forEach((w, i) => {
    const ok = TOKEN.test(w) && !bad(w);
    if (ok || (run.length && JOIN.has(w.toLowerCase()))) { if (!run.length) runStart = i; run.push(w); }
    else { flush(); }
  });
  flush();
  return out.slice(0, 2);
}

/**
 * The generic EASM queries for a campaign: by CVE (Shodan's `vuln:` filter, a paid-tier filter) and
 * by NVD CPE (Shodan `cpe:` and `product:`, Censys `software.product`). `cpes` is nvdCpes() output
 * across the campaign's CVEs; NVD lists the library and every product that embeds it, so the
 * products the campaign names (`terms`, from its title) come first and at most four are kept;
 * operating systems and hardware (parts o, h) are the platform, not the service, and are skipped.
 * While NVD has no CPE configuration for the CVEs, the software the campaign names (`named`, from
 * its title, never an actor or malware name) stands in: a product and an http.component query per
 * name, with the card's own affected-version text (`affected`) on the row; NVD's rows replace them
 * at the re-check that finds the configuration.
 * Returns { built_at, items[], products[], note }.
 */
export function exposureQueries({ cves = [], cpes = [], terms = [], named = [], affected = [], now = Date.now() } = {}) {
  const ids = [...new Set(cves.filter((c) => CVE_RE.test(c)))].slice(0, 3);
  const items = [];
  const shodan = (q) => `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
  for (const c of ids) items.push({ engine: 'shodan', kind: 'cve', for: c, query: `vuln:${c}`, note: 'Shodan tags a service with a CVE from its banner version; a paid-tier filter. Exact for this CVE, blind to a host Shodan has not fingerprinted.', url: shodan(`vuln:${c}`) });
  const termKeys = terms.map(norm).filter(Boolean);
  const isNamed = (p) => termKeys.some((t) => t === norm(p.product) || t === norm(p.vendor) || (t.length >= 5 && norm(p.product).includes(t)));
  const apps = cpes.filter((p) => p.part === 'a');
  const ranked = [...apps.filter(isNamed), ...apps.filter((p) => !isNamed(p))];
  const seen = new Set();
  for (const p of ranked) {
    const key = `${p.vendor}:${p.product}`;
    if (seen.has(key) || seen.size >= 4) continue;
    seen.add(key);
    const name = productName(p.product);
    const affected = p.ranges.length ? `Affected per NVD: ${p.ranges.join('; ')}.` : '';
    const cpe22 = `cpe:/${p.part}:${p.vendor}:${p.product}`;
    items.push({ engine: 'shodan', kind: 'cpe', for: key, query: `cpe:"${cpe22}"`, note: `Every ${name} service Shodan fingerprinted, any version (CPE 2.2 form of ${p.cpe23}). ${affected}`.trim(), url: shodan(`cpe:"${cpe22}"`) });
    items.push({ engine: 'shodan', kind: 'product', for: key, query: `product:"${name}"`, note: `Banner product name, NVD's spelling; adjust if Shodan's differs. ${affected}`.trim(), url: shodan(`product:"${name}"`) });
    items.push({ engine: 'censys', kind: 'product', for: key, query: `host.services: (software.product = "${name}")`, note: `Censys Platform host search, software as fingerprinted at layer 7. ${affected}`.trim(), url: null });
  }
  const products = [...seen];
  const skipped = apps.length - products.length;
  // no CPE yet: the campaign's own name for the software, so the card is not blind to the product
  const names = !apps.length && ids.length ? [...new Set(named.map((n) => String(n || '').trim()).filter((n) => /^[A-Za-z][A-Za-z0-9 .+-]{2,59}$/.test(n)))].slice(0, 2) : [];
  const aff = affected.length ? ` Affected per the card: ${affected.slice(0, 3).map((a) => String(a).slice(0, 100)).join('; ')}.` : '';
  for (const n of names) {
    const key = `named:${norm(n)}`;
    items.push({ engine: 'shodan', kind: 'named', for: key, query: `product:"${n}"`, note: `The name the campaign uses (NVD has not named the software yet): Shodan's product field, for software that is itself the service.${aff}`.trim(), url: shodan(`product:"${n}"`) });
    items.push({ engine: 'shodan', kind: 'named', for: key, query: `http.component:"${n}"`, note: `The same name as a web component: a CMS or web application Shodan fingerprints behind the web server. Component versions are not a search filter; compare the banner's version with the affected range in your own tool.${aff}`.trim(), url: shodan(`http.component:"${n}"`) });
    items.push({ engine: 'censys', kind: 'named', for: key, query: `host.services: (software.product = "${n}")`, note: `Censys Platform host search, software as fingerprinted at layer 7.${aff}`.trim(), url: null });
  }
  const note = !ids.length ? 'No CVE in this campaign: nothing an internet scanner keys on. Scope by product in your own tool.'
    : !apps.length ? `NVD has not published CPE configurations for these CVEs yet, so only the CVE query is exact${names.length ? `; the product queries use the name the campaign gives (${names.join(', ')}) and are replaced by NVD's spelling at the daily re-check once it names the software` : '; product queries appear here at the daily re-check once NVD names the software'}.`
      : skipped > 0 ? `NVD names ${skipped} more affected product${skipped === 1 ? '' : 's'} (libraries and embedders); the CVE query covers them where Shodan has fingerprinted the version.` : null;
  return { built_at: new Date(now).toISOString(), items: items.slice(0, 16), products, note };
}

const fmtN = (n) => Number(n).toLocaleString('en-US');

/**
 * What Shodan said about one query, as a line (lib/shodan.js writes `check`, `total`, `counted_at`):
 * the internet-wide total with the earliest and previous points of the card's trend, a zero as
 * "matches nothing under this spelling", or why there is no count. Mirrored in public/cards/lifecycle.js.
 */
/** The earliest and the previous trend point for a query, each as "N on <day> (±delta ±pct%)", plus the direction since the first. */
function trendRefs(i, trend = []) {
  const day = String(i.counted_at || '').slice(0, 10);
  const pts = (trend || []).filter((t) => t?.totals && t.totals[i.query] != null && t.at !== day);
  const ref = (t) => { const a = t.totals[i.query]; const d = (i.total || 0) - a; const pct = a ? ` ${d >= 0 ? '+' : '-'}${Math.round(Math.abs(d) / a * 100)}%` : ''; return `${fmtN(a)} on ${t.at} (${d >= 0 ? '+' : '-'}${fmtN(Math.abs(d))}${pct})`; };
  const refs = pts.length ? [pts[0], ...(pts.length > 1 ? [pts[pts.length - 1]] : [])].map(ref) : [];
  const first = pts[0]?.totals[i.query];
  return { refs, dir: first == null ? '' : (i.total || 0) > first ? 'up' : (i.total || 0) < first ? 'down' : 'flat' };
}

export function countLine(i, trend = []) {
  if (!i?.check) return '';
  const day = String(i.counted_at || '').slice(0, 10);
  if (i.check === 'counted' || i.check === 'empty') {
    const { refs } = trendRefs(i, trend);
    const head = i.check === 'empty' ? `Shodan: 0 services match this spelling (${day})${i.check_note ? ` — ${i.check_note}` : ''}` : `Shodan: ${fmtN(i.total)} services internet-wide (${day})`;
    return [head, ...refs].join(' · ');
  }
  return i.check === 'plan' || i.check === 'skipped' ? `Shodan count: ${i.check_note}` : `Shodan count failed: ${i.check_note}`;
}

/**
 * The same, as HTML the eye lands on: the number as a badge (accent for a hit, muted for a zero),
 * the label after it, the trend in mono coloured by direction (up is more exposure). Classes
 * `cnt hit|zero|off`, `num`, `lbl`, `trd up|down|flat`; styled in api/page.js and inline in lifecycle.js.
 */
export function countHtml(i, trend = []) {
  if (!i?.check) return '';
  const day = String(i.counted_at || '').slice(0, 10);
  if (i.check === 'counted' || i.check === 'empty') {
    const { refs, dir } = trendRefs(i, trend);
    const zero = i.check === 'empty';
    const lbl = zero ? `match this spelling on Shodan · ${day}${i.check_note ? ` — ${i.check_note}` : ''}` : `services internet-wide on Shodan · ${day}`;
    return `<p class="cnt ${zero ? 'zero' : 'hit'}"><span class="num">${fmtN(i.total || 0)}</span><span class="lbl">${esc(lbl)}</span>${refs.length ? `<span class="trd ${dir}">${dir === 'up' ? '▲' : dir === 'down' ? '▼' : '▬'} ${esc(refs.join(' · '))}</span>` : ''}</p>`;
  }
  return `<p class="cnt off"><span class="lbl">${esc(countLine(i))}</span></p>`;
}

/** The trend as rows [query, first point, latest point, change] for every query with two or more days of counts. */
export function trendRows(trend = []) {
  const byQ = new Map();
  for (const t of trend || []) for (const [q, n] of Object.entries(t?.totals || {})) { if (!byQ.has(q)) byQ.set(q, []); byQ.get(q).push({ at: t.at, n }); }
  const rows = [];
  for (const [q, pts] of byQ) {
    if (pts.length < 2) continue;
    const a = pts[0]; const b = pts[pts.length - 1]; const d = b.n - a.n;
    rows.push({ query: q, first: a, latest: b, delta: d, pct: a.n ? Math.round(d / a.n * 100) : null, points: pts.length });
  }
  return rows;
}

/** The exposure section as HTML: one row per query with Shodan's count, the trend, the scope note, the NVD caveat. */
export function exposureTable(ex) {
  if (!ex) return '<p class="s">No exposure query has been generated yet.</p>';
  // one block per query, not a table: a <pre> in a table cell collapses to one character a line on a phone
  const rows = (ex.items || []).map((i) => `<div class="xq" style="margin:0 0 10px"><p class="k" style="margin:0">${esc(i.engine)} <span class="s">· ${esc(i.kind)}${i.for ? ` · ${esc(i.for)}` : ''}</span></p><pre style="margin:4px 0">${esc(i.query)}</pre><p class="s" style="margin:0">${i.url ? `<a href="${esc(i.url)}">open</a> · ` : ''}${esc(i.note)}</p>${countHtml(i, ex.trend)}</div>`);
  const tr = trendRows(ex.trend);
  const trend = tr.length ? `<p class="k">Internet-wide count, trend</p><table><tr><th>Query</th><th>First</th><th>Latest</th><th>Change</th></tr>${tr.map((r) => `<tr><td><code>${esc(r.query)}</code></td><td>${fmtN(r.first.n)} <span class="s">${esc(r.first.at)}</span></td><td>${fmtN(r.latest.n)} <span class="s">${esc(r.latest.at)}</span></td><td>${r.delta >= 0 ? '+' : '-'}${fmtN(Math.abs(r.delta))}${r.pct != null ? ` (${r.delta >= 0 ? '+' : '-'}${Math.abs(r.pct)}%)` : ''} <span class="s">over ${r.points} days</span></td></tr>`).join('')}</table><p class="s">Shodan's count of matching services on the whole internet, one point a day; the scope (your ranges) is never part of it. A count moves with Shodan's crawl as much as with patching, so read the direction, not the digit.</p>` : '';
  const sh = (ex.shodan?.status === 'unset' ? `<p class="s">${esc(ex.shodan.note)}</p>` : ex.shodan?.note ? `<p class="s">Shodan: ${esc(ex.shodan.note)}.</p>` : '')
    + (ex.shodan?.aliases?.suggested ? `<p class="s">Banner spellings: a model read ${ex.shodan.aliases.suggested} from the NVD names and this card's text (former and marketing names, console titles); ${ex.shodan.aliases.matched} matched something on Shodan and ${ex.shodan.aliases.matched === 1 ? 'is' : 'are'} shown above, the rest ${ex.shodan.aliases.suggested - ex.shodan.aliases.matched === 1 ? 'was' : 'were'} dropped.</p>` : '');
  return rows.join('') + trend
    + (ex.note ? `<p class="s">${esc(ex.note)}</p>` : '')
    + (ex.named_tried?.length ? `<p class="s">Also tried under the name the card uses, nothing matched on Shodan: ${ex.named_tried.map((q) => `<code>${esc(q)}</code>`).join(', ')}.</p>` : '') + sh
    + `<p class="s">${esc(SCOPE_NOTE)} Generated automatically ${esc(String(ex.built_at).slice(0, 16).replace('T', ' '))}Z from the CVE ids and NVD's CPE configurations${ex.shodan?.status === 'ok' ? ', each Shodan query counted against Shodan itself' : ''}; re-built daily with the coverage check.</p>`;
}
