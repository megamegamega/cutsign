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

/**
 * The generic EASM queries for a campaign: by CVE (Shodan's `vuln:` filter, a paid-tier filter) and
 * by NVD CPE (Shodan `cpe:` and `product:`, Censys `software.product`). `cpes` is nvdCpes() output
 * across the campaign's CVEs; NVD lists the library and every product that embeds it, so the
 * products the campaign names (`terms`, from its title) come first and at most four are kept;
 * operating systems and hardware (parts o, h) are the platform, not the service, and are skipped.
 * Returns { built_at, items[], products[], note }.
 */
export function exposureQueries({ cves = [], cpes = [], terms = [], now = Date.now() } = {}) {
  const ids = [...new Set(cves.filter((c) => CVE_RE.test(c)))].slice(0, 3);
  const items = [];
  const shodan = (q) => `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
  for (const c of ids) items.push({ engine: 'shodan', kind: 'cve', for: c, query: `vuln:${c}`, note: 'Shodan tags a service with a CVE from its banner version; a paid-tier filter. Exact for this CVE, blind to a host Shodan has not fingerprinted.', url: shodan(`vuln:${c}`) });
  const named = terms.map(norm).filter(Boolean);
  const isNamed = (p) => named.some((t) => t === norm(p.product) || t === norm(p.vendor) || (t.length >= 5 && norm(p.product).includes(t)));
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
  const note = !ids.length ? 'No CVE in this campaign: nothing an internet scanner keys on. Scope by product in your own tool.'
    : !apps.length ? 'NVD has not published CPE configurations for these CVEs yet, so only the CVE query is exact; product queries appear here at the daily re-check once NVD names the software.'
      : skipped > 0 ? `NVD names ${skipped} more affected product${skipped === 1 ? '' : 's'} (libraries and embedders); the CVE query covers them where Shodan has fingerprinted the version.` : null;
  return { built_at: new Date(now).toISOString(), items: items.slice(0, 16), products, note };
}

const fmtN = (n) => Number(n).toLocaleString('en-US');

/**
 * What Shodan said about one query, as a line (lib/shodan.js writes `check`, `total`, `counted_at`):
 * the internet-wide total with the earliest and previous points of the card's trend, a zero as
 * "matches nothing under this spelling", or why there is no count. Mirrored in public/cards/lifecycle.js.
 */
export function countLine(i, trend = []) {
  if (!i?.check) return '';
  const day = String(i.counted_at || '').slice(0, 10);
  if (i.check === 'counted' || i.check === 'empty') {
    const pts = (trend || []).filter((t) => t?.totals && t.totals[i.query] != null && t.at !== day);
    const ref = (t) => { const a = t.totals[i.query]; const d = (i.total || 0) - a; const pct = a ? ` ${d >= 0 ? '+' : '-'}${Math.round(Math.abs(d) / a * 100)}%` : ''; return `${fmtN(a)} on ${t.at} (${d >= 0 ? '+' : '-'}${fmtN(Math.abs(d))}${pct})`; };
    const refs = pts.length ? [pts[0], ...(pts.length > 1 ? [pts[pts.length - 1]] : [])].map(ref) : [];
    const head = i.check === 'empty' ? `Shodan: 0 services match this spelling (${day})${i.check_note ? ` — ${i.check_note}` : ''}` : `Shodan: ${fmtN(i.total)} services internet-wide (${day})`;
    return [head, ...refs].join(' · ');
  }
  return i.check === 'plan' || i.check === 'skipped' ? `Shodan count: ${i.check_note}` : `Shodan count failed: ${i.check_note}`;
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
  const rows = (ex.items || []).map((i) => { const c = countLine(i, ex.trend); return `<div class="xq" style="margin:0 0 10px"><p class="k" style="margin:0">${esc(i.engine)} <span class="s">· ${esc(i.kind)}${i.for ? ` · ${esc(i.for)}` : ''}</span></p><pre style="margin:4px 0">${esc(i.query)}</pre><p class="s" style="margin:0">${i.url ? `<a href="${esc(i.url)}">open</a> · ` : ''}${esc(i.note)}</p>${c ? `<p class="s" style="margin:0"><b>${esc(c)}</b></p>` : ''}</div>`; });
  const tr = trendRows(ex.trend);
  const trend = tr.length ? `<p class="k">Internet-wide count, trend</p><table><tr><th>Query</th><th>First</th><th>Latest</th><th>Change</th></tr>${tr.map((r) => `<tr><td><code>${esc(r.query)}</code></td><td>${fmtN(r.first.n)} <span class="s">${esc(r.first.at)}</span></td><td>${fmtN(r.latest.n)} <span class="s">${esc(r.latest.at)}</span></td><td>${r.delta >= 0 ? '+' : '-'}${fmtN(Math.abs(r.delta))}${r.pct != null ? ` (${r.delta >= 0 ? '+' : '-'}${Math.abs(r.pct)}%)` : ''} <span class="s">over ${r.points} days</span></td></tr>`).join('')}</table><p class="s">Shodan's count of matching services on the whole internet, one point a day; the scope (your ranges) is never part of it. A count moves with Shodan's crawl as much as with patching, so read the direction, not the digit.</p>` : '';
  const sh = ex.shodan?.status === 'unset' ? `<p class="s">${esc(ex.shodan.note)}</p>` : ex.shodan?.note ? `<p class="s">Shodan: ${esc(ex.shodan.note)}.</p>` : '';
  return rows.join('') + trend
    + (ex.note ? `<p class="s">${esc(ex.note)}</p>` : '') + sh
    + `<p class="s">${esc(SCOPE_NOTE)} Generated automatically ${esc(String(ex.built_at).slice(0, 16).replace('T', ' '))}Z from the CVE ids and NVD's CPE configurations${ex.shodan?.status === 'ok' ? ', each Shodan query counted against Shodan itself' : ''}; re-built daily with the coverage check.</p>`;
}
