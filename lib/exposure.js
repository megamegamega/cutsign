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

/** The exposure section as HTML: one row per query, the scope note, the NVD caveat. */
export function exposureTable(ex) {
  if (!ex) return '<p class="s">No exposure query has been generated yet.</p>';
  const rows = (ex.items || []).map((i) => `<tr><td>${esc(i.engine)}</td><td><pre style="margin:0">${esc(i.query)}</pre></td><td class="s">${i.url ? `<a href="${esc(i.url)}">open</a> · ` : ''}${esc(i.note)}</td></tr>`);
  return (rows.length ? `<table><tr><th>Engine</th><th>Query</th><th>Reads</th></tr>${rows.join('')}</table>` : '')
    + (ex.note ? `<p class="s">${esc(ex.note)}</p>` : '')
    + `<p class="s">${esc(SCOPE_NOTE)} Generated automatically ${esc(String(ex.built_at).slice(0, 16).replace('T', ' '))}Z from the CVE ids and NVD's CPE configurations; re-built daily with the coverage check.</p>`;
}
