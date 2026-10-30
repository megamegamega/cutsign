// Shodan's own answer to the generated exposure queries, through its count endpoint
// (GET /shodan/host/count: the number of services matching a query, plus facets; it spends no
// query credits, and the API allows one request a second). It adds three things to a card:
//   - whether a query matches anything at all: a product NVD spells one way and Shodan another
//     returns nothing, which otherwise reads as "nothing exposed";
//   - Shodan's own spelling when it does not: the product and http.component facets of a text
//     search for the product's distinctive words, each candidate counted before it is shown;
//   - the internet-wide total, kept day by day as a trend on the card.
// The key is read from the environment, goes only to api.shodan.io and is never part of any
// stored text; a query never carries scope (no net:, org: or hostname:), only the generic filter.

const API = 'https://api.shodan.io';
const UA = 'Mozilla/5.0 (compatible; cutsign-coverage/1.0; +https://cutsign.vercel.app)';
const TIMEOUT_MS = 12_000;
export const MAX_CALLS = 12;         // a card's budget per check: ~13 s at the rate limit, inside the GitHub lane's wait
export const TREND_POINTS = 90;      // daily points kept per card
const GENERIC = new Set(['virtual', 'appliance', 'server', 'software', 'edition', 'enterprise', 'platform', 'services', 'service', 'manager', 'management', 'system', 'systems', 'suite', 'web', 'http', 'the', 'and', 'for']);

let shNext = 0; // module-level: every check in a sweep shares the key's one-a-second limit
async function spaced(minGapMs, sleep) { const t = Math.max(0, shNext - Date.now()); shNext = Math.max(shNext, Date.now()) + minGapMs; if (t) await sleep(t); }

/** One count call → { status, total, facets, error }. Never throws; the error text is Shodan's own, never the URL. */
export async function shodanCount(query, { key, facets = '', fetchImpl = fetch } = {}) {
  const url = `${API}/shodan/host/count?key=${encodeURIComponent(key)}&query=${encodeURIComponent(query)}${facets ? `&facets=${encodeURIComponent(facets)}` : ''}`;
  try {
    const r = await fetchImpl(url, { headers: { Accept: 'application/json', 'User-Agent': UA }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    let body = {}; try { body = JSON.parse(await r.text()); } catch { body = {}; }
    if (r.status !== 200) return { status: r.status, total: null, facets: {}, error: String(body?.error || `HTTP ${r.status}`).slice(0, 160) };
    return { status: 200, total: Number(body.total) || 0, facets: body.facets || {}, error: null };
  } catch (e) { return { status: 0, total: null, facets: {}, error: String(e?.message || e).slice(0, 160) }; }
}

/** Why a count failed: the key itself, the key's plan (vuln: needs a higher one), the rate limit, or something else. */
export const failureKind = (r) => (r.status === 401 && /invalid|unauthori[sz]ed|no api key/i.test(r.error || '')) ? 'key'
  : ((r.status === 401 || r.status === 403) && /upgrade|plan|access denied|membership|not allowed/i.test(r.error || '')) ? 'plan'
    : r.status === 429 ? 'rate' : 'failed';

const words = (s) => String(s || '').toLowerCase().split(/[^a-z0-9.]+/).filter((w) => w.length >= 3 && !GENERIC.has(w));
const flat = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/** The text searched to learn Shodan's spelling: the product's distinctive words ("Panorama Virtual Appliance" → Panorama; "Php" → Php). */
export function discoveryText(name) {
  const w = String(name || '').split(/\s+/).filter((x) => x && !GENERIC.has(x.toLowerCase()));
  return (w.length ? w : String(name || '').split(/\s+/)).join(' ').trim();
}

/** Is a facet value Shodan's name for this product (shares a word with the NVD vendor or product), not just a neighbour in the same banners (nginx next to PHP)? */
export function relevant(value, { vendor = '', product = '' } = {}) {
  const mine = new Set([...words(vendor), ...words(product), flat(product)].filter(Boolean));
  const theirs = words(value);
  const vflat = flat(value);
  return theirs.some((t) => mine.has(t)) || [...mine].some((m) => m.length >= 3 && vflat.includes(m)) || theirs.some((t) => t.length >= 4 && flat(product).includes(t));
}

const fmtDay = (ms) => new Date(ms).toISOString().slice(0, 10);
const shodanUrl = (q) => `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;

/**
 * Count every Shodan query of an exposure block, add Shodan's own spelling where NVD's matched
 * nothing, and carry the day's totals onto the trend. Returns a new exposure object; the input is
 * not changed. Without a key the block is returned with `shodan.status = 'unset'` and the previous
 * trend carried, so a key added later picks up where the counts left off.
 * @param cpes  nvdCpes() output (vendor/product per `for` key) for the discovery search
 * @param prev  the previous check's exposure block (its trend is carried forward)
 */
export async function validateExposure(ex, { key = '', cpes = [], prev = null, fetchImpl = fetch, now = Date.now(), minGapMs = 1100, sleep = (ms) => new Promise((res) => setTimeout(res, ms)), maxCalls = MAX_CALLS } = {}) {
  if (!ex) return ex;
  const day = fmtDay(now);
  const trend = (prev?.trend || []).filter((t) => t && t.at !== day).slice(-(TREND_POINTS - 1));
  const base = { ...ex, items: (ex.items || []).map((i) => ({ ...i })) };
  if (trend.length) base.trend = trend;
  if (!key) return { ...base, shodan: { status: 'unset', note: 'Internet-wide counts need SHODAN_API_KEY (Shodan\'s count endpoint; it spends no query credits).' } };

  const at = new Date(now).toISOString();
  let calls = 0; let planBlocked = false; let keyBad = null;
  const count = async (q, facets = '') => { if (calls >= maxCalls) return null; calls++; await spaced(minGapMs, sleep); return shodanCount(q, { key, facets, fetchImpl }); };
  const mark = (it, check, note) => { it.check = check; it.check_note = String(note || '').slice(0, 200); it.counted_at = at; };
  const totals = {};

  for (const it of base.items) {
    if (it.engine !== 'shodan') continue;
    if (keyBad) { mark(it, 'failed', keyBad); continue; }
    if (it.kind === 'cve' && planBlocked) { mark(it, 'plan', 'vuln: is a paid-tier filter the key\'s plan does not include'); continue; }
    const r = await count(it.query);
    if (!r) { mark(it, 'skipped', 'not counted this check (the card\'s call budget); counted at the next daily check'); continue; }
    if (r.status === 200) { it.total = r.total; it.check = r.total ? 'counted' : 'empty'; it.check_note = ''; it.counted_at = at; totals[it.query] = r.total; continue; }
    const k = failureKind(r);
    if (k === 'key') { keyBad = `SHODAN_API_KEY is not accepted (${r.error})`; mark(it, 'failed', keyBad); continue; }
    if (k === 'plan') { if (it.kind === 'cve') planBlocked = true; mark(it, 'plan', `the key's plan does not include this filter (${r.error})`); continue; }
    mark(it, 'failed', k === 'rate' ? `rate limited (${r.error}); counted at the next daily check` : r.error);
  }

  // Shodan's own spelling, for a product none of whose queries matched: one text search with facets, then each candidate counted
  const out = [];
  for (const it of base.items) {
    out.push(it);
    const key2 = it.for;
    if (it.engine !== 'censys' || !key2) continue; // the censys row closes a product's group
    const mine = base.items.filter((x) => x.engine === 'shodan' && x.for === key2 && x.kind !== 'discovered');
    if (!mine.length || !mine.every((x) => x.check === 'empty')) continue;
    const p = cpes.find((c) => `${c.vendor}:${c.product}` === key2) || { vendor: key2.split(':')[0], product: key2.split(':').slice(1).join(':') };
    const name = (mine.find((x) => x.kind === 'product')?.query.match(/^product:"(.*)"$/) || [])[1] || p.product;
    const text = discoveryText(name);
    const r = await count(text, 'product:5,http.component:5,cpe:5');
    if (!r || r.status !== 200) continue;
    const affected = (mine[0].note.match(/Affected per NVD:.*$/) || [''])[0];
    const cands = [
      ...(r.facets.product || []).filter((f) => relevant(f.value, p)).map((f) => ({ query: `product:"${f.value}"`, via: 'product' })),
      ...(r.facets['http.component'] || []).filter((f) => relevant(f.value, p)).map((f) => ({ query: `http.component:"${f.value}"`, via: 'http.component' })),
    ].filter((c, i, a) => a.findIndex((x) => x.query === c.query) === i).slice(0, 2);
    const stored = (r.facets.cpe || []).map((f) => String(f.value)).find((v) => v.startsWith(`cpe:/a:${p.vendor}:${p.product}`));
    const cpeItem = mine.find((x) => x.kind === 'cpe');
    if (stored && cpeItem) cpeItem.check_note = `Shodan stores this CPE with its version (e.g. ${stored}), so the versionless form matches nothing`;
    for (const c of cands) {
      const rc = await count(c.query);
      if (!rc || rc.status !== 200 || !rc.total) continue;
      totals[c.query] = rc.total;
      out.push({ engine: 'shodan', kind: 'discovered', for: key2, query: c.query, note: `Shodan's own spelling, from the ${c.via} facet of a text search for "${text}"; counted before it was shown. ${affected}`.trim(), url: shodanUrl(c.query), total: rc.total, check: 'counted', check_note: '', counted_at: at });
    }
  }
  base.items = out;
  if (Object.keys(totals).length) base.trend = [...trend, { at: day, totals }];
  const counted = out.filter((i) => i.check === 'counted').length;
  base.shodan = { status: keyBad ? 'failed' : 'ok', at, calls, counted, note: keyBad || (planBlocked ? 'vuln: needs a higher Shodan plan; product queries counted' : '') };
  return base;
}
