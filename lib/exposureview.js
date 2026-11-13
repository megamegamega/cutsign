// The Exposure tab (api/page.js ?view=exposure): every card's generic internet-scanner queries
// (lib/exposure.js) with Shodan's internet-wide count and trend (lib/shodan.js), in one place and
// in a form a shell script can read. Three renderings of one report: the page, JSON, and a
// tab-separated table with one query per line (`IFS=$'\t' read`, awk -F'\t', cut).
// Nothing is fetched or counted here: the numbers are the ones the daily coverage check already
// stored on each card. Like the cards, this holds the generic half only; the ranges, org name and
// domains that scope a query to one estate are never generated, stored or rendered. The reader
// appends them in their own tool, on their own machine.

import { countHtml } from './exposure.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = (n) => Number(n).toLocaleString('en-US');
const DAY = 86_400_000;

// What the reader appends to a query. Placeholders only.
export const SCOPE = {
  shodan: ['net:<your_ranges>', 'org:"<your_org>"', 'hostname:<your_domain>'],
  censys: ['host.ip: <your_ranges>', 'host.dns.names: <your_domain>'],
  how: 'Append one of these to a query in your own tool, on your own machine. Cutsign never receives, stores or shows a scope.',
};

// One query per line. Order is part of the contract: new columns are only ever added at the end.
export const TSV_COLUMNS = ['card', 'date', 'lane', 'cves', 'kev', 'engine', 'kind', 'product', 'check', 'count', 'count_7d_ago', 'counted_at', 'query', 'url', 'affected'];

// The most specific query first: a CVE tag is exact, a CPE is the product as NVD names it, then the
// product field, then spellings found or suggested. The headline is the first of these that counted.
const KIND_RANK = { cve: 0, cpe: 1, product: 2, named: 3, discovered: 4, alias: 5 };
const rank = (k) => KIND_RANK[k] ?? 9;

/** The affected-version text a query's note carries ("Affected per NVD: < 24.3.1."), or ''. */
const affectedOf = (note) => ((String(note || '').match(/Affected per (?:NVD|the card): (.*?)\.?$/) || [])[1] || '').trim();

/** A query's counts day by day, oldest first, from the card's trend. */
const pointsOf = (query, trend) => (trend || []).filter((t) => t?.totals && t.totals[query] != null).map((t) => ({ at: t.at, count: t.totals[query] }));

/**
 * Every active card's exposure queries as one report.
 * @param cards       manifest entries (hand-written and AI-published), any status
 * @param coverageOf  (card) → the card's stored coverage check, or null
 * @param kevOf       (card) → { CVE: {...} } for the card's CVEs in CISA KEV
 * @param base        the site's public origin, for absolute links a script can follow
 */
export function exposureReport(cards, { coverageOf = () => null, kevOf = () => ({}), base = 'https://cutsign.vercel.app', now = Date.now() } = {}) {
  const out = []; const none = [];
  for (const c of cards.filter((x) => x.status === 'active')) {
    const cov = coverageOf(c) || null;
    const ex = cov?.exposure || null;
    const url = `${base}${c.url}`;
    const items = ex?.items || [];
    if (!items.length) {
      none.push({ card: c.slug, title: c.title, date: c.date, url, why: ex?.note || (cov ? 'No exposure query could be generated for this card.' : 'Not checked yet.') });
      continue;
    }
    const queries = items.map((i) => {
      const pts = pointsOf(i.query, ex.trend);
      const counted = i.check === 'counted' || i.check === 'empty';
      const count = counted ? Number(i.total) || 0 : null;
      // the newest point that is at least seven days older than this count
      const day = String(i.counted_at || '').slice(0, 10);
      const weekCut = day ? new Date(Date.parse(day) - 7 * DAY).toISOString().slice(0, 10) : '';
      const week = counted && weekCut ? pts.filter((p) => p.at <= weekCut).at(-1) || null : null;
      return {
        engine: i.engine, kind: i.kind, product: i.for || null, query: i.query, url: i.url || null,
        check: i.check || (i.engine === 'shodan' ? 'pending' : 'not_counted'),
        count, counted_at: i.counted_at || null,
        week_ago: week, change_7d: week && count != null ? count - week.count : null,
        first: counted && pts.length ? pts[0] : null,
        affected: affectedOf(i.note) || null, note: i.note || '', check_note: i.check_note || '',
        trend: pts.slice(-30),
      };
    });
    const hits = queries.filter((q) => q.check === 'counted').sort((a, b) => rank(a.kind) - rank(b.kind) || b.count - a.count);
    const h = hits[0] || null;
    out.push({
      card: c.slug, title: c.title, date: c.date, lane: c.lane || '', source: c.source || 'hand', url,
      cves: c.cves || [], kev: Object.keys(kevOf(c) || {}),
      checked_at: cov.checked_at || null, shodan: ex.shodan?.status || null, note: ex.note || null,
      headline: h ? { query: h.query, kind: h.kind, count: h.count, counted_at: h.counted_at, change_7d: h.change_7d } : null,
      queries,
    });
  }
  out.sort((a, b) => String(b.date).localeCompare(String(a.date)) || a.card.localeCompare(b.card));
  const all = out.flatMap((c) => c.queries);
  return {
    kind: 'cutsign.exposure', generated: new Date(now).toISOString(),
    note: 'Public OSINT only. Each query is the generic half of an attack-surface check: what the vulnerable software looks like to an internet scanner, built from the CVE ids and NVD CPE configurations of a verdict card. count is the number of services Shodan matches internet-wide (its count endpoint), re-counted daily; a count is how widespread the software is, not how many of those services are vulnerable. Compare the banner version with the affected range.',
    scope: SCOPE,
    endpoints: { html: `${base}/exposure`, json: `${base}/exposure.json`, tsv: `${base}/exposure.tsv` },
    tsv_columns: TSV_COLUMNS,
    totals: { cards: out.length, queries: all.length, counted: all.filter((q) => q.check === 'counted').length, cards_without_queries: none.length },
    cards: out,
    without_queries: none,
  };
}

// A field can never be empty or hold a tab: bash treats a tab in IFS as whitespace and folds two
// in a row into one, which would shift every later column. A dash stands in for "nothing".
const cell = (v) => { const s = String(v ?? '').replace(/[\t\r\n]+/g, ' ').trim(); return s || '-'; };

/** The report as tab-separated text: a header line, then one line per query, newest card first. */
export function exposureTsv(report) {
  const lines = [TSV_COLUMNS.join('\t')];
  for (const c of report.cards) for (const q of c.queries) {
    lines.push([c.card, c.date, c.lane, c.cves.join(','), c.kev.join(','), q.engine, q.kind, q.product, q.check,
      q.count ?? '', q.week_ago ? q.week_ago.count : '', q.counted_at ? String(q.counted_at).slice(0, 10) : '', q.query, q.url, q.affected].map(cell).join('\t'));
  }
  return `${lines.join('\n')}\n`;
}

/**
 * The self-check, as a script the page prints and the tests run: the reader's own count beside the
 * internet-wide one for every query Shodan matched. The scope and the key come from the reader's
 * environment and go only to Shodan.
 */
export const selfCheckScript = (base = 'https://cutsign.vercel.app') => `#!/usr/bin/env bash
# Your own count beside the internet-wide one, for every query Shodan matched.
# Needs curl, jq and your Shodan API key. SCOPE is your estate as a Shodan filter;
# it stays in your shell and goes only to Shodan:
#   export SCOPE='net:<your_ranges>'      (or org:"<your_org>", hostname:<your_domain>)
set -euo pipefail
: "\${SHODAN_API_KEY:?set SHODAN_API_KEY}" "\${SCOPE:?set SCOPE}"
printf 'mine\\tinternet\\tcard\\tcves\\tquery\\n'
curl -fsS ${base}/exposure.tsv | tail -n +2 |
while IFS=$'\\t' read -r card date lane cves kev engine kind product check count week counted_at query url affected; do
  [ "$engine" = shodan ] && [ "$check" = counted ] || continue
  mine=$(curl -fsS -G https://api.shodan.io/shodan/host/count \\
    --data-urlencode "key=$SHODAN_API_KEY" \\
    --data-urlencode "query=$query $SCOPE" </dev/null | jq -r '.total // "?"') || mine='?'
  printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "$mine" "$count" "$card" "$cves" "$query"
  sleep 1.1
done`;

export const EXPOSURE_STYLE = `
.xp-rank{width:100%;border-collapse:collapse;margin:8px 0 18px;font-size:13px}
.xp-rank th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);font-weight:600;padding:4px 8px;border-bottom:1px solid var(--line)}
.xp-rank td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.xp-rank td.n{font-variant-numeric:tabular-nums;font-weight:700;text-align:right;white-space:nowrap}
.xp-rank th.n{text-align:right}
.xp-rank .up{color:var(--bad)} .xp-rank .down{color:var(--acc)} .xp-rank .flat{color:var(--mut)}
.xp-q{margin:0 0 12px}
.xp-q pre{margin:4px 0}
.xp-kev{color:var(--bad)}
`;

const chg = (n) => n == null ? '<span class="flat">–</span>' : n > 0 ? `<span class="up">▲ +${fmtN(n)}</span>` : n < 0 ? `<span class="down">▼ −${fmtN(-n)}</span>` : '<span class="flat">▬ 0</span>';

/** The Exposure tab's body. */
export function exposureBody(report, { base = 'https://cutsign.vercel.app' } = {}) {
  const t = report.totals;
  const hero = `<div class="hero"><h1>Exposure</h1><p class="sub">${t.counted} quer${t.counted === 1 ? 'y' : 'ies'} with a live internet-wide count, ${t.queries} in all, across ${t.cards} active card${t.cards === 1 ? '' : 's'} · counted by Shodan, re-counted daily with each card · the same queries each card carries, in one place</p></div>`;

  const how = '<h3 style="border:none;padding-top:0">Use it from a script</h3>'
    + `<pre>GET ${esc(base)}/exposure.tsv     one query per line, tab-separated, header on line 1
GET ${esc(base)}/exposure.json    the same, grouped by card, with notes and the daily trend

columns  ${TSV_COLUMNS.map((c, i) => `${i + 1} ${c}`).join('  ')}
check    counted (count &gt; 0) · empty (0 under this spelling) · plan, skipped, failed (no count) · not_counted (Censys)
empty    a field is never empty: a dash stands in, so IFS=$'\\t' read keeps its columns
count    services Shodan matches internet-wide: how widespread the software is, not how many are vulnerable</pre>`
    + '<p class="s">The ten most widespread, from a shell:</p>'
    + `<pre>curl -fsS ${esc(base)}/exposure.tsv | awk -F'\\t' 'NR&gt;1 &amp;&amp; $9=="counted"' | sort -t$'\\t' -k10,10nr | cut -f1,4,10,13 | head</pre>`
    + '<p class="s">Your own exposure beside it. The script reads your scope from your shell and sends it only to Shodan, with your own key; the count endpoint spends no query credits, and a <code>vuln:</code> row needs a plan that has that filter:</p>'
    + `<pre>${esc(selfCheckScript(base))}</pre>`
    + `<p class="s">${esc(SCOPE.how)} Shodan: ${SCOPE.shodan.map((s) => `<code>${esc(s)}</code>`).join(', ')}. Censys: ${SCOPE.censys.map((s) => `<code>${esc(s)}</code>`).join(', ')}. No key: every Shodan row has an <b>open</b> link; add the scope in the search box. A hit is a service to check, not a finding: compare its banner version with the affected range.</p>`;

  const ranked = report.cards.filter((c) => c.headline).sort((a, b) => b.headline.count - a.headline.count);
  const rankHtml = ranked.length ? '<h3 style="border:none">Most widespread</h3>'
    + '<p class="s">One line per card: its most specific query that Shodan matched (a CVE tag before a CPE, a CPE before a product name).</p>'
    + `<table class="xp-rank"><tr><th class="n">Services</th><th>7 days</th><th>Card</th><th>CVEs</th></tr>${ranked.map((c) => `<tr><td class="n">${fmtN(c.headline.count)}</td><td>${chg(c.headline.change_7d)}</td>`
      + `<td><a href="#${esc(c.card)}">${esc(c.title)}</a><div class="s"><code>${esc(c.headline.query)}</code></div></td>`
      + `<td>${c.cves.map((v) => `<span class="${c.kev.includes(v) ? 'xp-kev' : ''}">${esc(v)}${c.kev.includes(v) ? ' (KEV)' : ''}</span>`).join('<br>') || '<span class="s">none</span>'}</td></tr>`).join('')}</table>` : '';

  // the card's trend shape for countHtml: the first point ever, then the last thirty days
  const trendOf = (q) => (q.first && q.trend[0]?.at !== q.first.at ? [q.first, ...q.trend] : q.trend).map((p) => ({ at: p.at, totals: { [q.query]: p.count } }));
  const qBlock = (q) => `<div class="xp-q"><p class="k" style="margin:0">${esc(q.engine)} <span class="s">· ${esc(q.kind)}${q.product ? ` · ${esc(q.product)}` : ''}</span></p>`
    + `<pre>${esc(q.query)}</pre>`
    + (q.engine === 'shodan' && q.check !== 'pending' ? countHtml({ query: q.query, check: q.check, total: q.count ?? 0, counted_at: q.counted_at, check_note: q.check_note }, trendOf(q)) : '')
    + `<p class="s" style="margin:4px 0 0">${q.url ? `<a href="${esc(q.url)}">open</a>` : 'paste into Censys search'}${q.affected ? ` · affected: ${esc(q.affected)}` : ''}</p></div>`;
  const cardBlock = (c) => {
    const live = c.queries.filter((q) => q.check === 'counted' || q.engine !== 'shodan');
    const rest = c.queries.filter((q) => !live.includes(q));
    return `<div class="card" id="${esc(c.card)}"><div class="chead"><h3><a href="${esc(c.url)}">${esc(c.title)}</a></h3></div>`
      + `<div><span class="c">${esc(c.lane)}</span><span class="c">as of ${esc(c.date)}</span>${c.cves.map((v) => `<a class="c${c.kev.includes(v) ? ' xp-kev' : ''}" href="/?q=${encodeURIComponent(v)}">${esc(v)}${c.kev.includes(v) ? ' · KEV' : ''}</a>`).join('')}<a class="c" href="${esc(c.url)}">open card</a></div>`
      + `<div style="margin-top:10px">${live.map(qBlock).join('')}</div>`
      + (rest.length ? `<details><summary class="s">${rest.length} more quer${rest.length === 1 ? 'y' : 'ies'} Shodan matched nothing for, or could not count</summary>${rest.map(qBlock).join('')}</details>` : '')
      + (c.note ? `<p class="s">${esc(c.note)}</p>` : '') + '</div>';
  };
  const cardsHtml = report.cards.length ? `<h3 style="border:none">By card, newest first</h3>${report.cards.map(cardBlock).join('\n')}` : '<p class="s">No card carries an exposure query yet.</p>';
  const noneHtml = report.without_queries.length
    ? `<details><summary class="s">${report.without_queries.length} active card${report.without_queries.length === 1 ? '' : 's'} with nothing an internet scanner keys on</summary>${report.without_queries.map((c) => `<p class="s"><a href="${esc(c.url)}">${esc(c.title)}</a> — ${esc(c.why)}</p>`).join('')}</details>` : '';
  return `${hero}<div class="w">${how}${rankHtml}${cardsHtml}${noneHtml}</div>`;
}
