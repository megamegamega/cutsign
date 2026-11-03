// The Actors tab (api/page.js ?view=actors): lib/actors.js's report as a world map shaded by
// attributed country, a week-by-week chart, a card per country with its adversaries and why each
// was attributed there, the tools seen across countries, and the actors no source places anywhere.
// Server-rendered SVG over lib/worldmap.json: no script, no network, prints and works without JS.

import { readFileSync } from 'node:fs';
import { CATEGORIES } from './actors.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// read on first use: a missing map leaves the page with its tables, never a broken site
let MAP;
export function worldMap() {
  if (MAP === undefined) {
    try { MAP = JSON.parse(readFileSync(new URL('./worldmap.json', import.meta.url), 'utf8')); } catch { MAP = null; }
  }
  return MAP;
}

export const WINDOWS = { 14: '14 days', 30: '30 days', 90: '90 days', all: 'All stored' };

export const ACTORS_STYLE = `
.am-bar{display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;margin:16px 0 4px}
.am-bar .grp{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.am-l{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--mut)}
.am-bar .tabs a,.am-bar .tabs span{white-space:nowrap}
.am-map{margin:14px 0 4px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px}
.am-map svg{display:block;width:100%;height:auto}
.am-sea{fill:var(--bg);stroke:var(--line)}
.am-c{fill:var(--panel2);stroke:var(--bg);stroke-width:.5}
a .am-c:hover,a .am-dot:hover{stroke:var(--acc);stroke-width:1.4}
.am-s1{fill:color-mix(in srgb,var(--bad) 18%,var(--panel2))}.am-s2{fill:color-mix(in srgb,var(--bad) 36%,var(--panel2))}
.am-s3{fill:color-mix(in srgb,var(--bad) 56%,var(--panel2))}.am-s4{fill:color-mix(in srgb,var(--bad) 78%,var(--panel2))}
.am-s5{fill:var(--bad)}
.am-dot{stroke:var(--text);stroke-width:.6}
.am-lab{font:700 12px var(--mono);fill:var(--text);paint-order:stroke;stroke:var(--bg);stroke-width:3px;stroke-linejoin:round;pointer-events:none}
.am-leg{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;font-size:11.5px;color:var(--mut);margin:8px 4px 0}
.am-leg i{display:inline-block;width:14px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.am-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin:10px 0}
.am-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0;scroll-margin-top:70px}
.am-card:target{outline:2px solid var(--acc);outline-offset:3px}
.am-card .hd{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.am-card .nm{font-weight:700;font-size:16px}
.am-card .big{margin-left:auto;font:800 22px var(--mono);color:var(--bad)}
.am-card .meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:12px;color:var(--mut);margin:4px 0 8px}
.am-card .up{color:var(--bad)} .am-card .down{color:var(--new)}
.am-card details{margin-top:8px;font-size:12.5px}
.am-card details li{margin:5px 0}
.am-card .why{color:var(--mut);font-size:11.5px}
.c.k-state{border-color:color-mix(in srgb,var(--bad) 55%,var(--chip-line))}
.c.k-crime{border-color:color-mix(in srgb,var(--acc) 65%,var(--chip-line))}
.c.k-hacktivist{border-color:color-mix(in srgb,var(--link) 65%,var(--chip-line))}
.c.k-spyware{border-color:color-mix(in srgb,var(--new) 65%,var(--chip-line))}
.c b{font-weight:700;margin-left:4px;color:var(--mut)}
.am-spark{vertical-align:middle}
.am-spark polyline{fill:none;stroke:var(--bad);stroke-width:1.5}
.am-spark circle{fill:var(--bad)}
/* a long run of weeks scrolls inside its box on a phone, opening on the newest (the right) */
.am-weeks{margin:8px 0;overflow-x:auto;direction:rtl}
.am-weeks svg{display:block;width:100%;height:auto;direction:ltr;margin:0 auto 0 0}
.am-weeks text{font:10.5px var(--mono);fill:var(--mut)}
.am-tools td{font-size:13px}
.am-tools td:first-child{font-family:var(--mono);font-weight:700;white-space:nowrap}
.am-k1{fill:var(--bad)}.am-k2{fill:var(--link)}.am-k3{fill:var(--acc)}.am-k4{fill:var(--new)}.am-k5{fill:#b392f0}.am-k6{fill:var(--mut)}
@media (prefers-color-scheme: light){.am-k5{fill:#8250df}}
.am-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.am-sw.am-k1{background:var(--bad)}.am-sw.am-k2{background:var(--link)}.am-sw.am-k3{background:var(--acc)}.am-sw.am-k4{background:var(--new)}.am-sw.am-k5{background:#b392f0}.am-sw.am-k6{background:var(--mut)}
@media (prefers-color-scheme: light){.am-sw.am-k5{background:#8250df}}`;

const sid8 = (id) => `s-${String(id).slice(0, 8)}`;
const storyHref = (st) => `/?d=${encodeURIComponent(st.date)}&view=analyst#${sid8(st.id)}`;
const fmtDay = (d) => { const t = new Date(`${d}T00:00:00Z`); return `${t.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${t.getUTCDate()}`; };

// shade level 1–5 for a value against the largest (square root, so one story still shows)
const level = (v, max) => (v > 0 && max > 0 ? Math.min(5, Math.max(1, Math.ceil(5 * Math.sqrt(v / max)))) : 0);

function mapSvg(report, metric) {
  const map = worldMap();
  if (!map) return '<p class="s">The world map could not be loaded; the counts below are complete.</p>';
  const val = (c) => (metric === 'adversaries' ? c.adversaries : c.stories);
  const byNum = new Map(report.countries.filter((c) => val(c) > 0).map((c) => [c.num, c]));
  const max = Math.max(0, ...[...byNum.values()].map(val));
  const tip = (c) => `${c.name}: ${c.stories} stor${c.stories === 1 ? 'y' : 'ies'}, ${c.adversaries} adversar${c.adversaries === 1 ? 'y' : 'ies'}`
    + (c.actors.length ? ` (${c.actors.slice(0, 6).map((a) => a.name).join(', ')}${c.actors.length > 6 ? ', …' : ''})` : '');
  const shapes = map.countries.map((m) => {
    const c = byNum.get(m.id);
    if (!c) return `<path class="am-c" d="${m.d}"/>`;
    // countries too small to see at this scale also get a dot at their centre
    const dot = m.d.length < 420 ? `<circle class="am-dot am-s${level(val(c), max)}" cx="${m.c[0]}" cy="${m.c[1]}" r="4"/>` : '';
    return `<a href="#c-${c.cc.toLowerCase()}"><path class="am-c am-s${level(val(c), max)}" d="${m.d}"><title>${esc(tip(c))}</title></path>${dot ? dot.replace('/>', `><title>${esc(tip(c))}</title></circle>`) : ''}</a>`;
  }).join('');
  // a country attributed but not drawn at 1:110m (e.g. Singapore) is listed under the map instead
  const drawn = new Set(map.countries.map((m) => m.id));
  const undrawn = [...byNum.values()].filter((c) => !drawn.has(c.num));
  // labels for the leaders: at the country's centre, else just above or below it, else none
  const placed = [];
  const labels = [...byNum.values()].sort((a, b) => val(b) - val(a)).slice(0, 6).map((c) => {
    const m = map.countries.find((x) => x.id === c.num);
    if (!m) return '';
    const text = `${c.name} ${val(c)}`; const half = text.length * 3.8 + 4;
    const spot = [0, -17, 17].map((dy) => [m.c[0], m.c[1] + dy])
      .find(([x, y]) => !placed.some(([px, py, ph]) => Math.abs(px - x) < ph + half && Math.abs(py - y) < 15));
    if (!spot) return '';
    placed.push([...spot, half]);
    return `<text class="am-lab" x="${spot[0]}" y="${spot[1] + 4}" text-anchor="middle">${esc(text)}</text>`;
  }).join('');
  // legend: the value range each shade covers
  const ranges = [];
  for (let v = 1; v <= max; v++) { const l = level(v, max); if (!ranges[l]) ranges[l] = [v, v]; else ranges[l][1] = v; }
  const legend = ranges.map((r, l) => (r ? `<span><i style="background:${l === 5 ? 'var(--bad)' : `color-mix(in srgb,var(--bad) ${[0, 18, 36, 56, 78][l]}%,var(--panel2))`}"></i>${r[0] === r[1] ? r[0] : `${r[0]}–${r[1]}`}</span>` : '')).join('');
  const label = `World map shaded by ${metric === 'adversaries' ? 'adversaries' : 'stories'} attributed to each country: `
    + [...byNum.values()].sort((a, b) => val(b) - val(a)).map((c) => `${c.name} ${val(c)}`).join(', ');
  return `<figure class="am-map" style="margin:14px 0 4px"><svg viewBox="${map.viewBox}" role="img" aria-label="${esc(label)}">`
    + `<defs><clipPath id="am-globe"><path d="${map.outline}"/></clipPath></defs><path class="am-sea" d="${map.outline}"/>`
    + `<g clip-path="url(#am-globe)">${shapes}</g>${labels}</svg>`
    + `<figcaption class="am-leg"><span class="am-l">${metric === 'adversaries' ? 'Adversaries' : 'Stories'}</span>${legend || '<span>nothing attributed in this window</span>'}`
    + `${undrawn.length ? `<span>· not drawn at this scale: ${undrawn.map((c) => `<a href="#c-${c.cc.toLowerCase()}">${esc(c.name)} ${val(c)}</a>`).join(', ')}</span>` : ''}`
    + '<span>· hover a country for its actors, click for its card</span></figcaption></figure>';
}

// stacked weekly bars: the five leading countries and the rest
function weeksSvg(report) {
  const top = report.countries.filter((c) => c.stories).slice(0, 5);
  const rest = report.countries.filter((c) => c.stories && !top.includes(c));
  const weeks = report.weeks;
  const series = [...top.map((c, i) => ({ name: c.name, k: i + 1, vals: c.weekly })),
    ...(rest.length ? [{ name: `${rest.length} other${rest.length === 1 ? '' : 's'}`, k: 6, vals: weeks.map((_, i) => rest.reduce((n, c) => (c.weekly[i] == null ? n : n + c.weekly[i]), 0)) }] : [])];
  const hasData = weeks.map((_, i) => report.countries.some((c) => c.weekly[i] != null));
  const totals = weeks.map((_, i) => series.reduce((n, s) => n + (s.vals[i] || 0), 0));
  const max = Math.max(1, ...totals);
  // the drawing's width follows the week count, so its text stays legible from phone to desktop
  const W = Math.max(360, 30 + 80 * weeks.length); const H = 150; const padL = 30; const padB = 22; const padT = 16; const bw = (W - padL) / weeks.length;
  const y = (v) => padT + (H - padB - padT) * (1 - v / max);
  const bars = weeks.map((w, i) => {
    const x = padL + i * bw + bw * 0.18; const wd = bw * 0.64;
    if (!hasData[i]) return `<rect x="${x.toFixed(1)}" y="${H - padB - 2}" width="${wd.toFixed(1)}" height="2" class="am-k6" opacity=".35"><title>week of ${fmtDay(w)}: no briefs stored yet</title></rect>`;
    let acc = 0;
    return series.map((s) => {
      const v = s.vals[i] || 0;
      if (!v) return '';
      const r = `<rect x="${x.toFixed(1)}" y="${y(acc + v).toFixed(1)}" width="${wd.toFixed(1)}" height="${(y(acc) - y(acc + v)).toFixed(1)}" class="am-k${s.k}"><title>week of ${fmtDay(w)}: ${esc(s.name)} ${v}</title></rect>`;
      acc += v;
      return r;
    }).join('') + (totals[i] ? `<text x="${(x + wd / 2).toFixed(1)}" y="${(y(totals[i]) - 4).toFixed(1)}" text-anchor="middle">${totals[i]}</text>` : '');
  }).join('');
  // every week labelled up to eight weeks, every other one (ending on this week) past that
  const xl = weeks.map((w, i) => (weeks.length > 8 && (weeks.length - 1 - i) % 2 ? '' : `<text x="${(padL + i * bw + bw / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">${fmtDay(w)}</text>`)).join('');
  const grid = [0, Math.round(max / 2), max].filter((v, i, a) => a.indexOf(v) === i)
    .map((v) => `<line x1="${padL}" x2="${W}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" stroke="var(--line)"/><text x="${padL - 6}" y="${(y(v) + 4).toFixed(1)}" text-anchor="end">${v}</text>`).join('');
  const legend = series.map((s) => `<span><span class="am-sw am-k${s.k}"></span>${esc(s.name)}</span>`).join('');
  return `<div class="am-weeks"><svg viewBox="0 0 ${W} ${H}" style="min-width:${Math.round(W * 0.6)}px;max-width:${Math.round(W * 1.4)}px" role="img" aria-label="Stories per week attributed to each of the leading countries, ${weeks.length} weeks">${grid}${bars}${xl}</svg></div>`
    + `<div class="am-leg">${legend}<span>· a story naming actors from two countries counts once for each</span></div>`;
}

const spark = (vals) => {
  const pts = vals.map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (pts.length < 2) return '';
  const max = Math.max(1, ...pts.map(([, v]) => v)); const W = 84; const H = 22; const n = vals.length - 1;
  const xy = pts.map(([i, v]) => [(i / n) * (W - 4) + 2, H - 2 - (v / max) * (H - 4)]);
  return `<svg class="am-spark" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="stories per week: ${pts.map(([, v]) => v).join(', ')}">`
    + `<polyline points="${xy.map(([x, yy]) => `${x.toFixed(1)},${yy.toFixed(1)}`).join(' ')}"/><circle cx="${xy.at(-1)[0].toFixed(1)}" cy="${xy.at(-1)[1].toFixed(1)}" r="2"/></svg>`;
};

const delta = (c) => {
  if (c.prev7 == null) return `<span title="the 7 days before had no stored briefs">${c.last7} in 7 days</span>`;
  const d = c.last7 - c.prev7;
  return `<span class="${d > 0 ? 'up' : d < 0 ? 'down' : ''}" title="stories in the last 7 days vs the 7 before">${c.last7} in 7 days ${d > 0 ? `▲${d}` : d < 0 ? `▼${-d}` : '='} (${c.prev7} before)</span>`;
};

// a named actor links to search (every story naming it); an unnamed one to its latest story. On a
// country's card the country goes without saying, so an unnamed actor there is just "unnamed"
const actorChip = (a, inCountry) => `<a class="c k-${esc(a.category)}" href="${esc(a.unnamed ? (a.latest ? storyHref(a.latest) : '#') : `/?q=${encodeURIComponent(a.name)}`)}" title="${esc(`${a.name} · ${CATEGORIES[a.category]}${a.aliases.length ? ` · also ${a.aliases.join(', ')}` : ''}`)}">${esc(a.unnamed && inCountry ? 'unnamed' : a.name)}<b>${a.stories}</b></a>`;

function countryCard(c, metric) {
  const cats = Object.entries(c.categories).map(([k, n]) => `${n} ${CATEGORIES[k].toLowerCase()}`).join(' · ');
  const why = c.actors.map((a) => `<li><b>${esc(a.name)}</b> <span class="s">· ${esc(CATEGORIES[a.category])} · ${a.stories} stor${a.stories === 1 ? 'y' : 'ies'}${a.aliases.length ? ` · also ${esc(a.aliases.join(', '))}` : ''}</span>`
    + `${a.basis.length ? `<div class="why">${a.basis.map(esc).join('<br>')}</div>` : ''}`
    + `${a.latest ? `<div class="why">latest: <a href="${storyHref(a.latest)}">${esc(a.latest.date)} · ${esc(a.latest.title)}</a></div>` : ''}</li>`).join('');
  return `<div class="am-card" id="c-${c.cc.toLowerCase()}"><div class="hd"><span class="nm">${esc(c.name)}</span><span class="s">${cats}</span>`
    + `<span class="big" title="${metric === 'adversaries' ? 'adversaries' : 'stories'}">${metric === 'adversaries' ? c.adversaries : c.stories}</span></div>`
    + `<div class="meta"><span>${c.stories} stor${c.stories === 1 ? 'y' : 'ies'} · ${c.adversaries} adversar${c.adversaries === 1 ? 'y' : 'ies'}</span>${spark(c.weekly)}${delta(c)}</div>`
    + `<div>${c.actors.map((a) => actorChip(a, true)).join('')}</div>`
    + (why ? `<details><summary>Why these attributions</summary><ul>${why}</ul></details>` : '') + '</div>';
}

/** The page body. params: { w, cat, m } as given (validated by the caller). */
export function actorsBody(report, { w, cat, m }) {
  const qs = (o) => {
    const p = { view: 'actors', w, cat, m, ...o };
    return '/?' + Object.entries(p).filter(([k, v]) => v && !(k === 'w' && v === '30') && !(k === 'm' && v === 'stories')).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  };
  const pill = (label, on, href) => (on ? `<span>${esc(label)}</span>` : `<a href="${esc(href)}">${esc(label)}</a>`);
  const bar = `<div class="am-bar">`
    + `<div class="grp"><span class="am-l">Window</span><nav class="tabs">${Object.entries(WINDOWS).map(([k, l]) => pill(l, String(w) === k, qs({ w: k }))).join('')}</nav></div>`
    + `<div class="grp"><span class="am-l">Kind</span><nav class="tabs">${pill('All', !cat, qs({ cat: null }))}${['state', 'crime', 'hacktivist', 'spyware'].map((k) => pill(CATEGORIES[k], cat === k, qs({ cat: k }))).join('')}</nav></div>`
    + `<div class="grp"><span class="am-l">Shade by</span><nav class="tabs">${pill('Stories', m !== 'adversaries', qs({ m: null }))}${pill('Adversaries', m === 'adversaries', qs({ m: 'adversaries' }))}</nav></div></div>`;
  // the report lists countries by stories; shaded by adversaries, the cards follow that instead
  if (m === 'adversaries') report = { ...report, countries: [...report.countries].sort((a, b) => b.adversaries - a.adversaries || b.stories - a.stories || a.name.localeCompare(b.name)) };
  const t = report.totals;
  const lead = [...report.countries].sort((a, b) => b.stories - a.stories)[0];
  const share = lead?.stories && t.attributed_stories ? Math.round((100 * lead.stories) / t.attributed_stories) : 0;
  const tile = (n, l, hot) => `<div class="tile${hot ? ' hot' : ''}"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`;
  const tiles = `<div class="tiles">${tile(t.countries, 'countries')}${tile(t.adversaries, 'attributed adversaries', true)}`
    + `${tile(`${t.attributed_stories}<span class="s" style="font-size:13px">/${t.stories}</span>`, 'stories attributed')}`
    + `${share ? tile(`${share}%`, `of those: ${lead.name}`, true) : ''}</div>`;
  const win = report.window;
  const span = `${win.from} – ${win.to}${win.data_from > win.from ? ` (briefs stored from ${win.data_from})` : ''}`;
  const parts = [`<div class="hero"><h1>Adversaries by country</h1>`
    + `<p class="sub">Which country the public sources attribute each brief story's adversary to · ${esc(WINDOWS[String(w)] || '')}: ${esc(span)}${cat ? ` · ${esc(CATEGORIES[cat].toLowerCase())} only` : ''}</p></div>`,
  bar, tiles, mapSvg(report, m)];

  if (report.countries.length) {
    parts.push('<h3 style="border:none">Week by week</h3>', weeksSvg(report));
    parts.push(`<h3 style="border:none">By country</h3><div class="am-cards">${report.countries.filter((c) => c.adversaries).map((c) => countryCard(c, m)).join('')}</div>`);
  } else parts.push('<p class="s" style="margin-top:18px">No story in this window names an adversary attributed to a country.</p>');

  if (report.tools.length) {
    parts.push('<h3 style="border:none">Tools seen in more than one story</h3>'
      + '<p class="s">Malware and frameworks the extraction named, counted wherever a story names them, with the countries the same stories\' actors are attributed to.</p>'
      + `<table class="am-tools">${report.tools.map((x) => `<tr><td><a href="/?q=${encodeURIComponent(x.name)}">${esc(x.name)}</a></td><td>${x.stories} stories</td>`
        + `<td>${x.by.map((b) => (b.cc ? `<a href="#c-${b.cc.toLowerCase()}">${esc(b.name)} ${b.stories}</a>` : `<span class="s">${esc(b.name)} ${b.stories}</span>`)).join(' · ')}</td>`
        + `<td class="x">${x.latest ? `<a href="${storyHref(x.latest)}">${esc(x.latest.date)}</a>` : ''}</td></tr>`).join('')}</table>`);
  }

  const nc = Object.entries(report.no_country).filter(([, list]) => list.length);
  if (nc.length) {
    const order = ['state', 'crime', 'hacktivist', 'spyware', 'unknown'];
    parts.push(`<h3 style="border:none">Named, but no country stated (${t.named_no_country} stor${t.named_no_country === 1 ? 'y' : 'ies'})</h3>`
      + '<p class="s">The sources name these actors without attributing them to a country. Nation-state here means a source calls the activity espionage or state-sponsored without saying whose.</p>'
      + nc.sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
        .map(([k, list]) => `<p class="k">${esc(CATEGORIES[k])} (${list.length})</p><div>${list.map((a) => actorChip(a, false)).join('')}</div>`).join(''));
  }

  parts.push(`<details style="margin-top:26px"><summary>How attribution is read</summary><div class="s" style="margin-top:6px">
<p>Nothing here is Cutsign's own attribution. Each story's actor field, title and summary (written by the extraction from the public sources) are read for, strongest first:</p>
<ul><li>a group whose attribution is settled in public reporting (APT28, Lazarus, Storm-0940, …);</li>
<li>a vendor naming convention: Microsoft's Typhoon (China), Blizzard (Russia), Sandstorm (Iran), Sleet (North Korea); CrowdStrike's Panda, Bear, Kitten, Chollima; Unit 42's Taurus, Ursa, Serpens, Pisces; Secureworks' Bronze, Iron, Cobalt, Nickel;</li>
<li>the sources' own words next to the name: "China-nexus Volt Typhoon", "North Korea's TraderTraitor", "Iranian state-sponsored …";</li>
<li>a story that names no actor but says "North Korean threat actors" or "Russia-linked" counts one unnamed actor for that country.</li></ul>
<p>"Russian-speaking" and "Chinese-language" name a language, not a country, and count for neither; "pro-Ukrainian" is a stance; "Russian healthcare organization" is a victim. Vendors' alias tables merge one actor's names (Jade Sleet = TraderTraitor). A <b>story</b> is one update chain: a story and its later updates count once. Every card lists why each actor was placed where it is. JSON: <code>/?view=actors&amp;format=json</code> (same <code>w</code>, <code>cat</code> parameters).</p></div></details>`);
  return parts.join('\n');
}
