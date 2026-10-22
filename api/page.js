// Public, read-only web view of recent briefs. "/" (rewritten here in vercel.json) renders
// the latest sent run from the same buildDigestData the email uses, but with its own chrome:
// dark/light theme, sticky header with a 14-day picker (?d=YYYY-MM-DD), stat tiles, and the
// last 48 h of watch events whether or not they were already emailed. The email-only banner
// and reply-footer are stripped — content is public-OSINT-only by construction (the one rule),
// so the page is public; noindex like every other endpoint.

import { supabaseStore } from '../lib/db.js';
import { buildDigestData, renderHtml, exposureBox, defang } from '../lib/render.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const STYLE = `
:root{
  --bg:#0d1017;--panel:#151a23;--panel2:#1b2230;--text:#e7eaf1;--mut:#8d95a7;--line:#262f41;
  --acc:#e4a93c;--link:#7fb0ff;--new:#3fb950;--bad:#ff7b72;--chip:#1f2735;--chip-line:#2c3853;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: light){:root{
  --bg:#f6f7f9;--panel:#ffffff;--panel2:#f0f2f6;--text:#1b1f27;--mut:#5b6270;--line:#e2e5ea;
  --acc:#b07c14;--link:#2458b3;--new:#1a7f37;--bad:#b42318;--chip:#eef0f4;--chip-line:#dde1e8;
}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
.top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.top .in{max-width:860px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-family:var(--mono);font-size:15px;font-weight:700;letter-spacing:.14em}
.brand b{color:var(--acc);font-weight:700}
.brand .tag{margin-left:10px;font-weight:400;letter-spacing:0;font-size:11.5px;color:var(--mut)}
.nav{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
.nav a,.nav span{font-family:var(--mono);font-size:11.5px;padding:3px 9px;border-radius:999px;border:1px solid var(--chip-line);background:var(--chip);color:var(--mut)}
.nav span{background:var(--acc);border-color:var(--acc);color:#14161c;font-weight:700}
.nav a:hover{color:var(--text);text-decoration:none;border-color:var(--acc)}
main{max-width:860px;margin:0 auto;padding:26px 16px 60px}
.hero h1{margin:0;font-size:26px;letter-spacing:-.01em}
.hero .sub{margin:4px 0 0;color:var(--mut);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px;margin:18px 0 8px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.tile .n{font-size:24px;font-weight:700;font-family:var(--mono)}
.tile .l{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--mut);margin-top:2px}
.tile.hot .n{color:var(--acc)}
/* ---- email body classes, reskinned ---- */
.w{line-height:1.55;font-size:14.5px}
h3{font-size:17px;margin:34px 0 6px;padding-top:18px;border-top:1px solid var(--line)}
h3 .u{font-weight:400;font-size:13px;color:var(--mut)}
.s{color:var(--mut);font-size:12.5px}
.k{margin:14px 0 4px;font-weight:650}
.c{display:inline-block;font-size:11px;font-family:var(--mono);padding:1.5px 8px;border-radius:999px;background:var(--chip);border:1px solid var(--chip-line);color:var(--text);margin:0 4px 4px 0}
pre{font-family:var(--mono);font-size:12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
code{font-family:var(--mono);font-size:12.5px;background:var(--panel2);border-radius:4px;padding:0 4px}
table{border-collapse:collapse;width:100%;margin:4px 0}
td{padding:4px 10px 4px 0;vertical-align:top;font-size:12.5px;border-bottom:1px solid var(--line)}
td.v{font-family:var(--mono);word-break:break-all} td.x{color:var(--mut)}
ul{margin:4px 0;padding-left:20px} li{margin:3px 0}
.bad{color:var(--bad)}
.bh{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--mut);border-radius:8px;padding:8px 12px;margin:8px 0}
.bh.n{border-left-color:var(--new)} .bh.i{border-left-style:dashed}
.bt{font-weight:650} .bt a{font-weight:400;font-size:12px}
.new{display:inline-block;font-size:10px;font-weight:700;color:#fff;background:var(--new);border-radius:3px;padding:0 5px;margin-right:6px;vertical-align:1px}
.basis{float:right;color:var(--mut);font-size:11px;font-family:var(--mono)}
.ch{font-family:var(--mono);font-size:12.5px;background:var(--panel2);border-radius:6px;padding:3px 8px;margin:4px 0;display:inline-block;word-break:break-all}
.q{color:var(--mut);font-size:12px;font-style:italic;margin-top:4px}
.ex{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0;font-size:13px}
.ex b{display:inline-block;min-width:122px;color:var(--mut);font-weight:600}
.ex .h{font-size:10.5px;letter-spacing:.09em;color:var(--acc);font-weight:700}
details{margin:6px 0} summary{cursor:pointer;color:var(--mut)} summary:hover{color:var(--text)}
hr{border:none;border-top:1px solid var(--line);margin:28px 0 10px}
footer{max-width:860px;margin:0 auto;padding:0 16px 40px;color:var(--mut);font-size:12px;font-family:var(--mono)}
/* ---- CISO view ---- */
.tabs{display:flex;gap:6px}
.tabs a,.tabs span{font-size:12px;font-weight:600;padding:4px 12px;border-radius:999px;border:1px solid var(--chip-line);background:var(--chip);color:var(--mut)}
.tabs span{background:var(--text);border-color:var(--text);color:var(--bg)}
.tabs a:hover{color:var(--text);text-decoration:none;border-color:var(--acc)}
.exec{background:var(--panel);border-left:3px solid var(--acc);border-radius:0 10px 10px 0;padding:12px 16px;margin:18px 0;font-size:15px}
.search input{background:var(--panel2);border:1px solid var(--chip-line);border-radius:999px;color:var(--text);font:12px var(--mono);padding:4px 12px;width:160px;outline:none;transition:width .15s,border-color .15s}
.search input:focus{border-color:var(--acc);width:220px}
a.c{color:var(--link)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:14px 0}
.card h3{margin:0;border:none;padding:0;font-size:17px;display:inline}
.card .ex{background:var(--panel2)}
.chead{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}
.pri{font-family:var(--mono);font-weight:700;font-size:11px;padding:2px 8px;border-radius:5px;flex:none}
.pri.p1{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.pri.p2{background:color-mix(in srgb,var(--acc) 18%,transparent);color:var(--acc)}
.pri.p3{background:var(--chip);color:var(--mut)}
@media (max-width:600px){.hero h1{font-size:22px}.tile .n{font-size:20px}}`;

const doc = (title, headerNav, inner, foot) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head>
<body><header class="top"><div class="in"><span class="brand">CUT<b>SIGN</b><span class="tag">cutting for sign — daily OSINT threat read</span></span><nav class="nav">${headerNav}</nav></div></header>
<main>${inner}</main><footer>${foot}</footer></body></html>`;

const tile = (n, label, hot) => `<div class="tile${hot ? ' hot' : ''}"><div class="n">${n}</div><div class="l">${esc(label)}</div></div>`;

const searchForm = (q) => `<form class="search" action="/"><input type="search" name="q" placeholder="search stories & IoCs" value="${esc(q)}" maxlength="80"></form>`;

// Search results across every stored brief: extracted stories (title/summary/actor/malware/CVE)
// and the IoC table (substring on normalized value). Capped at 30 each.
function searchBody(q, stories, iocs) {
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span class="c">${esc(c)}</span>`).join('');
  const cap = stories.length >= 30 || iocs.length >= 30 ? ' (capped at 30 each — narrow the term for more)' : '';
  const parts = [`<div class="hero"><h1>Search — “${esc(q)}”</h1>
    <p class="sub">${stories.length} stor${stories.length === 1 ? 'y' : 'ies'} · ${iocs.length} IoC${iocs.length === 1 ? '' : 's'}${cap}</p></div>`];
  if (!stories.length && !iocs.length) parts.push('<p class="s" style="margin-top:20px">Nothing matched in extracted stories or IoCs.</p>');
  if (stories.length) {
    parts.push('<h3 style="border:none">Stories</h3>');
    for (const s of stories) {
      parts.push(`<div class="card"><div class="chead"><span class="pri p${s.priority ?? 3}">P${s.priority ?? '?'}</span><h3>${esc(s.title || '(untitled)')}</h3></div>`,
        `<div>${s.brief_date ? `<a class="c" href="/?d=${encodeURIComponent(s.brief_date)}">brief ${esc(s.brief_date)}</a>` : ''}`
        + `${chips([s.selected ? 'deep read' : 'quick read', s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...(s.cves || [])])}</div>`,
        `<p style="margin:8px 0 0">${esc(s.summary || '')}</p></div>`);
    }
  }
  if (iocs.length) {
    parts.push('<h3>IoCs</h3><table>');
    for (const i of iocs) {
      parts.push(`<tr><td>${esc(i.type)}</td><td class="v">${esc(defang(i.type, i.value_norm))}</td>`
        + `<td>seen ${i.seen_count}×, first ${esc(String(i.first_seen_at).slice(0, 10))}</td><td class="x">${esc(i.context || '')}</td></tr>`);
    }
    parts.push('</table>');
  }
  return parts.join('\n');
}

// Executive view: verdict-shaped cards for the stories that matter (deep reads and P1/P2),
// HIGH watch developments, one-liners for the rest. No IoC tables, no hunt cards.
function cisoBody(d) {
  const pri = (s) => s.priority ?? 3;
  const cards = d.analyzed.filter((s) => s.selected || pri(s) <= 2);
  const rest = d.analyzed.filter((s) => !cards.includes(s));
  const highs = (d.watchEvents || []).filter((e) => e.level === 'HIGH');
  const highByStory = new Map(); // watch_title -> events, newest last
  for (const e of highs) { if (!highByStory.has(e.watch_title)) highByStory.set(e.watch_title, []); highByStory.get(e.watch_title).push(e); }
  const p1 = cards.filter((s) => pri(s) === 1).length;
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span class="c">${esc(c)}</span>`).join('');
  const parts = [];

  const top = d.analyzed[0];
  parts.push(`<div class="exec"><b>Today:</b> ${d.analyzed.length} stories in the brief, ${p1} high-priority.`
    + (top ? ` Top story: ${esc(top.title)}.` : '')
    + (d.updateCount ? ` ${d.updateCount} are developments of stories already being tracked.` : '')
    + (highByStory.size ? ` <b class="bad">${highByStory.size} tracked stor${highByStory.size === 1 ? 'y' : 'ies'} escalated in the last 48 h.</b>` : '')
    + '</div>');

  if (highByStory.size) {
    parts.push('<h3 style="border:none;padding-top:0">Developments on tracked stories (48 h)</h3><ul>');
    for (const [title, evs] of highByStory) {
      const latest = evs[evs.length - 1];
      parts.push(`<li><b>${esc(title)}</b> — ${evs.length === 1 ? '' : `${evs.length} developments; latest: `}${esc(latest.summary)}</li>`);
    }
    parts.push('</ul>');
  }

  for (const s of cards) {
    const p = pri(s);
    parts.push(`<div class="card"><div class="chead"><span class="pri p${p}">P${p}</span><h3>${esc(s.title)}</h3></div>`,
      `<div>${chips([s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`,
        ...s.cves, s.updateOf && `update to ${s.updateOf.brief_date || String(s.updateOf.created_at).slice(0, 10)}`])}</div>`,
      `<p style="margin:8px 0">${esc(s.summary)}</p>`,
      exposureBox(s.raw_iocs?.exposure),
      `<p class="s"><b>Why it matters:</b> ${esc(s.priority_reason || '')}</p></div>`);
  }

  if (rest.length) {
    parts.push(`<h3>Also in today's read (${rest.length})</h3><ul>`);
    for (const s of rest) parts.push(`<li><b>${esc(s.title)}</b> <span class="s">P${pri(s)} · ${esc(s.summary)}</span></li>`);
    parts.push('</ul>');
  }
  parts.push('<p class="s" style="margin-top:28px">Priorities and summaries are drawn from public reporting only. The analyst view carries the full behaviors, evidence and indicators.</p>');
  return parts.join('\n');
}

export default async function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=600');
  try {
    const store = supabaseStore();

    const qraw = String(req.query.q || '').trim().slice(0, 80);
    if (qraw) {
      const [stories, iocs] = await Promise.all([store.searchStories(qraw), store.searchIocs(qraw)]);
      return res.status(200).send(doc(`Cutsign — search “${qraw}”`,
        searchForm(qraw) + '<nav class="tabs"><a href="/">← latest brief</a></nav>',
        `<div class="w">${searchBody(qraw, stories, iocs)}</div>`,
        'Cutsign · public OSINT digest · search across all stored briefs'));
    }

    const runs = (await store.listRecentSentRuns(14)).reverse(); // newest first
    if (!runs.length) return res.status(200).send(doc('Cutsign', '', '<p class="s">No briefs in the last 14 days.</p>', 'Cutsign'));
    const briefs = await Promise.all(runs.map((r) => store.getBrief(r.brief_id).catch(() => null)));
    // one pill per brief date, newest date first; when a date has several runs keep the
    // newest run (runs is newest-first, so the first one seen wins)
    const byDate = new Map();
    runs.forEach((r, i) => {
      const date = briefs[i]?.brief_date || String(briefs[i]?.received_at || r.started_at).slice(0, 10);
      if (!byDate.has(date)) byDate.set(date, { run: r, date });
    });
    const days = [...byDate.values()].sort((a, b) => b.date.localeCompare(a.date));
    const want = String(req.query.d || '').slice(0, 10);
    const pick = days.find((x) => x.date === want) || days[0];
    const ciso = req.query.view === 'ciso';
    const q = (date) => `/?d=${encodeURIComponent(date)}${ciso ? '&view=ciso' : ''}`;

    const d = await buildDigestData(store, pick.run);
    try { // web view: recent watch events regardless of digested/notified state
      const cutoff = Date.now() - 48 * 3600 * 1000;
      d.watchEvents = (await store.listWatchEvents({})).filter((e) => new Date(e.created_at).getTime() >= cutoff);
    } catch { /* watches table absent — keep whatever buildDigestData found */ }

    // analyst view: full (level 0) email body, minus the email-only chrome; if render.js markup
    // drifts these strips become no-ops and the page just shows a little extra, never breaks
    const analystBody = () => {
      const full = renderHtml(d, 0);
      return full.slice(full.indexOf('<div class="w">') + '<div class="w">'.length, full.lastIndexOf('</div></body></html>'))
        .replace(/<p class="ban">[\s\S]*?<\/p>/, '')                                   // email banner
        .replace(/<h2 style="[^"]*">Cutsign — [\s\S]*?<\/h2>/, '')                      // email heading (hero replaces it)
        .replace(/<p class="dl">[\s\S]*?<\/p>/, '')                                     // delta line (tiles replace it)
        .replace(/<p class="s">[^<]*brief: “[\s\S]*?<\/p>/, '')                         // meta line (hero sub replaces it)
        .replace(/<hr>\s*<p class="s">Reply with freeform[\s\S]*?<\/p>/, '');           // email reply footer
    };

    const tabs = `<nav class="tabs">${ciso
      ? `<a href="/?d=${encodeURIComponent(pick.date)}">Analyst</a><span>CISO</span>`
      : `<span>Analyst</span><a href="/?d=${encodeURIComponent(pick.date)}&view=ciso">CISO</a>`}</nav>`;
    const nav = days.slice(0, 14).map((x) => x.date === pick.date
      ? `<span>${esc(x.date.slice(5))}</span>` : `<a href="${q(x.date)}">${esc(x.date.slice(5))}</a>`).join('');
    const deep = d.analyzed.filter((s) => s.selected).length;
    const hero = `<div class="hero"><h1>${esc(d.date)}${d.run.dry ? ' <span class="s">(dry run)</span>' : ''}</h1>
      <p class="sub">${d.analyzed.length} stories analyzed · ${deep} deep reads · brief: “${esc(d.brief.subject)}”</p></div>
      <div class="tiles">${tile(d.newIocCount, 'new IoCs', d.newIocCount > 0)}${tile(d.novelBehaviorCount, 'novel behaviors', d.novelBehaviorCount > 0)}${tile(d.restatedIocCount, 'restated IoCs')}${tile(d.updateCount, 'story updates')}${tile((d.watchEvents || []).length, 'watch events 48h', (d.watchEvents || []).some((e) => e.level === 'HIGH'))}</div>`;

    const foot = `Cutsign · public OSINT digest · run ${esc(String(d.run.id).slice(0, 8))} · rendered ${new Date().toISOString().slice(0, 16)}Z`;
    const inner = `${hero}<div class="w">${ciso ? cisoBody(d) : analystBody()}</div>`;
    return res.status(200).send(doc(`Cutsign — ${d.date}${ciso ? ' — CISO view' : ''}`, tabs + searchForm('') + nav, inner, foot));
  } catch (e) {
    return res.status(500).send(doc('Cutsign', '', `<p class="bad">Error rendering page: ${esc(e.message)}</p>`, 'Cutsign'));
  }
}
