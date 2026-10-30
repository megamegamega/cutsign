// Public, read-only web view of recent briefs. "/" (rewritten here in vercel.json) renders
// the CISO view of the latest sent run (?view=analyst for the full analyst body) from the same buildDigestData the email uses, but with its own chrome:
// dark/light theme, sticky header with a 14-day picker (?d=YYYY-MM-DD), stat tiles, and the
// last 48 h of watch events whether or not they were already emailed. The email-only banner
// and reply-footer are stripped — content is public-OSINT-only by construction (the one rule),
// so the page is public; noindex like every other endpoint.

import { supabaseStore } from '../lib/db.js';
import { buildDigestData, renderHtml, exposureBox, defang } from '../lib/render.js';
import { CARDS, cardIndex } from '../lib/cards.js';
import { LOG_SOURCE_KEYS, logSourceKeys } from '../lib/logsources.js';
import { PROPOSAL_SHAPES } from '../lib/schemas.js';
import { draftBody } from '../lib/carddraft.js';
import { fetchKevEntries } from '../lib/hype.js';
import { subscribeForm } from '../lib/subscribe.js';

// Cards in play for this request: the manifest's hand-written ones plus the pipeline's published
// AI cards (card_drafts rows with status 'promoted'). Set per request from the same table state,
// so an interleaved request overwriting it changes nothing.
let IDX = cardIndex([]);

// CISA KEV, fetched at most hourly per instance; an empty result never replaces a good one
let kevCache = { at: 0, map: new Map() };
async function kevEntries() {
  if (Date.now() - kevCache.at < 3600_000) return kevCache.map;
  const m = await fetchKevEntries();
  if (m.size) kevCache = { at: Date.now(), map: m };
  return kevCache.map;
}

// The card a story belongs to, following its update chain (today's row → the row it updates → …);
// `d.priorById` (from buildDigestData) supplies the earlier rows. Search and corpus rows carry
// only updates_story_id, so they resolve one hop back.
const cardOf = (s, d) => IDX.cardForStory(s, (id) => d?.priorById?.get(id) || null);
// "Verdict card" chip for a story that has a card: hand-written in public/cards/, or published by the pipeline
const verdictChip = (s, d) => {
  const c = cardOf(s, d);
  return c ? `<a class="c" href="${esc(c.url)}">${c.source === 'ai' ? 'AI verdict card' : 'Verdict card'}</a>` : '';
};
// surfaced AI draft for a story (its thread includes the story or the row it updates)
const draftOf = (s, d) => (d?.drafts || []).find((x) => (x.thread_ids || []).some((id) => id === s.id || id === s.updates_story_id)) || null;
const draftChip = (s, d) => { const x = draftOf(s, d); return x ? `<a class="c" href="/?view=draft&id=${esc(x.id)}">AI draft v${esc(String(x.version || 1))}</a>` : ''; };
// "update to <date>" chip links to the earlier story in its own brief (CISO view when it was
// an executive story that day, the analyst view otherwise, which anchors every story)
const updateChip = (s) => {
  const u = s.updateOf;
  if (!u) return '';
  const date = u.brief_date || String(u.created_at || '').slice(0, 10);
  const exec = u.selected || (u.priority ?? 3) <= 2;
  const href = `/?d=${encodeURIComponent(date)}&view=${exec ? 'ciso' : 'analyst'}#s-${esc(String(u.id).slice(0, 8))}`;
  return `<a class="c" href="${href}">${u.run_id && u.run_id === s.run_id ? 'continues an earlier item today' : `update to ${esc(date)}`}</a>`;
};

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
a.tile{display:block;color:inherit;text-decoration:none}
a.tile:hover{border-color:var(--acc)}
/* tile detail strips: hidden until their tile is clicked (:target) */
.tdetail{display:none;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:0 10px 10px 0;padding:10px 14px;margin:10px 0 4px;font-size:13px}
.tdetail:target{display:block}
.tdetail ul{margin:6px 0 0;padding-left:18px}
.tdetail .x{float:right;color:var(--mut);text-decoration:none;font-family:var(--mono)}
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
.tzl{border-bottom:1px dotted var(--mut);cursor:help}
/* deep-link landing: mark the story a search/card link jumped to */
h3:target,li:target,.card:target{outline:2px solid var(--acc);outline-offset:6px;border-radius:4px;scroll-margin-top:14px}
.since{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:0 10px 10px 0;padding:10px 14px;margin:14px 0 4px;font-size:13px}
.since .t{font-family:var(--mono);color:var(--mut);font-size:11px;margin-right:8px}
.since ul{margin:4px 0 0;padding-left:18px}
a.c{color:var(--link)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:14px 0}
.card h3{margin:0;border:none;padding:0;font-size:17px;display:inline}
.card .ex{background:var(--panel2)}
/* print / save-PDF button (the hand cards have the same one) and the card-mail sign-up form */
.pbar{display:flex;justify-content:flex-end;margin:12px 0 -4px}
.pdf{font:600 12px/1 inherit;padding:6px 12px;border-radius:999px;border:1px solid var(--chip-line);background:var(--chip);color:var(--text);cursor:pointer}
.pdf:hover{border-color:var(--acc);color:var(--acc)}
.sub{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:22px 0 10px;font-size:13px}
.sub label{display:block;margin-bottom:6px}
.sub div{display:flex;gap:8px;flex-wrap:wrap;margin:4px 0 6px}
.sub input[type=email]{flex:1 1 220px;min-width:0;background:var(--panel2);border:1px solid var(--chip-line);border-radius:8px;color:var(--text);font:13px var(--mono);padding:6px 10px;outline:none}
.sub input[type=email]:focus{border-color:var(--acc)}
.sub button{font:600 12px/1 inherit;padding:7px 14px;border-radius:8px;border:1px solid var(--acc);background:var(--acc);color:var(--bg);cursor:pointer}
.sub .hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
/* Shodan counts under each exposure query (lib/exposure.js countHtml): the number is the thing to see */
.cnt{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 10px;margin:6px 0 0;font-size:12.5px;color:var(--mut)}
.cnt .num{font-weight:800;font-size:19px;line-height:1;letter-spacing:-.01em;font-variant-numeric:tabular-nums;color:var(--acc);background:color-mix(in srgb,var(--acc) 14%,transparent);border:1px solid color-mix(in srgb,var(--acc) 35%,transparent);border-radius:7px;padding:4px 9px}
.cnt.zero .num{color:var(--mut);background:var(--chip);border-color:var(--chip-line)}
.cnt .trd{font-family:var(--mono);font-size:11.5px}
.cnt .trd.up{color:var(--bad)} .cnt .trd.down{color:var(--acc)}
.cnt.off .lbl{font-style:italic}
/* print / save-PDF: the AI card and draft pages print like the hand cards — site chrome off,
   dark backgrounds kept, full bleed (phones have no "Margins: None" control) */
@media print{
  @page{margin:0}
  html,body{background:var(--bg)!important;print-color-adjust:exact;-webkit-print-color-adjust:exact}
  header.top,footer,.tabs,.search,.nav,.pbar,.sub{display:none!important}
  main{max-width:none;padding:14px 18px}
  body{font-size:12.5px}
  .card,pre,.ch,.c{print-color-adjust:exact;-webkit-print-color-adjust:exact}
  a{text-decoration:none;color:inherit}
  tr,li,pre,.xq{break-inside:avoid}
  h3{break-after:avoid}
}
.chead{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}
.pri{font-family:var(--mono);font-weight:700;font-size:11px;padding:2px 8px;border-radius:5px;flex:none}
.pri.p1{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.pri.p2{background:color-mix(in srgb,var(--acc) 18%,transparent);color:var(--acc)}
.pri.p3{background:var(--chip);color:var(--mut)}
@media (max-width:600px){.hero h1{font-size:22px}.tile .n{font-size:20px}}`;

// Rewrites every rendered UTC timestamp ("2026-10-23 11:20Z", "2026-10-23T13:05Z", bare "11:20Z")
// into the viewer's local time WITH an explicit timezone label (e.g. "2026-10-23 07:20 EDT"),
// keeping the original Zulu time on hover. Skips pre/code so raw query/IoC text is never touched.
// Date-only values are left alone — without a time they cannot shift zones honestly.
const TZ_SCRIPT = String.raw`<script>
(function(){try{
  var zone=Intl.DateTimeFormat().resolvedOptions().timeZone||'';
  if(/^(UTC|Etc\/)/.test(zone))return; // already reading in UTC: labels stay Z
  function fmt(d,withDate){
    var parts={},f=new Intl.DateTimeFormat([],{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false,timeZoneName:'short'});
    f.formatToParts(d).forEach(function(p){parts[p.type]=p.value});
    var t=parts.hour+':'+parts.minute+' '+parts.timeZoneName;
    return withDate?parts.year+'-'+parts.month+'-'+parts.day+' '+t:t;
  }
  var re=/\b(?:(\d{4}-\d{2}-\d{2})[ T])?(\d{2}:\d{2})Z\b/g;
  var walk=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,{acceptNode:function(n){
    return n.parentNode.closest('pre,code,script,style')?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT}});
  var nodes=[],n;while((n=walk.nextNode()))if(re.test(n.nodeValue)){nodes.push(n);re.lastIndex=0}
  nodes.forEach(function(node){
    var txt=node.nodeValue,frag=document.createDocumentFragment(),last=0,m;re.lastIndex=0;
    while((m=re.exec(txt))){
      var day=m[1]||new Date().toISOString().slice(0,10),d=new Date(day+'T'+m[2]+':00Z');
      if(isNaN(d))continue;
      frag.appendChild(document.createTextNode(txt.slice(last,m.index)));
      var s=document.createElement('span');s.className='tzl';s.textContent=fmt(d,!!m[1]);s.title=m[0]+' UTC';
      frag.appendChild(s);last=m.index+m[0].length;
    }
    if(!last)return;
    frag.appendChild(document.createTextNode(txt.slice(last)));
    node.parentNode.replaceChild(frag,node);
  });
}catch(e){}})();
</script>`;

const doc = (title, headerNav, inner, foot) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head>
<body><header class="top"><div class="in"><span class="brand">CUT<b>SIGN</b><span class="tag">cutting for sign — daily OSINT threat read</span></span><nav class="nav">${headerNav}</nav></div></header>
<main>${inner}</main><footer>${foot}<br>Built by Marcus Liberto · Apache-2.0 · <a href="https://github.com/megamegamega/cutsign">source</a></footer>${TZ_SCRIPT}</body></html>`;

// A tile with an href is the navigation to its detail (raw IoCs, corpus, watch section, cards)
const tile = (n, label, hot, href) => href
  ? `<a class="tile${hot ? ' hot' : ''}" href="${esc(href)}"><div class="n">${n}</div><div class="l">${esc(label)}</div></a>`
  : `<div class="tile${hot ? ' hot' : ''}"><div class="n">${n}</div><div class="l">${esc(label)}</div></div>`;

// "2026-10-23 11:20Z" when the value carries a real time, else just the date.
// Midnight UTC reads as date-only: pre-migration published_at values have no time.
const ts = (v) => {
  const s = String(v ?? '');
  if (!s) return '';
  return /T(?!00:00)\d\d:\d\d/.test(s) ? `${s.slice(0, 10)} ${s.slice(11, 16)}Z` : s.slice(0, 10);
};

// compact one-line behavior: ATT&CK link, kind, process chain, where to hunt
const behaviorLine = (b) => `<div class="s">${b.attack_technique
  ? `<a href="https://attack.mitre.org/techniques/${esc(String(b.attack_technique).replace('.', '/'))}/">${esc(b.attack_technique)}</a> · ` : ''}`
  + `${esc(b.pattern_kind)}${b.parent || b.children?.length ? `: ${b.parent ? `<code>${esc(b.parent)}</code>` : ''}${b.parent && b.children?.length ? ' → ' : ''}${(b.children || []).map(esc).join(', ')}` : ''}`
  + `${b.log_source ? ` · hunt in: ${esc(b.log_source)}` : ''}</div>`;

const searchForm = (q) => `<form class="search" action="/"><input type="search" name="q" placeholder="search stories & IoCs" value="${esc(q)}" maxlength="80"></form>`;
// the same button the hand-written cards carry; the print stylesheet above drops the site chrome
const printBar = '<div class="pbar"><button class="pdf" type="button" onclick="window.print()">Print / save PDF</button></div>';

// Search results across every stored brief: extracted stories (title/summary/actor/malware/CVE)
// and the IoC table (substring on normalized value). Capped at 30 each.
function searchBody(q, stories, iocs) {
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span class="c">${esc(c)}</span>`).join('');
  const sid = (id) => `s-${String(id).slice(0, 8)}`;
  const cap = stories.length >= 30 || iocs.length >= 30 ? ' (capped at 30 each — narrow the term for more)' : '';
  const parts = [`<div class="hero"><h1>Search — “${esc(q)}”</h1>
    <p class="sub">${stories.length} stor${stories.length === 1 ? 'y' : 'ies'} · ${iocs.length} IoC${iocs.length === 1 ? '' : 's'}${cap}</p></div>`];
  if (!stories.length && !iocs.length) parts.push('<p class="s" style="margin-top:20px">Nothing matched in extracted stories or IoCs.</p>');
  if (stories.length) {
    parts.push('<h3 style="border:none">Stories</h3>');
    for (const s of stories) {
      const a = sid(s.id);
      parts.push(`<div class="card"><div class="chead"><span class="pri p${s.priority ?? 3}">P${s.priority ?? '?'}</span><h3>${esc(s.title || '(untitled)')}</h3></div>`,
        `<div>${s.brief_date ? `<a class="c" href="/?d=${encodeURIComponent(s.brief_date)}&view=analyst#${a}">brief ${esc(s.brief_date)}</a>` : ''}`
        + (s.brief_date && (s.selected || (s.priority ?? 3) <= 2) ? `<a class="c" href="/?d=${encodeURIComponent(s.brief_date)}&view=ciso#${a}">CISO card</a>` : '')
        + (s.ioc_count ? `<a class="c" href="/?view=iocs#${a}">IoC card (${s.ioc_count})</a>` : '')
        + verdictChip(s)
        + `${chips([s.selected ? 'deep read' : 'quick read', s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...(s.cves || [])])}</div>`,
        `<p style="margin:8px 0 0">${esc(s.summary || '')}</p></div>`);
    }
  }
  if (iocs.length) {
    parts.push('<h3>IoCs</h3><table>');
    for (const i of iocs) {
      const first = (i.stories || [])[0];
      const card = first ? `/?view=iocs#${sid(first.id)}` : '/?view=iocs#s-unattributed';
      const links = (i.stories || []).filter((s) => s.date)
        .map((s) => `<a href="/?d=${encodeURIComponent(s.date)}&view=analyst#${sid(s.id)}" title="${esc(s.title || '')}">${esc(s.date)}</a>`).join(' ');
      parts.push(`<tr><td>${esc(i.type)}</td><td class="v"><a href="${card}" title="IoC corpus card">${esc(defang(i.type, i.value_norm))}</a></td>`
        + `<td>seen ${i.seen_count}×, first ${esc(ts(i.first_seen_at))}</td><td class="x">${esc(i.context || '')}${links ? ` · ${links}` : ''}</td></tr>`);
    }
    parts.push('</table>');
  }
  return parts.join('\n');
}

// "Since this brief": watch events newer than the displayed run's send time — the same updates
// the HIGH alert emails/Discord already carried, surfaced at the top of the page instead of
// waiting to be found in the watch section. Only rendered on the newest day.
function sinceStrip(d) {
  const sentAt = new Date(d.run.finished_at || d.run.started_at).getTime();
  const evs = (d.watchEvents || []).filter((e) => new Date(e.created_at).getTime() > sentAt)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  if (!evs.length) return '';
  // same materiality bar as the watch section: below HIGH with no actionable artifact = noise
  const isNoise = (e) => e.level !== 'HIGH' && !e.assessment?.new_iocs?.length && !e.assessment?.deep;
  const noise = evs.filter(isNoise).length;
  const shown = evs.filter((e) => !isNoise(e)).slice(0, 10);
  const hhmm = (iso) => String(iso).slice(11, 16);
  const lines = shown.map((e) => `<li><span class="t">${esc(hhmm(e.created_at))}Z</span>${e.level === 'HIGH' ? '<span class="new">HIGH</span> ' : ''}<b>${esc(e.watch_title)}</b> — ${esc(e.summary)}${e.url ? ` <a href="${esc(e.url)}">source</a>` : ''}</li>`);
  if (noise) lines.push(`<li class="s">+ ${noise} low-signal update${noise === 1 ? '' : 's'} (folded)</li>`);
  return `<div class="since"><b>Since this brief</b> <span class="s">· watch updates newer than this run; HIGH ones were already alerted</span><ul>${lines.join('')}</ul></div>`;
}

// Machine-first view (?view=agent): raw IoC values grouped one-per-line for direct paste into
// hunt queries, plus the JSON contract carrying the same data with behaviors and exposure.
// Raw means NOT defanged — that is the point of this view; defang before quoting elsewhere.
function agentIocMap(d) {
  const flat = new Map(); // type -> Set(raw value)
  const add = (type, v) => { if (!type || !v) return; if (!flat.has(type)) flat.set(type, new Set()); flat.get(type).add(String(v)); };
  for (const s of d.analyzed) for (const i of [...s.newIocs, ...s.repeatIocs]) add(i.type, i.value_norm);
  for (const e of d.watchEvents || []) for (const i of e.assessment?.new_iocs || []) add(i.type, i.value);
  return flat;
}

function agentBody(d, days) {
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span class="c">${esc(c)}</span>`).join('');
  // one-per-line <pre> blocks per IoC type, scoped to whatever list is passed in
  const typeBlocks = (iocs) => {
    const m = new Map();
    for (const i of iocs) { if (!i.value) continue; if (!m.has(i.type)) m.set(i.type, new Set()); m.get(i.type).add(String(i.value)); }
    return [...m].map(([t, set]) => `<p class="k">${esc(t)} (${set.size})</p><pre>${[...set].map(esc).join('\n')}</pre>`).join('');
  };
  const parts = [
    '<p class="s">Machine-first view of this brief, <b>grouped by story</b> so indicator streams stay attributable. IoC values are <b>raw, not defanged</b>, one per line, ready for hunt queries — defang before pasting into chat or email. Everything here is public OSINT; exposure and behavior detail lives in the JSON (also grouped per story).</p>',
    `<h3 style="border:none;padding-top:0">Endpoints</h3><pre>GET /?view=agent&amp;format=json          this brief as JSON (stories, behaviors, exposure, IoCs, watch events)
GET /?view=agent&amp;format=json&amp;d=DATE   a specific day — available: ${days.map((x) => esc(x.date)).join(', ')}
GET /?view=iocs&amp;format=json           cumulative IoC corpus — every brief + watch event, all time
GET /?q=TERM&amp;format=json               search every stored brief (stories + IoCs)
GET /?view=cards&amp;format=json          verdict-card manifest (slug, title, lane, cves, story_ids, url)
GET /cards/&lt;slug&gt;.html                 a hand-written verdict card; /cards/&lt;slug&gt; one the pipeline published; stories here carry verdict_card when one exists

Shapes: log_source is the extractor's free text; log_source_keys beside it is a closed vocabulary
(see vocab.log_source_keys) for mapping to your own data. evidence_samples are the exact strings the
sources printed (replay targets). exposure is null when the sources stated nothing.</pre>`,
  ];

  // watch-event IoCs join their story's stream when the watch tracks a story in this brief
  // (directly, or via the brief story being an update of the watched one); the rest keep
  // their own watch-titled streams below
  const matched = new Map(); // story id -> [{type,value}]
  const byWatch = new Map(); // watch title -> [{type,value}] (unmatched)
  for (const e of d.watchEvents || []) {
    const s = e.watch_story_id && d.analyzed.find((x) => x.id === e.watch_story_id || x.updates_story_id === e.watch_story_id);
    for (const i of e.assessment?.new_iocs || []) {
      const key = s ? s.id : e.watch_title;
      const m = s ? matched : byWatch;
      if (!m.has(key)) m.set(key, []);
      m.get(key).push({ type: i.type, value: i.value });
    }
  }

  // per-story streams: title, tags, one-line context, behaviors + detection guidance, then
  // this story's values only
  for (const s of d.analyzed) {
    const iocs = [...s.newIocs, ...s.repeatIocs].map((i) => ({ type: i.type, value: i.value_norm }));
    const fromWatch = matched.get(s.id) || [];
    const srcByUrl = new Map((s.sources || []).map((x) => [x.url, x]));
    parts.push(`<h3 id="s-${esc(String(s.id).slice(0, 8))}">P${s.priority ?? 3} · ${esc(s.title)}${cardOf(s, d) ? ` ${verdictChip(s, d)}` : ''}</h3>`,
      `<div>${chips([s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...(s.cves || [])])}</div>`,
      s.summary ? `<p class="s">${esc(s.summary)}</p>` : '',
      s.priority_reason ? `<p class="s"><b>Why P${s.priority ?? 3}:</b> ${esc(s.priority_reason)}</p>` : '',
      (s.behaviors || []).length ? `<p class="k">Behaviors (${s.behaviors.length}) <span class="s">· as of ${esc(d.date)}</span></p>${s.behaviors.map(behaviorLine).join('')}` : '',
      (s.guidance || []).length ? `<p class="k">Detection guidance (${s.guidance.length}) <span class="s">· as of ${esc(d.date)}</span></p>`
        + s.guidance.map((g) => {
          const pub = srcByUrl.get(g.url)?.published_at;
          return (/^https?:\/\//i.test(g.url || '') ? `<p class="s"><a href="${esc(g.url)}">source</a>${g.publisher_tier ? ` · tier ${esc(String(g.publisher_tier))}` : ''}${pub ? ` · published ${esc(ts(pub))}` : ''}${g.log_source ? ` · ${esc(g.log_source)}` : ''}</p>` : '')
            + `<pre>${esc(g.raw)}</pre>`;
        }).join('') : '',
      iocs.length ? typeBlocks(iocs) : fromWatch.length ? '' : '<p class="s">No IoCs extracted for this story.</p>',
      fromWatch.length ? `<p class="s">From this story's watch (last 48 h):</p>${typeBlocks(fromWatch)}` : '');
  }

  if (byWatch.size) {
    parts.push('<h3>Watch streams — new IoCs in the last 48 h</h3>');
    for (const [title, iocs] of byWatch) parts.push(`<p class="k">${esc(title)}</p>${typeBlocks(iocs)}`);
  }

  // bulk sweep: everything above combined, collapsed so the attributed streams stay primary
  const flat = agentIocMap(d);
  const total = [...flat.values()].reduce((n, s) => n + s.size, 0);
  if (total) {
    parts.push(`<details><summary>All values combined, unattributed (${total}) — for one big sweep</summary>`
      + [...flat].map(([t, set]) => `<p class="k">${esc(t)} (${set.size})</p><pre>${[...set].map(esc).join('\n')}</pre>`).join('')
      + '</details>');
  } else parts.push('<p class="s">No IoCs in this brief or the last 48 h of watch events.</p>');
  return parts.join('\n');
}

function agentJson(d, days) {
  return {
    kind: 'cutsign.brief',
    date: d.date,
    run: String(d.run.id),
    generated: new Date().toISOString(),
    note: 'Public OSINT only. IoC values are raw (not defanged) for direct query use.',
    days: days.map((x) => x.date),
    endpoints: { brief: '/?view=agent&format=json&d=YYYY-MM-DD', search: '/?q=TERM&format=json' },
    vocab: { log_source_keys: LOG_SOURCE_KEYS, proposal_shapes: PROPOSAL_SHAPES, proposal_tiers: ['proposed'] },
    stories: d.analyzed.map((s) => ({
      id: s.id,
      updates_story_id: s.updates_story_id || null,
      brief_date: d.date,
      verdict_card: cardOf(s, d)?.url || null,
      ai_draft: draftOf(s, d) ? `/?view=draft&id=${draftOf(s, d).id}` : null,
      title: s.title,
      priority: s.priority ?? 3,
      deep_read: !!s.selected,
      severity: s.severity || null,
      cves: s.cves || [],
      threat_actor: s.threat_actor || null,
      malware_family: s.malware_family || null,
      summary: s.summary || '',
      priority_reason: s.priority_reason || null,
      exposure: s.raw_iocs?.exposure || null,
      update_of: s.updateOf ? (s.updateOf.brief_date || String(s.updateOf.created_at).slice(0, 10)) : null,
      behaviors: (s.behaviors || []).map((b) => ({
        attack_technique: b.attack_technique || null, kind: b.pattern_kind, parent: b.parent || null,
        children: b.children || [], log_source: b.log_source || null, log_source_keys: logSourceKeys(b.log_source),
        time_window: b.time_window || null, vendor_stated: !!b.vendor_stated, novel: !!b.novel,
      })),
      detection_guidance: (s.guidance || []).map((g) => ({
        text: g.raw, url: g.url || null, publisher_tier: g.publisher_tier ?? null,
        log_source: g.log_source || null, log_source_keys: logSourceKeys(g.log_source),
        source_published: (s.sources || []).find((x) => x.url === g.url)?.published_at || null,
      })),
      evidence_samples: (s.samples || []).map((e) => ({
        kind: e.kind, raw: e.raw, log_source: e.log_source || null, log_source_keys: logSourceKeys(e.log_source),
        attack_technique: e.attack_technique || null,
      })),
      iocs: [...s.newIocs, ...s.repeatIocs].map((i) => ({
        type: i.type, value: i.value_norm, role: i.role || null, new: i.isNew,
        seen_count: i.seen_count ?? null, first_seen: i.first_seen_at || null,
      })),
      sources: (s.sources || []).map((x) => ({ url: x.url, publisher: x.publisher || null, published_at: x.published_at || null, outcome: x.outcome || null })),
      // AI-proposed hunt shapes (lib/queries.js): tier `proposed`, placeholders only, candidates for a lab
      proposed_queries: s.raw_iocs?.proposed_queries || [],
    })),
    watch_events_48h: (d.watchEvents || []).map((e) => ({
      at: e.created_at, level: e.level, kind: e.kind, watch: e.watch_title,
      story_id: e.watch_story_id || null,
      summary: e.summary, url: e.url || null, new_iocs: e.assessment?.new_iocs || [],
    })),
  };
}

// Executive view: verdict-shaped cards for the stories that matter (deep reads and P1/P2),
// HIGH watch developments, one-liners for the rest. No IoC tables, no hunt cards.
function cisoBody(d) {
  const pri = (s) => s.priority ?? 3;
  const cards = d.analyzed.filter((s) => s.selected || pri(s) <= 2);
  const rest = d.analyzed.filter((s) => !cards.includes(s));
  // HIGH only, and HIGH that stands on substance: a model-assessed material change, a KEV
  // listing, or a high-traction PoC repo. A stray HIGH with no assessed substance stays off
  // the executive view ("a watched blog changed" is never a development worth their click).
  const highs = (d.watchEvents || []).filter((e) => e.level === 'HIGH'
    && (e.assessment?.material || e.kind === 'kev_added' || e.kind === 'poc_repo'));
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
    parts.push('<h3 style="border:none;padding-top:0">Developments on tracked stories (48 h)</h3>');
    for (const [title, evs] of highByStory) {
      const newestFirst = [...evs].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
      parts.push(`<details><summary><b style="color:var(--text)">${esc(title)}</b> <span class="s">· ${evs.length} development${evs.length === 1 ? '' : 's'}</span></summary><ul>`
        + newestFirst.map((e) => `<li><span class="s">${esc(ts(e.created_at))}</span> ${esc(e.summary)}${e.url ? ` <a href="${esc(e.url)}">source</a>` : ''}</li>`).join('')
        + '</ul></details>');
    }
  }

  parts.push(`<h3 id="cards" style="border:none">From the brief — ${cards.length} verdict-shaped card${cards.length === 1 ? '' : 's'}</h3>`);
  for (const s of cards) {
    const p = pri(s);
    parts.push(`<div class="card" id="s-${esc(String(s.id).slice(0, 8))}"><div class="chead"><span class="pri p${p}">P${p}</span><h3>${esc(s.title)}</h3></div>`,
      `<div>${chips([s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...s.cves])}${updateChip(s)}`
      + (s.newIocs?.length || s.repeatIocs?.length ? `<a class="c" href="/?view=iocs#s-${esc(String(s.id).slice(0, 8))}">IoC card</a>` : '') + verdictChip(s, d) + draftChip(s, d) + '</div>',
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

    const json = req.query.format === 'json';
    // published AI cards (table may not exist before migration 0004)
    let aiRows = [];
    try { aiRows = await store.listCardDrafts({ status: 'promoted', limit: 50 }); } catch { aiRows = []; }
    IDX = cardIndex(aiRows);

    const qraw = String(req.query.q || '').trim().slice(0, 80);
    if (qraw) {
      const [stories, iocs] = await Promise.all([store.searchStories(qraw), store.searchIocs(qraw)]);
      if (json) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.status(200).send(JSON.stringify({
          kind: 'cutsign.search', q: qraw, generated: new Date().toISOString(),
          note: 'Public OSINT only. IoC values are raw (not defanged) for direct query use.',
          stories: stories.map((s) => ({
            id: s.id, title: s.title, brief_date: s.brief_date || null, priority: s.priority ?? 3, deep_read: !!s.selected,
            severity: s.severity || null, cves: s.cves || [], threat_actor: s.threat_actor || null,
            malware_family: s.malware_family || null, summary: s.summary || '', ioc_count: s.ioc_count || 0,
            proposals: (s.proposed_queries || []).map((p) => ({ id: p.id, name: p.name, shape: p.shape, confidence: p.confidence })),
          })),
          iocs: iocs.map((i) => ({
            type: i.type, value: i.value_norm, seen_count: i.seen_count,
            first_seen: i.first_seen_at, context: i.context || null,
            stories: (i.stories || []).map((s) => ({ id: s.id, title: s.title, brief_date: s.date })),
          })),
        }, null, 1));
      }
      return res.status(200).send(doc(`Cutsign — search “${qraw}”`,
        searchForm(qraw) + '<nav class="tabs"><a href="/">← latest brief</a></nav>',
        `<div class="w">${searchBody(qraw, stories, iocs)}</div>`,
        'Cutsign · public OSINT digest · search across all stored briefs'));
    }

    // AI-generated card draft (lib/hype.js → lib/carddraft.js): uuid URL, banner, never in the manifest
    if (req.query.view === 'draft') {
      const id = String(req.query.id || '');
      let row = null;
      try { row = /^[0-9a-f-]{36}$/i.test(id) ? await store.getCardDraft(id) : null; } catch { row = null; }
      if (!row) return res.status(404).send(doc('Cutsign — draft', '', '<div class="w"><p class="s">No such draft.</p></div>', 'Cutsign'));
      const tabsDraft = '<nav class="tabs"><a href="/?view=analyst">Analyst</a><a href="/?view=ciso">CISO</a><a href="/?view=agent">Agent</a><a href="/?view=iocs">IoCs</a><a href="/?view=cards">Cards</a></nav>';
      if (row.status === 'promoted' && row.promoted_slug) { res.setHeader('Location', `/cards/${row.promoted_slug}`); return res.status(302).send(''); }
      return res.status(200).send(doc(`Cutsign — draft: ${row.title}`, tabsDraft + searchForm(''),
        `<div class="w">${printBar}${draftBody(row)}</div>`, 'Cutsign · AI-generated draft, unreviewed · public OSINT only'));
    }

    // A card the pipeline published: /cards/<slug> (vercel.json rewrites it here; the static
    // .html files are the hand-written cards and are served before any rewrite)
    if (req.query.view === 'card') {
      const slug = String(req.query.slug || '').toLowerCase();
      const row = aiRows.find((r) => r.promoted_slug === slug) || null;
      if (!row) return res.status(404).send(doc('Cutsign — card', '', '<div class="w"><p class="s">No such card. <a href="/?view=cards">All cards</a></p></div>', 'Cutsign'));
      const tabsCard = '<nav class="tabs"><a href="/?view=analyst">Analyst</a><a href="/?view=ciso">CISO</a><a href="/?view=agent">Agent</a><a href="/?view=iocs">IoCs</a><a href="/?view=cards">Cards</a></nav>';
      res.setHeader('Cache-Control', 's-maxage=120, stale-while-revalidate=600');
      return res.status(200).send(doc(`Cutsign — ${row.title}`, tabsCard + searchForm(''),
        `<div class="w">${printBar}${draftBody(row, { published: true })}${subscribeForm()}</div>`, 'Cutsign · AI-generated verdict card, auto-published · public OSINT only'));
    }

    // Verdict cards index: hand-written one-page verdicts (public/cards/), newest first
    if (req.query.view === 'cards') {
      // AI drafts awaiting a human, surfaced ones first (table may not exist before migration 0004)
      let drafts = [];
      try { drafts = (await store.listCardDrafts({ status: 'draft', limit: 30 })).sort((a, b) => (b.surfaced_at ? 1 : 0) - (a.surfaced_at ? 1 : 0)); } catch { drafts = []; }
      // a hand-written card's automated coverage check rides on its manifest story rows
      // (lib/hype.js writes raw_iocs.hype.card_coverage); its AI re-issue draft is a draft row that names it
      const handIds = CARDS.flatMap((c) => c.story_ids);
      let handRows = [];
      try { handRows = await store.getStories(handIds); } catch { handRows = []; }
      const coverageOf = (c) => c.source === 'ai' ? c.coverage || null
        : handRows.filter((r) => c.story_ids.includes(r.id) && r.raw_iocs?.hype?.card_coverage).map((r) => r.raw_iocs.hype.card_coverage).sort((a, b) => String(b.checked_at).localeCompare(String(a.checked_at)))[0] || null;
      // the re-issue draft is folded into the hand-written card page by lifecycle.js: the new lane and
      // verdict, what changed since the card's as-of date, the timeline after it; the draft page has the rest
      const reissueOf = (c) => {
        const x = drafts.find((r) => (r.reasons || []).includes(`re-issue of card ${c.slug}`));
        if (!x) return null;
        const d = x.draft || {};
        return { id: x.id, version: x.version || 1, created_at: x.created_at, as_of: String(x.created_at).slice(0, 10), url: `/?view=draft&id=${x.id}`,
          lane: d.lane || null, priority: d.triage?.priority || null, confidence: d.confidence || null, verdict: d.verdict || null,
          changes: (d.changes_since_prior || []).slice(0, 10), timeline: (d.timeline || []).filter((t) => String(t.date || '') > c.date).slice(0, 10) };
      };
      const candidates = drafts.filter((x) => !(x.reasons || []).some((r) => r.startsWith('re-issue of card ')));
      if (json) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        // live KEV status per card CVE: the card pages read it and correct a stale "not listed" row
        const kev = await kevEntries();
        const kevOf = (c) => Object.fromEntries((c.cves || []).filter((v) => kev.has(v)).map((v) => [v, { date_added: kev.get(v).dateAdded, due_date: kev.get(v).dueDate || null }]));
        return res.status(200).send(JSON.stringify({
          kind: 'cutsign.cards', generated: new Date().toISOString(),
          cards: IDX.cards.map((c) => ({ ...c, kev: kevOf(c), coverage: coverageOf(c), reissue: c.source === 'hand' ? reissueOf(c) : null })),
          candidates: candidates.map((x) => ({ id: x.id, title: x.title, version: x.version || 1, score: x.score, reasons: x.reasons, created_at: x.created_at, surfaced_at: x.surfaced_at || null, url: `/?view=draft&id=${x.id}` })),
        }, null, 1));
      }
      const tabsCards = '<nav class="tabs"><a href="/?view=analyst">Analyst</a><a href="/?view=ciso">CISO</a><a href="/?view=agent">Agent</a><a href="/?view=iocs">IoCs</a><span>Cards</span></nav>';
      const candHtml = candidates.length ? `<h3 style="border:none">AI drafts below the publish bar (${candidates.length})</h3>`
        + candidates.map((x) => `<div class="card"><div class="chead"><h3><a href="/?view=draft&id=${esc(x.id)}">${esc(x.title)}</a></h3></div>`
          + `<div>${x.surfaced_at ? '<span class="c" style="color:var(--bad)">ready to publish</span>' : ''}<span class="c">AI draft v${esc(String(x.version || 1))}</span><span class="c">score ${esc(String(x.score))}</span><span class="c">${esc(String(x.created_at).slice(0, 10))}</span>${(x.reasons || []).map((r) => `<span class="c">${esc(r)}</span>`).join('')}</div>`
          + `<p class="s" style="margin:8px 0 0">AI-generated, unreviewed. ${esc(x.draft?.verdict || '')}</p></div>`).join('\n') : '';
      const active = IDX.cards.filter((c) => c.status === 'active');
      const retired = IDX.cards.filter((c) => c.status !== 'active').sort((a, b) => String(b.archived_on || '').localeCompare(String(a.archived_on || '')));
      const aiN = active.filter((c) => c.source === 'ai').length;
      const hero = `<div class="hero"><h1>Verdict cards</h1><p class="sub">${active.length} active card${active.length === 1 ? '' : 's'}${aiN ? ` (${aiN} AI-published)` : ''}${retired.length ? ` · ${retired.length} archived` : ''} · one-page verdicts with lane, exposure, detection coverage (checked automatically from public sources) and escalation triggers · print to PDF from the card</p></div>`;
      // newest day first; within a day, urgency order (hunt/IR, patch-now, patch, prepare)
      const laneRank = (l) => /hunt|ir/i.test(l) && !/patch/i.test(l) ? 0 : /now/i.test(l) ? 1 : /patch/i.test(l) ? 2 : 3;
      const sorted = [...active].sort((a, b) => b.date.localeCompare(a.date) || laneRank(a.lane) - laneRank(b.lane));
      const cardHtml = (c) => `<div class="card"><div class="chead"><h3><a href="${esc(c.url)}">${esc(c.title)}</a></h3></div>`
        + `<div><span class="c">${esc(c.lane)}</span><span class="c">as of ${esc(c.date)}</span>`
        + (c.source === 'ai' ? `<span class="c" style="color:var(--acc)">AI-published v${esc(String(c.version || 1))}</span>` : '')
        + (c.status !== 'active' ? `<span class="c">${esc(c.status)}${c.archived_on ? ` ${esc(c.archived_on)}` : ''}</span>` : '')
        + (c.superseded_by ? `<a class="c" href="/cards/${esc(c.superseded_by)}.html">↳ superseded by ${esc(c.superseded_by)}</a>` : '')
        + c.cves.map((v) => `<a class="c" href="/?q=${encodeURIComponent(v)}">${esc(v)}</a>`).join('')
        + (reissueOf(c) && c.source === 'hand' ? `<a class="c" style="color:var(--bad)" href="${esc(c.url)}">re-issued ${esc(reissueOf(c).as_of)} (AI v${esc(String(reissueOf(c).version))})${reissueOf(c).lane && reissueOf(c).lane !== c.lane ? ` · ${esc(reissueOf(c).lane)}` : ''}</a>` : '')
        + `<a class="c" href="${esc(c.url)}">open card</a></div>`
        + `<p style="margin:8px 0 0">${esc(c.summary)}</p></div>`;
      const parts = [];
      let day = '';
      for (const c of sorted) {
        if (c.date !== day) { day = c.date; parts.push(`<h3 style="border:none">${esc(day)}</h3>`); }
        parts.push(cardHtml(c));
      }
      if (retired.length) {
        parts.push(`<details><summary class="s">Archived (${retired.length}) — no longer tracked; pages stay at their URLs</summary>${retired.map(cardHtml).join('\n')}</details>`);
      }
      const partsHtml = candHtml + parts.join('\n');
      return res.status(200).send(doc('Cutsign — verdict cards', tabsCards + searchForm(''),
        `${hero}<div class="w">${subscribeForm()}${partsHtml}</div>`, 'Cutsign · verdict cards · public OSINT only'));
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
    const view = ['ciso', 'agent', 'iocs', 'analyst'].includes(req.query.view) ? req.query.view : 'ciso'; // root = CISO
    const q = (date) => `/?d=${encodeURIComponent(date)}&view=${view}`;

    // Cumulative IoC corpus: day-independent union of every stored indicator (iocs table)
    // and every watch-event IoC (which live only in event assessments). Human view defangs;
    // ?format=json carries raw values for machine use.
    if (view === 'iocs') {
      const [corpus, watchIocs] = await Promise.all([store.listIocCorpus(), store.listWatchIocEvents()]);
      if (json) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.status(200).send(JSON.stringify({
          kind: 'cutsign.iocs', generated: new Date().toISOString(),
          note: 'Cumulative across all briefs and watch events. Values are raw (not defanged). Public OSINT only. Brief IoCs and watch IoCs may overlap.',
          iocs: corpus.map((i) => ({
            type: i.type, value: i.value_norm, seen_count: i.seen_count,
            first_seen: i.first_seen_at, context: i.context || null,
            stories: i.stories.map((s) => ({ id: s.id, title: s.title, brief_date: s.date })),
          })),
          watch_iocs: watchIocs.flatMap((e) => e.new_iocs.map((i) => ({ type: i.type, value: i.value, context: i.context || null, watch: e.watch, story_id: e.story_id, at: e.at }))),
        }, null, 1));
      }

      // one card per story (campaign), CISO-style: newest brief first, its indicators inside,
      // cross-links where an IoC also appears in another card and where a story updates another
      const sid = (id) => `s-${String(id).slice(0, 8)}`;
      const cards = new Map(); // story id -> { story, iocs, watch }
      const orphans = [];
      for (const i of corpus) {
        if (!i.stories.length) { orphans.push(i); continue; }
        for (const s of i.stories) {
          if (!cards.has(s.id)) cards.set(s.id, { story: s, iocs: [], watch: [] });
          cards.get(s.id).iocs.push(i);
        }
      }
      for (const e of watchIocs) { // a watch tracks a story: fold its IoCs into that card
        const hit = (e.story_id && cards.get(e.story_id))
          || [...cards.values()].find((c) => e.story_id && c.story.updates_story_id === e.story_id);
        if (hit) hit.watch.push(e);
        else if (e.story_id || e.watch) orphans.push(...e.new_iocs.map((i) => ({ type: i.type, value_norm: i.value, seen_count: 1, first_seen_at: e.at, context: `${e.watch}: ${i.context || ''}` })));
      }
      const sorted = [...cards.values()].sort((a, b) => String(b.story.date || '').localeCompare(String(a.story.date || ''))
        || (a.story.priority ?? 3) - (b.story.priority ?? 3));

      // behaviors + published detection guidance for every carded story
      const storyIds = [...cards.keys()];
      const [behaviors, evidence] = await Promise.all([store.listBehaviors(storyIds), store.listEvidence(storyIds)]);
      const gUrls = [...new Set(evidence.filter((e) => e.kind === 'guidance' && e.url).map((e) => e.url))];
      const pubByUrl = new Map((gUrls.length ? await store.getSources(gUrls) : []).map((x) => [x.url, x.published_at]));
      const gLine = (g) => `<li>${esc(String(g.raw || '').split('\n')[0].slice(0, 300))}`
        + `${g.publisher_tier ? ` <span class="c">tier ${esc(String(g.publisher_tier))}</span>` : ''}`
        + `${pubByUrl.get(g.url) ? ` <span class="s">published ${esc(ts(pubByUrl.get(g.url)))}</span>` : ''}`
        + `${/^https?:\/\//i.test(g.url || '') ? ` <a href="${esc(g.url)}">link</a>` : ''}`
        + `${String(g.raw || '').includes('\n') ? `<pre>${esc(g.raw)}</pre>` : ''}</li>`;

      const row = (i, selfId) => {
        const also = (i.stories || []).filter((s) => s.id !== selfId && cards.has(s.id))
          .map((s) => `<a href="#${sid(s.id)}">also ${esc(s.date || 'brief')}</a>`).join(' ');
        return `<tr><td>${esc(i.type)}</td><td class="v"><a href="/?q=${encodeURIComponent(i.value_norm)}">${esc(defang(i.type, i.value_norm))}</a></td>`
          + `<td>${i.seen_count}×</td><td>${esc(ts(i.first_seen_at))}</td><td class="x">${esc(i.context || '')}${also ? ` · ${also}` : ''}</td></tr>`;
      };
      const parts = ['<p class="s">Every indicator Cutsign has stored, grouped by the story it belongs to — newest brief first. Values link to search (every story and record containing them); chips link to the day\'s brief and related cards. Raw machine version: <code>/?view=iocs&amp;format=json</code>.</p>'];
      for (const c of sorted) {
        const s = c.story;
        const p = s.priority ?? 3;
        const parent = s.updates_story_id && cards.has(s.updates_story_id);
        const children = sorted.filter((x) => x.story.updates_story_id === s.id);
        const seen = new Set(); const uniq = c.iocs.filter((i) => !seen.has(`${i.type}|${i.value_norm}`) && seen.add(`${i.type}|${i.value_norm}`));
        const behs = behaviors.filter((b) => b.story_id === s.id);
        const guid = evidence.filter((e) => e.story_id === s.id && e.kind === 'guidance');
        parts.push(`<div class="card" id="${sid(s.id)}"><div class="chead"><span class="pri p${p}">P${p}</span><h3>${esc(s.title)}</h3></div>`,
          `<div>${s.date ? `<a class="c" href="/?d=${encodeURIComponent(s.date)}&view=analyst#${sid(s.id)}">brief ${esc(s.date)}</a>` : ''}`
          + (s.date && ((s.priority ?? 3) <= 2 || s.selected) ? `<a class="c" href="/?d=${encodeURIComponent(s.date)}&view=ciso#${sid(s.id)}">CISO card</a>` : '')
          + verdictChip(s)
          + `<span class="c">${uniq.length} IoC${uniq.length === 1 ? '' : 's'}</span>`
          + (parent ? `<a class="c" href="#${sid(s.updates_story_id)}">↳ updates earlier card</a>` : '')
          + children.map((x) => `<a class="c" href="#${sid(x.story.id)}">↰ updated by ${esc(x.story.date || 'later brief')}</a>`).join('') + '</div>',
          `<table>${uniq.map((i) => row(i, s.id)).join('')}</table>`,
          behs.length ? `<details><summary class="s">Behaviors (${behs.length})${s.date ? ` · as of ${esc(s.date)}` : ''}</summary>${behs.map(behaviorLine).join('')}</details>` : '',
          guid.length ? `<details><summary class="s">Detection guidance (${guid.length})${s.date ? ` · as of ${esc(s.date)}` : ''}</summary><ul class="s">${guid.map(gLine).join('')}</ul></details>` : '');
        for (const e of c.watch) {
          parts.push(`<p class="s" style="margin:8px 0 2px">via watch · ${esc(ts(e.at))}</p><table>`
            + e.new_iocs.map((i) => row({ type: i.type, value_norm: i.value, seen_count: 1, first_seen_at: e.at, context: i.context })).join('') + '</table>');
        }
        parts.push('</div>');
      }
      if (orphans.length) {
        parts.push(`<div class="card" id="s-unattributed"><div class="chead"><span class="pri p3">—</span><h3>Unattributed</h3></div><table>${orphans.map((i) => row(i, null)).join('')}</table></div>`);
      }
      const total = corpus.length + watchIocs.reduce((n, e) => n + e.new_iocs.length, 0);
      const heroIocs = `<div class="hero"><h1>IoC corpus</h1><p class="sub">${total} indicators · ${sorted.length} stories · cumulative across all briefs and watch events</p></div>`;
      const tabsIocs = `<nav class="tabs"><a href="/?view=analyst">Analyst</a><a href="/?view=ciso">CISO</a><a href="/?view=agent">Agent</a><span>IoCs</span><a href="/?view=cards">Cards</a></nav>`;
      return res.status(200).send(doc('Cutsign — IoC corpus', tabsIocs + searchForm(''),
        `${heroIocs}<div class="w">${parts.join('\n')}</div>`,
        'Cutsign · public OSINT digest · cumulative IoC corpus'));
    }

    const d = await buildDigestData(store, pick.run);
    // AI drafts (lib/hype.js) that crossed the surface bar: a chip on their story in the CISO view
    // and an ai_draft link in the agent JSON; the table may not exist before migration 0004
    try { d.drafts = (await store.listCardDrafts({ status: 'draft', limit: 30 })).filter((x) => x.surfaced_at); } catch { d.drafts = []; }
    try { // web view: recent watch events regardless of digested/notified state
      const cutoff = Date.now() - 48 * 3600 * 1000;
      d.watchEvents = (await store.listWatchEvents({})).filter((e) => new Date(e.created_at).getTime() >= cutoff);
    } catch { /* watches table absent — keep whatever buildDigestData found */ }

    if (view === 'agent' && json) {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return res.status(200).send(JSON.stringify(agentJson(d, days), null, 1));
    }

    // analyst view: full (level 0) email body, minus the email-only chrome; if render.js markup
    // drifts these strips become no-ops and the page just shows a little extra, never breaks
    // Web-only: each watched story's updates collapse to a clickable title (the email keeps
    // the flat list); HIGH badge surfaces on the summary line so nothing urgent hides.
    const collapseWatch = (html) => {
      const start = html.indexOf('<h3>Developments on tracked stories');
      if (start === -1) return html;
      const next = html.indexOf('<h3', start + 10);
      const end = next === -1 ? html.length : next;
      const region = html.slice(start, end).replace(/<p class="k">([^<]+)<\/p>([\s\S]*?)(?=<p class="k">|$)/g, (m, title, body) =>
        `<details><summary>${body.includes('class="new"') ? '<span class="new">HIGH</span> ' : ''}<b style="color:var(--text)">${title}</b> <span class="s">· click to expand</span></summary>${body}</details>`);
      return html.slice(0, start) + region + html.slice(end);
    };
    const analystBody = () => {
      const full = renderHtml(d, 0, { proposals: true });
      return collapseWatch(full.slice(full.indexOf('<div class="w">') + '<div class="w">'.length, full.lastIndexOf('</div></body></html>')))
        .replace('<h3>Developments on tracked stories', '<h3 id="watch">Developments on tracked stories') // tile deep-link target
        .replace(/<p class="ban">[\s\S]*?<\/p>/, '')                                   // email banner
        .replace(/<h2 style="[^"]*">Cutsign — [\s\S]*?<\/h2>/, '')                      // email heading (hero replaces it)
        .replace(/<p class="dl">[\s\S]*?<\/p>/, '')                                     // delta line (tiles replace it)
        .replace(/<p class="s">[^<]*brief: “[\s\S]*?<\/p>/, '')                         // meta line (hero sub replaces it)
        .replace(/<hr>\s*<p class="s">Reply with freeform[\s\S]*?<\/p>/, '')            // email reply footer
    };

    const tabLink = (v, label) => view === v
      ? `<span>${label}</span>`
      : `<a href="/?d=${encodeURIComponent(pick.date)}&view=${v}">${label}</a>`;
    const tabs = `<nav class="tabs">${tabLink('analyst', 'Analyst')}${tabLink('ciso', 'CISO')}${tabLink('agent', 'Agent')}<a href="/?view=iocs">IoCs</a><a href="/?view=cards">Cards</a></nav>`;
    const nav = days.slice(0, 14).map((x) => x.date === pick.date
      ? `<span>${esc(x.date.slice(5))}</span>` : `<a href="${q(x.date)}">${esc(x.date.slice(5))}</a>`).join('');
    const deep = d.analyzed.filter((s) => s.selected).length;
    // tiles count what matters: watch developments above the low-signal bar, and this
    // brief's stories that have a hand-written verdict card
    const matWatch = (d.watchEvents || []).filter((e) => e.level === 'HIGH' || e.assessment?.new_iocs?.length || e.assessment?.deep).length;
    const cardsToday = d.analyzed.filter((s) => cardOf(s, d)).length;

    // each counting tile opens an inline strip breaking its number down per story, deep-linked —
    // a count you cannot decompose is decoration
    const sid8 = (id) => `s-${String(id).slice(0, 8)}`;
    const tstrip = (id, title, items) => items.length
      ? `<div class="tdetail" id="${id}"><a class="x" href="#">× close</a><b>${esc(title)}</b><ul>${items.join('')}</ul></div>` : '';
    const iocStories = d.analyzed.filter((s) => s.newIocs.length)
      .map((s) => `<li><a href="/?d=${encodeURIComponent(pick.date)}&view=agent#${sid8(s.id)}">${esc(s.title)}</a> <span class="s">· ${s.newIocs.length} new IoC${s.newIocs.length === 1 ? '' : 's'} (raw, agent view)</span></li>`);
    const behStories = d.analyzed.map((s) => ({ s, n: s.behaviors.filter((b) => b.novel).length })).filter((x) => x.n)
      .map(({ s, n }) => `<li><a href="/?d=${encodeURIComponent(pick.date)}&view=analyst#${sid8(s.id)}">${esc(s.title)}</a> <span class="s">· ${n} novel behavior${n === 1 ? '' : 's'}</span></li>`);
    const updStories = d.analyzed.filter((s) => s.updateOf)
      .map((s) => `<li><a href="/?d=${encodeURIComponent(pick.date)}&view=analyst#${sid8(s.id)}">${esc(s.title)}</a> <span class="s">· updates ${esc(s.updateOf.brief_date || String(s.updateOf.created_at).slice(0, 10))}'s story</span></li>`);

    const hero = `<div class="hero"><h1>${esc(d.date)}${d.run.dry ? ' <span class="s">(dry run)</span>' : ''}</h1>
      <p class="sub">${d.analyzed.length} stories analyzed · ${deep} deep reads · brief: “${esc(d.brief.subject)}”</p>
      <p class="sub">received ${esc(ts(d.brief.received_at))}${d.run.finished_at ? ` · emailed ${esc(ts(d.run.finished_at))}` : ''}</p></div>
      <div class="tiles">${tile(d.newIocCount, 'new IoCs', d.newIocCount > 0, '#t-ioc')}${tile(d.novelBehaviorCount, 'novel behaviors', d.novelBehaviorCount > 0, '#t-beh')}${tile(d.updateCount, 'story updates', false, '#t-upd')}${tile(matWatch, 'watch devs 48h', (d.watchEvents || []).some((e) => e.level === 'HIGH'), `/?d=${encodeURIComponent(pick.date)}&view=analyst#watch`)}${cardsToday ? tile(cardsToday, 'verdict cards', true, '/?view=cards') : ''}</div>`
      + tstrip('t-ioc', `New IoCs (${d.newIocCount}) — by story`, iocStories)
      + tstrip('t-beh', `Novel behaviors (${d.novelBehaviorCount}) — by story`, behStories)
      + tstrip('t-upd', `Story updates (${d.updateCount}) — developments of earlier briefs' stories`, updStories);

    const foot = `Cutsign · public OSINT digest · run ${esc(String(d.run.id).slice(0, 8))} · rendered ${new Date().toISOString().slice(0, 16)}Z`;
    const strip = view !== 'agent' && pick.date === days[0].date ? sinceStrip(d) : '';
    const jump = view === 'ciso' ? '<p class="s" style="margin:10px 0 0"><a href="#cards">↓ Jump to brief cards</a></p>'
      : view === 'analyst' ? '<p class="s" style="margin:10px 0 0"><a href="#brief">↓ Jump to brief</a></p>' : '';
    const body = view === 'ciso' ? cisoBody(d) : view === 'agent' ? agentBody(d, days) : analystBody();
    const inner = `${hero}${jump}${strip}<div class="w">${body}</div>`;
    const viewTag = view === 'ciso' ? ' — CISO view' : view === 'agent' ? ' — Agent view' : '';
    return res.status(200).send(doc(`Cutsign — ${d.date}${viewTag}`, tabs + searchForm('') + nav, inner, foot));
  } catch (e) {
    return res.status(500).send(doc('Cutsign', '', `<p class="bad">Error rendering page: ${esc(e.message)}</p>`, 'Cutsign'));
  }
}
