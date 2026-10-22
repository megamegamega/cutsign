// v0 rendering: the daily read as one email (HTML + plain text) built from one data object.
// v1 replaces the body with a five-line summary + pack link; keep buildDigestData() as the seam.

import { techniqueName } from './attack.js';
import { isNovelBehavior } from './diff.js';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const safeHref = (u) => (/^https?:\/\//i.test(String(u || '')) ? esc(u) : '');

/** Defang for display so mail clients never linkify a malicious indicator. */
export function defang(type, v) {
  if (!['domain', 'url', 'ipv4', 'ipv6', 'email'].includes(type)) return v;
  return String(v).replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]');
}

const dateOnly = (iso) => (iso ? String(iso).slice(0, 10) : '');

/** Gather everything the email needs. */
export async function buildDigestData(store, run) {
  const brief = await store.getBrief(run.brief_id);
  const stories = await store.listStories(run.id);
  const ids = stories.map((s) => s.id);
  const [behaviors, evidence, links] = await Promise.all([store.listBehaviors(ids), store.listEvidence(ids), store.listStoryIocs(ids)]);
  const urls = [...new Set(stories.flatMap((s) => s.source_urls))];
  const sources = await store.getSources(urls);
  const byStory = (rows) => (id) => rows.filter((r) => r.story_id === id);
  // history for diffing: what earlier briefs (90 days) already showed
  const priors = await store.listPriorStories(run.id, 90);
  const priorById = new Map(priors.map((p) => [p.id, p]));
  const priorBehaviors = await store.listBehaviors(priors.map((p) => p.id));
  const analyzed = stories.filter((s) => s.status === 'extracted')
    .sort((a, b) => (a.priority ?? 3) - (b.priority ?? 3) || Number(b.selected) - Number(a.selected) || a.ordinal - b.ordinal)
    .map((s) => {
      const iocs = byStory(links)(s.id).filter((l) => l.ioc).map((l) => ({ ...l.ioc, role: l.role, isNew: l.ioc.first_seen_run_id === run.id }));
      return {
        ...s,
        behaviors: byStory(behaviors)(s.id).map((b) => ({ ...b, novel: isNovelBehavior(b, priorBehaviors) })),
        updateOf: s.updates_story_id ? priorById.get(s.updates_story_id) || null : null,
        guidance: byStory(evidence)(s.id).filter((e) => e.kind === 'guidance'),
        samples: byStory(evidence)(s.id).filter((e) => e.kind !== 'guidance'),
        newIocs: iocs.filter((i) => i.isNew),
        repeatIocs: iocs.filter((i) => !i.isNew),
        sources: s.source_urls.map((u) => sources.find((x) => x.url === u) || { url: u, outcome: 'not fetched' }),
      };
    });
  let watchEvents = [];
  try { watchEvents = await store.listWatchEvents({ undigested: true }); } catch { /* watches table not created yet */ }
  return {
    run, brief, watchEvents,
    date: brief.brief_date || dateOnly(brief.received_at),
    analyzed,
    failed: stories.filter((s) => s.status === 'failed'),
    notAnalyzed: stories.filter((s) => s.status === 'pending' || s.status === 'skipped'),
    newIocCount: new Set(analyzed.flatMap((s) => s.newIocs.map((i) => i.id))).size,
    restatedIocCount: new Set(analyzed.flatMap((s) => s.repeatIocs.map((i) => i.id))).size,
    novelBehaviorCount: analyzed.reduce((n, s) => n + s.behaviors.filter((b) => b.novel).length, 0),
    updateCount: analyzed.filter((s) => s.updateOf).length,
  };
}

const KIND_LABEL = {
  shell_from_server_process: 'Shell spawned by a server process', discovery_burst: 'Burst of discovery commands',
  download_cradle: 'Download of a second stage', persistence_artifact: 'Persistence', credential_access: 'Credential access',
  lateral_auth: 'Lateral movement / onward authentication', defense_evasion: 'Defense evasion', exfil_channel: 'Exfiltration channel',
  other: 'Behavior',
};
const attackUrl = (id) => `https://attack.mitre.org/techniques/${String(id).replace('.', '/')}/`;

const KIND_TEXT = { page_changed: 'source updated', new_source: 'new write-up', kev_added: 'CISA KEV', poc_repo: 'public repo', nvd_status: 'NVD' };

/** "Watched stories — what changed" since the last email, grouped by watch. HIGH items first.
 *  Low-traction repo mentions (poc_repo below the HIGH star bar) fold into one collapsed line per
 *  watch so a hot CVE's repo churn never swamps the material changes. */
function watchSection(events, chips) {
  if (!events.length) return '';
  const isRepoNoise = (e) => e.kind === 'poc_repo' && e.level !== 'HIGH';
  const byWatch = new Map();
  for (const e of events) { if (!byWatch.has(e.watch_title)) byWatch.set(e.watch_title, []); byWatch.get(e.watch_title).push(e); }
  const nNoise = events.filter(isRepoNoise).length;
  const nMaterial = events.length - nNoise;
  const out = [`<h3>Watched stories — what changed (${nMaterial}${nNoise ? ` + ${nNoise} repo mention${nNoise === 1 ? '' : 's'}` : ''})</h3>`];
  const li = (e) => {
    const a = e.assessment || {};
    return `<li>${e.level === 'HIGH' ? '<span class="new">HIGH</span>' : ''}${chips([KIND_TEXT[e.kind] || e.kind, e.notified_at ? 'alerted' : null])} ${esc(e.summary)}`
      + (e.url ? ` <a href="${esc(e.url)}">source</a>` : '')
      + (a.new_iocs?.length ? `<table>${a.new_iocs.map((i) => `<tr><td>${esc(i.type)}</td><td class="v">${esc(defang(i.type, i.value))}</td><td class="x">${esc(i.context)}</td></tr>`).join('')}</table>` : '')
      + (a.deep?.behaviors?.length ? a.deep.behaviors.map((b) => behaviorCard({ ...b, novel: true }, false)).join('') : '')
      + '</li>';
  };
  for (const [title, evs] of byWatch) {
    const noise = evs.filter(isRepoNoise);
    const shown = evs.filter((e) => !isRepoNoise(e));
    out.push(`<p class="k">${esc(title)}</p><ul>`);
    for (const e of shown.sort((a, b) => (a.level === 'HIGH' ? 0 : 1) - (b.level === 'HIGH' ? 0 : 1))) out.push(li(e));
    if (noise.length && noise.length < 3) for (const e of noise) out.push(li(e));
    else if (noise.length) {
      out.push(`<li>${chips(['public repos'])} ${noise.length} new low-traction repo mentions — mostly scanners, backports and fakes; alerts fire only at real traction.`
        + `<details><summary class="s">list (${noise.length})</summary><ul class="s">`
        + noise.map((e) => `<li>${esc(e.summary.slice(0, 140))}${e.url ? ` <a href="${esc(e.url)}">repo</a>` : ''}</li>`).join('')
        + '</ul></details></li>');
    }
    out.push('</ul>');
  }
  return out.join('');
}

/** "Can I rule this out?" box — only the conditions the sources state; omitted when there are none.
 *  Exported for the web CISO view (api/page.js). */
export function exposureBox(x) {
  if (!x) return '';
  const rows = [['Affected', x.affected], ['Only if', x.only_if], ['Not affected if', x.not_affected_if], ['Fixed in', x.fixed_in ? [x.fixed_in] : []]]
    .filter(([, v]) => v && v.length)
    .map(([k, v]) => `<div><b>${k}</b>${v.map(esc).join(' · ')}</div>`);
  return rows.length ? `<div class="ex"><div class="h">EXPOSURE CHECK</div>${rows.join('')}</div>` : '';
}

/** One behavior as a hunt card: what → chain → where to look → why we believe it. */
function behaviorCard(b, trim) {
  const tech = b.attack_technique
    ? ` <a href="${attackUrl(b.attack_technique)}">${esc(b.attack_technique)} ${esc(techniqueName(b.attack_technique) || '')}</a>` : '';
  const chain = [b.parent || '?', b.children.length ? b.children.join(' · ') : null].filter(Boolean).join(' → ');
  const where = [b.log_source, b.time_window && `window: ${b.time_window}`].filter(Boolean).join(' · ');
  return `<div class="bh${b.novel ? ' n' : ''}${b.vendor_stated ? '' : ' i'}">`
    + `<span class="basis">${b.vendor_stated ? 'vendor-stated' : 'inferred'}${b.novel ? '' : ' · seen before'}</span>`
    + `<div class="bt">${b.novel ? '<span class="new">★ NEW</span>' : ''}${esc(KIND_LABEL[b.pattern_kind] || b.pattern_kind)}${tech}</div>`
    + `<div class="ch">${esc(chain)}</div>`
    + (where ? `<div class="s">Hunt in: ${esc(where)}</div>` : '')
    + (!trim && b.source_quote_ref ? `<div class="q">${esc(b.source_quote_ref)}</div>` : '')
    + '</div>';
}

const BANNER = 'Personal OSINT tool. Do not paste or forward anything from work into it or into replies.';

// Gmail clips HTML bodies over ~102 KB ("[Message clipped]"). Styles live in one <style> block (classes,
// not per-element inline styles), and if a heavy day still runs long, quick-read stories are compacted
// step by step until the body fits.
export const MAX_HTML_BYTES = 95_000;

const STYLE = `
.w{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1b1f27;max-width:760px;margin:0 auto;line-height:1.5;font-size:14px}
.ban{background:#fff4d6;border:1px solid #f0d58a;padding:6px 10px;font-size:12px;border-radius:4px}
.dl{margin:4px 0;padding:6px 10px;background:#eef6ee;border-radius:4px;font-size:13px}
.s{color:#5b6270;font-size:12px}
h3{font-size:16px;margin:28px 0 4px}
h3 .u{font-weight:normal;font-size:13px;color:#5b6270}
.c{display:inline-block;font-size:11px;padding:1px 6px;border-radius:3px;background:#eef0f4;margin-right:4px}
.k{margin:10px 0 2px;font-weight:bold}
pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#f4f5f7;border:1px solid #e2e4e8;border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;margin:4px 0}
table{border-collapse:collapse} td{padding:3px 8px 3px 0;vertical-align:top;font-size:12px}
td.v{font-family:ui-monospace,Menlo,monospace;word-break:break-all} td.x{color:#5b6270}
ul{margin:0;padding-left:18px} .bad{color:#b42318}
.bh{border-left:3px solid #c9ced8;padding:4px 0 4px 10px;margin:8px 0}
.bh.n{border-left-color:#2f8f46} .bh.i{border-left-style:dashed}
.bt{font-weight:600} .bt a{font-weight:normal;color:#33408f;text-decoration:none;font-size:12px}
.new{display:inline-block;font-size:10px;font-weight:700;color:#fff;background:#2f8f46;border-radius:3px;padding:0 5px;margin-right:6px;vertical-align:1px}
.basis{float:right;color:#5b6270;font-size:11px}
.ch{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;background:#f4f5f7;border-radius:3px;padding:3px 6px;margin:3px 0;display:inline-block;word-break:break-all}
.q{color:#5b6270;font-size:12px;font-style:italic}
.ex{border:1px solid #d7dbe3;border-radius:4px;padding:6px 10px;margin:6px 0;font-size:12.5px}
.ex b{display:inline-block;min-width:118px;color:#5b6270;font-weight:600}
.ex .h{font-size:10.5px;letter-spacing:.06em;color:#5b6270;font-weight:700}
hr{border:none;border-top:1px solid #e2e4e8;margin:24px 0 8px}`;

export function renderDigest(d) {
  const top = d.analyzed[0];
  const subject = `Cutsign — ${d.date} — ${d.analyzed.length} stories, ${d.newIocCount} new IoCs` + (top ? `, top: ${top.title}` : '');
  let html;
  for (const level of [0, 1, 2]) {
    html = renderHtml(d, level);
    if (Buffer.byteLength(html) <= MAX_HTML_BYTES) break;
  }
  const text = [BANNER, '', `Cutsign — ${d.date}`, '',
    ...d.analyzed.flatMap((s) => [
      `P${s.priority} · ${s.title}`, s.summary,
      ...s.behaviors.map((b) => `  - [${b.attack_technique || '?'}] ${b.pattern_kind}: ${b.parent || '?'} -> ${b.children.join(', ')} (${b.log_source})`),
      `  IoCs: ${s.newIocs.length} new, ${s.repeatIocs.length} seen before`, '']),
  ].join('\n');
  return { subject, html, text };
}

/**
 * level 0: every huntable story in full
 * level 1: quick-read stories drop evidence/guidance/sources detail (counts kept); deep stories untouched
 * level 2: quick-read stories become one line each; deep stories untouched
 * Exported for the web view (api/page.js), which always renders level 0 and reskins the result.
 */
export function renderHtml(d, level) {
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span class="c">${esc(c)}</span>`).join('');
  const parts = [`<!doctype html><html><head><meta charset="utf-8"><style>${STYLE}</style></head><body><div class="w">`,
    `<p class="ban">${esc(BANNER)}</p>`,
    `<h2 style="margin:12px 0 2px">Cutsign — ${esc(d.date)}${d.run.dry ? ' (dry run)' : ''}</h2>`,
    `<p class="dl"><b>New today:</b> ${d.newIocCount} IoCs · ${d.novelBehaviorCount} never-seen behaviors`
      + ` &nbsp;·&nbsp; <b>Restated:</b> ${d.restatedIocCount} IoCs · ${d.updateCount} story update${d.updateCount === 1 ? '' : 's'}</p>`,
    `<p class="s">${d.analyzed.length} stories analyzed (${d.analyzed.filter((s) => s.selected).length} deep, rest quick read) · ${d.newIocCount} new IoCs · brief: “${esc(d.brief.subject)}”`
      + (level ? ` · long day: quick reads ${level === 1 ? 'trimmed' : 'listed as one-liners'} to fit Gmail` : '') + '</p>',
    watchSection(d.watchEvents || [], chips)];

  // light-read stories that turned up nothing huntable collapse to one line at the bottom
  const huntable = (s) => s.selected || s.behaviors.length || s.samples.length || s.guidance.length || s.newIocs.length || s.repeatIocs.length;
  const oneLine = (s) => `<li><b>${esc(s.title)}</b> <span class="s">P${s.priority ?? '?'} · ${esc(s.summary)}</span>`
    + (s.behaviors.length || s.newIocs.length ? ` <span class="s">(${s.behaviors.length} behaviors, ${s.newIocs.length} new IoCs)</span>` : '')
    + (s.suspicious_sources?.length ? ` <b class="bad">⚠ suspicious source excluded: ${s.suspicious_sources.map(esc).join(', ')}</b>` : '') + '</li>';
  const quiet = d.analyzed.filter((s) => !huntable(s));
  const full = d.analyzed.filter((s) => huntable(s) && (s.selected || level < 2));
  const squeezed = d.analyzed.filter((s) => huntable(s) && !s.selected && level === 2);

  for (const s of full) {
    const trim = level >= 1 && !s.selected;
    const upd = s.updateOf ? ` <span class="u">— update to ${esc(s.updateOf.brief_date || dateOnly(s.updateOf.created_at))}'s story</span>` : '';
    parts.push(`<h3>P${s.priority ?? '?'} · ${esc(s.title)}${upd}</h3>`,
      `<div>${chips([s.selected ? null : 'quick read', s.section, s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...s.cves])}</div>`,
      `<p style="margin:6px 0">${esc(s.summary)}</p>`,
      exposureBox(s.raw_iocs?.exposure),
      `<p class="s">Why P${s.priority}: ${esc(s.priority_reason)}${s.attack_techniques.length ? ' · ATT&amp;CK: ' + s.attack_techniques.map(esc).join(', ') : ''}</p>`,
      !s.selected || !s.raw_iocs?.selection ? ''
        : s.raw_iocs.selection.deep_done === 'reused'
          ? `<p class="s">Deep read reused from ${esc(s.raw_iocs.selection.reused_date)} — sources unchanged, no new indicators (score ${s.raw_iocs.selection.score})</p>`
          : `<p class="s">Deep read — score ${s.raw_iocs.selection.score}: ${esc(s.raw_iocs.selection.why.join(', '))}</p>`);

    // on an update, behaviors already shown on earlier days fold away; elsewhere they're just marked
    const shown = s.updateOf ? s.behaviors.filter((b) => b.novel) : s.behaviors;
    const folded = s.updateOf ? s.behaviors.filter((b) => !b.novel) : [];
    const novelN = s.behaviors.filter((b) => b.novel).length;
    parts.push(`<p class="k">Behaviors (${s.behaviors.length}${s.behaviors.length ? `, ${novelN} new` : ''})</p>`);
    if (!s.behaviors.length) parts.push('<p class="s">None extracted.</p>');
    // vendor-stated before inferred, new before seen-before
    const order = (b) => (b.vendor_stated ? 0 : 2) + (b.novel ? 0 : 1);
    for (const b of [...shown].sort((x, y) => order(x) - order(y))) parts.push(behaviorCard(b, trim));
    if (folded.length) {
      parts.push(`<details><summary class="s">Behaviors already reported (${folded.length})</summary>`
        + folded.map((b) => `<div class="s">${esc(b.pattern_kind)}: <code>${esc(b.parent || '?')}</code> → ${b.children.map(esc).join(', ')}</div>`).join('') + '</details>');
    }

    if (trim && (s.samples.length || s.guidance.length)) {
      parts.push(`<p class="s">${s.samples.length} evidence sample(s), ${s.guidance.length} detection guidance item(s) — omitted to fit Gmail.</p>`);
    } else {
      if (s.samples.length) {
        parts.push(`<p class="k">Evidence samples (${s.samples.length})</p>`);
        for (const e of s.samples) {
          parts.push(`<div class="s">${esc(e.kind)}${e.log_source ? ' · ' + esc(e.log_source) : ''}${e.attack_technique ? ' · ' + esc(e.attack_technique) : ''}</div><pre>${esc(e.raw)}</pre>`);
        }
      }
      if (s.guidance.length) {
        parts.push(`<p class="k">Published detection guidance (${s.guidance.length})</p><ul>`);
        for (const g of s.guidance) {
          parts.push(`<li>${esc(g.raw.split('\n')[0].slice(0, 300))} ${chips([g.publisher_tier && `tier ${g.publisher_tier}`, g.log_source])}${safeHref(g.url) ? ` <a href="${safeHref(g.url)}">link</a>` : ''}`
            + (g.raw.includes('\n') ? `<pre>${esc(g.raw)}</pre>` : '') + '</li>');
        }
        parts.push('</ul>');
      }
    }

    if (s.newIocs.length || s.repeatIocs.length) {
      parts.push(`<p class="k">IoCs <span class="s">— ${s.newIocs.length} new${s.repeatIocs.length ? `, ${s.repeatIocs.length} seen before` : ''}</span></p>`);
      if (s.newIocs.length) {
        parts.push('<table>' + s.newIocs.map((i) => `<tr><td>${esc(i.type)}</td><td class="v">${esc(defang(i.type, i.value_norm))}</td><td>${esc(i.role)}</td>`
          + (trim ? '' : `<td class="x">${esc(i.context)}</td>`) + '</tr>').join('') + '</table>');
      }
      if (s.repeatIocs.length) {
        parts.push(`<details><summary class="s">Seen before (${s.repeatIocs.length})</summary><ul class="s">`
          + s.repeatIocs.map((i) => `<li><code>${esc(defang(i.type, i.value_norm))}</code> — seen ${i.seen_count} times, first on ${esc(dateOnly(i.first_seen_at))}</li>`).join('')
          + '</ul></details>');
      }
    }

    const srcLine = (x) => `<li>${safeHref(x.url) ? `<a href="${safeHref(x.url)}">${esc(x.publisher || x.url)}</a>` : esc(x.url)} — ${esc(x.outcome)}`
      + (x.suspicious ? ` <b class="bad">⚠ suspicious, excluded: ${esc(x.suspicious_reason)}</b>` : '')
      + (x.outcome !== 'ok' && x.error ? ` <span class="s">(${esc(x.error)})</span>` : '') + '</li>';
    const srcs = trim ? s.sources.filter((x) => x.suspicious) : s.sources;
    if (srcs.length) parts.push(`<p class="k s">Sources</p><ul class="s">${srcs.map(srcLine).join('')}</ul>`);
  }

  if (squeezed.length) {
    parts.push(`<h3 style="font-size:14px">More quick reads (${squeezed.length})</h3><ul>${squeezed.map(oneLine).join('')}</ul>`);
  }
  if (quiet.length) {
    parts.push(`<h3 style="font-size:14px">Quick reads — nothing huntable found (${quiet.length})</h3><ul>${quiet.map(oneLine).join('')}</ul>`);
  }
  if (d.failed.length) {
    parts.push(`<h3>Extraction failed (${d.failed.length})</h3><ul>`
      + d.failed.map((s) => `<li>${esc(s.title)} — <span class="s">${esc(s.extract_error)}</span></li>`).join('') + '</ul>');
  }
  if (d.notAnalyzed.length) {
    parts.push(`<h3 style="font-size:14px">Also in the brief, not analyzed (${d.notAnalyzed.length})</h3><ul class="s">`
      + d.notAnalyzed.map((s) => `<li>${esc(s.title)} <span>(${esc(s.section)}${s.severity ? ', ' + esc(s.severity) : ''})</span></li>`).join('') + '</ul>');
  }
  parts.push(`<hr><p class="s">Reply with freeform thoughts on what was missing or wrong — generic notes only, nothing from work. Run ${esc(d.run.id)}.</p></div></body></html>`);
  return parts.join('\n');
}
