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
  return {
    run, brief,
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

const BANNER = 'Personal OSINT tool. Do not paste or forward anything from work into it or into replies.';

export function renderDigest(d) {
  const top = d.analyzed[0];
  const subject = `Cutsign — ${d.date} — ${d.analyzed.length} stories, ${d.newIocCount} new IoCs` + (top ? `, top: ${top.title}` : '');
  const css = {
    wrap: 'font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1b1f27;max-width:760px;margin:0 auto;line-height:1.5;font-size:14px',
    pre: 'font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#f4f5f7;border:1px solid #e2e4e8;border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;margin:4px 0',
    chip: 'display:inline-block;font-size:11px;padding:1px 6px;border-radius:3px;background:#eef0f4;margin-right:4px',
    h3: 'font-size:16px;margin:28px 0 4px',
    small: 'color:#5b6270;font-size:12px',
    td: 'padding:3px 8px 3px 0;vertical-align:top;font-size:12px',
  };
  const chips = (arr) => arr.filter(Boolean).map((c) => `<span style="${css.chip}">${esc(c)}</span>`).join('');
  const parts = [`<div style="${css.wrap}">`,
    `<p style="background:#fff4d6;border:1px solid #f0d58a;padding:6px 10px;font-size:12px;border-radius:4px">${esc(BANNER)}</p>`,
    `<h2 style="margin:12px 0 2px">Cutsign — ${esc(d.date)}${d.run.dry ? ' (dry run)' : ''}</h2>`,
    `<p style="margin:4px 0;padding:6px 10px;background:#eef6ee;border-radius:4px;font-size:13px"><b>New today:</b> ${d.newIocCount} IoCs · ${d.novelBehaviorCount} never-seen behaviors`
      + ` &nbsp;·&nbsp; <b>Restated:</b> ${d.restatedIocCount} IoCs · ${d.updateCount} story update${d.updateCount === 1 ? '' : 's'}</p>`,
    `<p style="${css.small}">${d.analyzed.length} stories analyzed (${d.analyzed.filter((s) => s.selected).length} deep, rest quick read) · ${d.newIocCount} new IoCs · brief: “${esc(d.brief.subject)}”</p>`];

  // light-read stories that turned up nothing huntable collapse to one line at the bottom
  const huntable = (s) => s.selected || s.behaviors.length || s.samples.length || s.guidance.length || s.newIocs.length || s.repeatIocs.length;
  const quiet = d.analyzed.filter((s) => !huntable(s));
  for (const s of d.analyzed.filter(huntable)) {
    const upd = s.updateOf ? ` <span style="font-weight:normal;font-size:13px;color:#5b6270">— update to ${esc(dateOnly(s.updateOf.created_at))}'s story</span>` : '';
    parts.push(`<h3 style="${css.h3}">P${s.priority ?? '?'} · ${esc(s.title)}${upd}</h3>`,
      `<div>${chips([s.selected ? null : 'quick read', s.section, s.severity, s.threat_actor && `actor: ${s.threat_actor}`, s.malware_family && `malware: ${s.malware_family}`, ...s.cves])}</div>`,
      `<p style="margin:6px 0">${esc(s.summary)}</p>`,
      `<p style="${css.small}">Why P${s.priority}: ${esc(s.priority_reason)}${s.attack_techniques.length ? ' · ATT&amp;CK: ' + s.attack_techniques.map(esc).join(', ') : ''}</p>`,
      s.selected && s.raw_iocs?.selection ? `<p style="${css.small}">Deep read — score ${s.raw_iocs.selection.score}: ${esc(s.raw_iocs.selection.why.join(', '))}</p>` : '');

    // on an update, behaviors already shown on earlier days fold away; elsewhere they're just marked
    const shown = s.updateOf ? s.behaviors.filter((b) => b.novel) : s.behaviors;
    const folded = s.updateOf ? s.behaviors.filter((b) => !b.novel) : [];
    const novelN = s.behaviors.filter((b) => b.novel).length;
    parts.push(`<p style="margin:10px 0 2px"><b>Behaviors (${s.behaviors.length}${s.behaviors.length ? `, ${novelN} new` : ''})</b></p>`);
    if (!s.behaviors.length) parts.push(`<p style="${css.small}">None extracted.</p>`);
    for (const b of shown) {
      const tags = [b.novel ? '★ new behavior' : 'seen before', b.pattern_kind,
        b.attack_technique && `${b.attack_technique} ${techniqueName(b.attack_technique) || ''}`, b.vendor_stated ? 'vendor-stated' : 'inferred'];
      parts.push(`<div style="margin:4px 0 8px">${chips(tags)}<br>`
        + `<code>${esc(b.parent || '?')}</code> → ${b.children.map((c) => `<code>${esc(c)}</code>`).join(', ') || '—'}`
        + `<br><span style="${css.small}">log: ${esc(b.log_source)}${b.time_window ? ' · window: ' + esc(b.time_window) : ''} · ${esc(b.source_quote_ref)}</span></div>`);
    }
    if (folded.length) {
      parts.push(`<details><summary style="${css.small}">Behaviors already reported (${folded.length})</summary>`
        + folded.map((b) => `<div style="${css.small};margin:2px 0">${esc(b.pattern_kind)}: <code>${esc(b.parent || '?')}</code> → ${b.children.map(esc).join(', ')}</div>`).join('') + '</details>');
    }

    if (s.samples.length) {
      parts.push(`<p style="margin:10px 0 2px"><b>Evidence samples (${s.samples.length})</b></p>`);
      for (const e of s.samples) {
        parts.push(`<div style="${css.small}">${esc(e.kind)}${e.log_source ? ' · ' + esc(e.log_source) : ''}${e.attack_technique ? ' · ' + esc(e.attack_technique) : ''}</div><pre style="${css.pre}">${esc(e.raw)}</pre>`);
      }
    }
    if (s.guidance.length) {
      parts.push(`<p style="margin:10px 0 2px"><b>Published detection guidance (${s.guidance.length})</b></p><ul style="margin:0;padding-left:18px">`);
      for (const g of s.guidance) {
        parts.push(`<li>${esc(g.raw.split('\n')[0].slice(0, 300))} ${chips([g.publisher_tier && `tier ${g.publisher_tier}`, g.log_source])}${safeHref(g.url) ? ` <a href="${safeHref(g.url)}">link</a>` : ''}`
          + (g.raw.includes('\n') ? `<pre style="${css.pre}">${esc(g.raw)}</pre>` : '') + '</li>');
      }
      parts.push('</ul>');
    }

    if (s.newIocs.length || s.repeatIocs.length) {
      parts.push(`<p style="margin:10px 0 2px"><b>IoCs</b> — ${s.newIocs.length} new${s.repeatIocs.length ? `, ${s.repeatIocs.length} seen before` : ''}</p>`);
      if (s.newIocs.length) {
        parts.push('<table style="border-collapse:collapse">');
        for (const i of s.newIocs) {
          parts.push(`<tr><td style="${css.td}">${esc(i.type)}</td><td style="${css.td};font-family:ui-monospace,Menlo,monospace;word-break:break-all">${esc(defang(i.type, i.value_norm))}</td><td style="${css.td}">${esc(i.role)}</td><td style="${css.td};color:#5b6270">${esc(i.context)}</td></tr>`);
        }
        parts.push('</table>');
      }
      if (s.repeatIocs.length) {
        parts.push(`<details><summary style="${css.small}">Seen before (${s.repeatIocs.length})</summary><ul style="margin:0;padding-left:18px;${css.small}">`
          + s.repeatIocs.map((i) => `<li><code>${esc(defang(i.type, i.value_norm))}</code> — seen ${i.seen_count} times, first on ${esc(dateOnly(i.first_seen_at))}</li>`).join('')
          + '</ul></details>');
      }
    }

    const srcLine = (x) => `<li>${safeHref(x.url) ? `<a href="${safeHref(x.url)}">${esc(x.publisher || x.url)}</a>` : esc(x.url)} — ${esc(x.outcome)}`
      + (x.suspicious ? ` <b style="color:#b42318">⚠ suspicious, excluded: ${esc(x.suspicious_reason)}</b>` : '')
      + (x.outcome !== 'ok' && x.error ? ` <span style="${css.small}">(${esc(x.error)})</span>` : '') + '</li>';
    parts.push(`<p style="margin:10px 0 2px;${css.small}">Sources</p><ul style="margin:0;padding-left:18px;${css.small}">${s.sources.map(srcLine).join('')}</ul>`);
  }

  if (quiet.length) {
    parts.push(`<h3 style="${css.h3};font-size:14px">Quick reads — nothing huntable found (${quiet.length})</h3><ul style="padding-left:18px">`
      + quiet.map((s) => `<li><b>${esc(s.title)}</b> <span style="${css.small}">P${s.priority ?? '?'} · ${esc(s.summary)}</span>`
        + (s.suspicious_sources?.length ? ` <b style="color:#b42318">⚠ suspicious source excluded: ${s.suspicious_sources.map(esc).join(', ')}</b>` : '') + '</li>').join('') + '</ul>');
  }
  if (d.failed.length) {
    parts.push(`<h3 style="${css.h3}">Extraction failed (${d.failed.length})</h3><ul>`
      + d.failed.map((s) => `<li>${esc(s.title)} — <span style="${css.small}">${esc(s.extract_error)}</span></li>`).join('') + '</ul>');
  }
  if (d.notAnalyzed.length) {
    parts.push(`<h3 style="${css.h3};font-size:14px">Also in the brief, not analyzed (${d.notAnalyzed.length})</h3><ul style="${css.small};padding-left:18px">`
      + d.notAnalyzed.map((s) => `<li>${esc(s.title)} <span>(${esc(s.section)}${s.severity ? ', ' + esc(s.severity) : ''})</span></li>`).join('') + '</ul>');
  }
  parts.push(`<hr style="border:none;border-top:1px solid #e2e4e8;margin:24px 0 8px"><p style="${css.small}">Reply with freeform thoughts on what was missing or wrong — generic notes only, nothing from work. Run ${esc(d.run.id)}.</p></div>`);

  const text = [BANNER, '', `Cutsign — ${d.date}`, '',
    ...d.analyzed.flatMap((s) => [
      `P${s.priority} · ${s.title}`, s.summary,
      ...s.behaviors.map((b) => `  - [${b.attack_technique || '?'}] ${b.pattern_kind}: ${b.parent || '?'} -> ${b.children.join(', ')} (${b.log_source})`),
      `  IoCs: ${s.newIocs.length} new, ${s.repeatIocs.length} seen before`, '']),
  ].join('\n');

  return { subject, html: parts.join('\n'), text };
}
