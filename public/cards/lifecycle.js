// Card lifecycle banner and live status: every card page loads this. It reads the cards JSON
// and (1) when this card is archived or superseded, says so at the top so a shared link never
// reads as current advice; (2) when an AI re-issue draft exists for this card (the pipeline saw
// developments after the card's as-of date), links it at the top; (3) appends the automated
// detection-coverage check under the hand-written coverage table; (4) when CISA KEV lists a CVE
// the card names, corrects the card's KEV row from the live catalog; (5) appends the generated
// external-attack-surface queries (generic Shodan/Censys filters; the reader scopes them in their
// own tool) after that table.
(async function () {
  try {
    const slug = (location.pathname.match(/\/cards\/([a-z0-9-]+)\.html$/) || [])[1];
    if (!slug) return;
    const r = await fetch('/?view=cards&format=json', { cache: 'no-store' });
    if (!r.ok) return;
    const me = ((await r.json()).cards || []).find((c) => c.slug === slug);
    if (!me) return;
    const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
    const banner = (id, html) => {
      const el = document.createElement('div');
      el.id = id;
      el.setAttribute('style', 'margin:0 0 16px;padding:12px 16px;border:1px solid #b58a2a;border-radius:8px;background:rgba(181,138,42,.12);font:600 14px/1.4 system-ui,sans-serif');
      el.innerHTML = html;
      document.body.insertBefore(el, document.body.firstChild);
    };

    if (me.status !== 'active') {
      banner('lifecycle', `${esc(me.status === 'superseded' ? 'Superseded' : 'Archived')} — no longer tracked${me.archived_on ? ' as of ' + esc(me.archived_on) : ''}. The verdict below is historical.`
        + (me.superseded_by ? ` Current card: <a href="/cards/${esc(me.superseded_by)}.html">${esc(me.superseded_by)}</a>.` : '')
        + ' <a href="/?view=cards">All cards</a>');
    }

    // the pipeline's re-issue, folded in: new lane and verdict first, then what changed and the
    // timeline after the card's date; the hand-written verdict below stays as of its own date
    if (me.reissue && me.reissue.url) {
      const r = me.reissue;
      const asOf = esc(r.as_of || String(r.created_at).slice(0, 10));
      const laneLine = r.lane && r.lane !== me.lane ? `<p style="margin:6px 0 0"><b>Lane:</b> ${esc(me.lane)} → <b>${esc(r.lane)}</b>${r.priority ? ` · ${esc(r.priority)}` : ''}${r.confidence ? ` · confidence ${esc(r.confidence)}` : ''}</p>` : (r.priority ? `<p style="margin:6px 0 0"><b>Lane:</b> ${esc(r.lane || me.lane)} · ${esc(r.priority)}</p>` : '');
      const changes = (r.changes || []).length ? `<p style="margin:8px 0 2px"><b>Changed since ${esc(me.date)}</b></p><ul style="margin:0;padding-left:20px;font-weight:400">${r.changes.map((x) => `<li>${esc(x).replace(/\[(S\d+)\]/g, '<span class="src">[$1]</span>')}</li>`).join('')}</ul>` : '';
      const tl = (r.timeline || []).length ? `<p style="margin:8px 0 2px"><b>Since the card</b></p><table style="font-weight:400">${r.timeline.map((t) => `<tr><td>${esc(t.date)}</td><td>${esc(t.event)}</td></tr>`).join('')}</table>` : '';
      banner('reissue', `<b>Re-issued automatically as of ${asOf}</b> (AI-generated v${esc(r.version)}, written by the pipeline from the stored public sources after developments on or after the card's as-of date, ${esc(me.date)}). `
        + (r.verdict ? `<span style="font-weight:400">${esc(r.verdict)}</span>` : '')
        + laneLine + changes + tl
        + `<p style="margin:8px 0 0;font-weight:400">The hand-written verdict below is as of ${esc(me.date)}. The <a href="${esc(r.url)}">full AI re-issue</a> has the hunts, scope, containment and sources behind this; its detection coverage and exposure queries are the automated ones on this page.</p>`);
      const asofEl = document.querySelector('.asof');
      if (asofEl) asofEl.insertAdjacentHTML('beforeend', ` <span class="src">· re-issued ${asOf} (AI)</span>`);
      const laneEl = document.querySelector('.card .lane');
      if (laneEl && r.lane && r.lane !== me.lane) laneEl.insertAdjacentHTML('beforeend', ` <span class="src">· re-issued: ${esc(r.lane)}</span>`);
      // a header tag the re-issue contradicts is struck, not deleted: the card stays legible as of its date
      const exploited = /actively exploited|in[- ]the[- ]wild|exploitation (observed|confirmed)/i.test((r.changes || []).join(' ') + ' ' + (r.verdict || ''));
      for (const tag of document.querySelectorAll('.card .lane .tag')) {
        if (exploited && /^no (known )?exploitation/i.test(tag.textContent.trim())) { tag.style.textDecoration = 'line-through'; tag.title = 'superseded by the re-issue'; }
      }
    }

    if (me.coverage && me.coverage.lanes && me.coverage.lanes.length) {
      const cls = (s) => (s === 'published' ? 'ok' : s === 'nothing found' ? 'bad' : 'src');
      const rows = me.coverage.lanes.map((l) => `<tr><td>${esc(l.category)}</td><td>${l.url && l.status !== 'nothing found' ? `<a href="${esc(l.url)}">${esc(l.name)}</a>` : esc(l.name)}</td><td><span class="${cls(l.status)}">${esc(l.status)}</span> — ${esc(l.detail)}</td></tr>`).join('');
      const s = me.coverage.summary || {};
      const html = `<h2 id="coverage-live">Detection coverage — automated check</h2><p class="src">Checked by the pipeline ${esc(String(me.coverage.checked_at).slice(0, 16).replace('T', ' '))}Z from public machine-readable sources and re-checked daily: ${esc(s.published || 0)} published, ${esc(s.nothing || 0)} nothing found, ${esc(s.unchecked || 0)} not machine-checkable, ${esc(s.failed || 0)} failed. The hand-written table above is the verdict as of the card's date; this one moves.</p><table><tr><th>Category</th><th>Source</th><th>Status</th></tr>${rows}</table>`;
      const heads = [...document.querySelectorAll('h2')];
      const h = heads.find((x) => /^Detection coverage/.test(x.textContent.trim()));
      let anchor = h; // after the hand-written table that follows the heading
      if (h) { let el = h.nextElementSibling; while (el && el.tagName !== 'TABLE' && el.tagName !== 'H2') el = el.nextElementSibling; if (el && el.tagName === 'TABLE') anchor = el; }
      if (anchor) anchor.insertAdjacentHTML('afterend', html);
      else document.body.insertAdjacentHTML('beforeend', html);

      // a hand-written row that said "nothing published" for a vendor the live check now finds is
      // corrected the way the KEV row is: struck, not deleted, with what the vendor published since
      // the card's date (Qualys QIDs, Tenable plugins, a CrowdStrike / Akamai / Wiz post, rule files)
      const vendorOf = (name) => (name.split(' · ')[0].match(/^(Qualys|Tenable|Rapid7|CrowdStrike|Microsoft|SentinelOne|Cloudflare|Akamai|Wiz|Talos|Elastic|Unit 42|Huntress|Sophos|Arctic Wolf|SigmaHQ|Splunk|Nuclei|Emerging Threats|Red Hat|Debian)/) || [])[1];
      const livePub = me.coverage.lanes.filter((l) => l.status === 'published' && vendorOf(l.name));
      const checked = esc(String(me.coverage.checked_at).slice(0, 10));
      for (const tr of document.querySelectorAll('tr')) {
        const cell = tr.lastElementChild;
        if (!cell || !cell.querySelector('.bad') || cell.querySelector('.live-fix')) continue;
        const label = [...tr.children].slice(0, 2).filter((td) => td.tagName === 'TD').map((td) => td.textContent).join(' ');
        const hits = livePub.filter((l) => new RegExp(`\\b${vendorOf(l.name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(label));
        if (!hits.length) continue;
        const seen = new Set();
        const parts = hits.filter((l) => !seen.has(l.name.split(' · ')[0] + l.detail) && seen.add(l.name.split(' · ')[0] + l.detail)).slice(0, 3)
          .map((l) => `<b>${esc(vendorOf(l.name))}</b>: ${l.url ? `<a href="${esc(l.url)}">${esc(l.detail.slice(0, 160))}</a>` : esc(l.detail.slice(0, 160))}`);
        cell.querySelector('.bad').style.textDecoration = 'line-through';
        cell.insertAdjacentHTML('beforeend', ` <span class="live-fix"><span class="ok">Published since</span> <span class="src">(live check ${checked}) — ${parts.join(' · ')}</span></span>`);
      }
    }

    const ex = me.coverage && me.coverage.exposure;
    if (ex && ((ex.items && ex.items.length) || ex.note)) {
      const rows = (ex.items || []).map((i) => `<tr><td>${esc(i.engine)}</td><td><pre style="margin:0">${esc(i.query)}</pre></td><td class="src">${i.url ? `<a href="${esc(i.url)}">open</a> · ` : ''}${esc(i.note)}</td></tr>`).join('');
      const html = `<h2 id="exposure-live">Exposure queries — generated automatically</h2>`
        + (rows ? `<table><tr><th>Engine</th><th>Query</th><th>Reads</th></tr>${rows}</table>` : '')
        + (ex.note ? `<p class="src">${esc(ex.note)}</p>` : '')
        + `<p class="src">Scope every query in your own tool, never in a shared document: Shodan <code>net:&lt;your_ranges&gt;</code>, <code>org:"&lt;your_org&gt;"</code> or <code>hostname:&lt;your_domain&gt;</code> (or a Shodan Monitor network alert, which applies the scope for you); Censys <code>host.ip</code> or <code>host.dns.names</code>. Then compare the banner version with the affected range. Built ${esc(String(ex.built_at).slice(0, 16).replace('T', ' '))}Z from the CVE ids and NVD's CPE configurations; re-built daily with the coverage check.</p>`;
      const live = document.getElementById('coverage-live');
      let anchor = live; if (live) { let el = live.nextElementSibling; while (el && el.tagName !== 'TABLE' && el.tagName !== 'H2') el = el.nextElementSibling; if (el && el.tagName === 'TABLE') anchor = el; }
      if (anchor) anchor.insertAdjacentHTML('afterend', html); else document.body.insertAdjacentHTML('beforeend', html);
    }

    const listed = Object.entries(me.kev || {});
    if (!listed.length) return;
    for (const tag of document.querySelectorAll('.card .lane .tag')) {
      if (/^not in kev$/i.test(tag.textContent.trim())) { tag.textContent = 'In KEV (live)'; tag.removeAttribute('style'); tag.title = 'corrected from the live CISA KEV catalog'; }
    }
    const text = listed.map(([cve, k]) => `${cve} listed ${k.date_added}${k.due_date ? ', federal due ' + k.due_date : ''}`).join('; ');
    const live = `<span class="src">(live from the CISA KEV catalog)</span>`;
    const row = [...document.querySelectorAll('tr')].find((tr) => tr.firstElementChild && tr.firstElementChild.tagName === 'TD' && tr.firstElementChild.textContent.trim() === 'KEV');
    if (row && row.children.length >= 3) {
      const cell = row.lastElementChild;
      if (cell.querySelector('.bad')) cell.innerHTML = `<span class="ok">Listed</span> — ${esc(text)} ${live}`; // the static text is stale: replace it
      else cell.insertAdjacentHTML('beforeend', ` <span class="src">· ${esc(text)}</span> ${live}`);     // already says listed: confirm it live
    } else {
      const el = document.createElement('p');
      el.id = 'kev-live';
      el.className = 'src';
      el.innerHTML = `<b>CISA KEV:</b> ${esc(text)} ${live}`;
      const lane = document.querySelector('.card .lane');
      if (lane && lane.parentNode) lane.parentNode.insertBefore(el, lane.nextSibling); else document.body.insertBefore(el, document.body.firstChild);
    }
  } catch { /* banner and KEV row are best-effort */ }
})();
