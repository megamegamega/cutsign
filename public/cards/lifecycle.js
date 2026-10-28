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

    if (me.reissue && me.reissue.url) {
      banner('reissue', `Developments after this card's as-of date (${esc(me.date)}): the pipeline wrote an <a href="${esc(me.reissue.url)}">AI re-issue draft (v${esc(me.reissue.version)}, ${esc(String(me.reissue.created_at).slice(0, 10))})</a> that folds them in. AI-generated and unreviewed; the card below is the human-written verdict as of its date.`);
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
