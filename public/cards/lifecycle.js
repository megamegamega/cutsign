// Card lifecycle banner and live KEV status: every card page loads this. It reads the manifest
// and (1) when this card is archived or superseded, says so at the top so a shared link never
// reads as current advice; (2) when CISA KEV lists a CVE the card names, corrects the card's KEV
// row from the live catalog, so a card written before the listing never keeps saying "not listed".
(async function () {
  try {
    const slug = (location.pathname.match(/\/cards\/([a-z0-9-]+)\.html$/) || [])[1];
    if (!slug) return;
    const r = await fetch('/?view=cards&format=json', { cache: 'no-store' });
    if (!r.ok) return;
    const me = ((await r.json()).cards || []).find((c) => c.slug === slug);
    if (!me) return;
    const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));

    if (me.status !== 'active') {
      const el = document.createElement('div');
      el.id = 'lifecycle';
      el.setAttribute('style', 'margin:0 0 16px;padding:12px 16px;border:1px solid #b58a2a;border-radius:8px;background:rgba(181,138,42,.12);font:600 14px/1.4 system-ui,sans-serif');
      el.innerHTML = `${esc(me.status === 'superseded' ? 'Superseded' : 'Archived')} — no longer tracked${me.archived_on ? ' as of ' + esc(me.archived_on) : ''}. The verdict below is historical.`
        + (me.superseded_by ? ` Current card: <a href="/cards/${esc(me.superseded_by)}.html">${esc(me.superseded_by)}</a>.` : '')
        + ' <a href="/?view=cards">All cards</a>';
      document.body.insertBefore(el, document.body.firstChild);
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
