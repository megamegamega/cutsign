// Card lifecycle banner: every card page loads this; it reads the manifest and, when this card
// is archived or superseded, says so at the top so a shared link never reads as current advice.
(async function () {
  try {
    const slug = (location.pathname.match(/\/cards\/([a-z0-9-]+)\.html$/) || [])[1];
    if (!slug) return;
    const r = await fetch('/?view=cards&format=json', { cache: 'no-store' });
    if (!r.ok) return;
    const me = ((await r.json()).cards || []).find((c) => c.slug === slug);
    if (!me || me.status === 'active') return;
    const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
    const el = document.createElement('div');
    el.id = 'lifecycle';
    el.setAttribute('style', 'margin:0 0 16px;padding:12px 16px;border:1px solid #b58a2a;border-radius:8px;background:rgba(181,138,42,.12);font:600 14px/1.4 system-ui,sans-serif');
    el.innerHTML = `${esc(me.status === 'superseded' ? 'Superseded' : 'Archived')} — no longer tracked${me.archived_on ? ' as of ' + esc(me.archived_on) : ''}. The verdict below is historical.`
      + (me.superseded_by ? ` Current card: <a href="/cards/${esc(me.superseded_by)}.html">${esc(me.superseded_by)}</a>.` : '')
      + ' <a href="/?view=cards">All cards</a>';
    document.body.insertBefore(el, document.body.firstChild);
  } catch { /* banner is best-effort */ }
})();
