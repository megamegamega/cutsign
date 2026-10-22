// Public, read-only web view of recent briefs. "/" (rewritten here in vercel.json) renders
// the latest sent run with the same buildDigestData + renderDigest the email uses, plus a
// day picker (last 14 sent runs, ?d=YYYY-MM-DD) and the last 48 h of watch events whether
// or not they were already emailed. Content is public-OSINT-only by construction (the one
// rule), so the page is public; noindex like every other endpoint.

import { supabaseStore } from '../lib/db.js';
import { buildDigestData, renderDigest } from '../lib/render.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const shell = (body) => `<!doctype html><html><head><meta charset="utf-8">`
  + `<meta name="viewport" content="width=device-width,initial-scale=1"><title>Cutsign</title></head>`
  + `<body style="font:15px/1.5 system-ui;max-width:720px;margin:40px auto;padding:0 16px"><h2>Cutsign</h2>${body}</body></html>`;

export default async function handler(req, res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=600');
  try {
    const store = supabaseStore();
    const runs = (await store.listRecentSentRuns(14)).reverse(); // newest first
    if (!runs.length) return res.status(200).send(shell('<p>No briefs in the last 14 days.</p>'));
    const briefs = await Promise.all(runs.map((r) => store.getBrief(r.brief_id).catch(() => null)));
    const days = runs.map((r, i) => ({ run: r, date: briefs[i]?.brief_date || String(briefs[i]?.received_at || r.started_at).slice(0, 10) }));
    const want = String(req.query.d || '').slice(0, 10);
    const pick = days.find((x) => x.date === want) || days[0];

    const d = await buildDigestData(store, pick.run);
    try { // web view: recent watch events regardless of digested/notified state
      const cutoff = Date.now() - 48 * 3600 * 1000;
      d.watchEvents = (await store.listWatchEvents({})).filter((e) => new Date(e.created_at).getTime() >= cutoff);
    } catch { /* watches table absent — keep whatever buildDigestData found */ }

    const { html } = renderDigest(d);
    const nav = `<p style="margin:0 0 10px">${days.map((x) => x.date === pick.date
      ? `<b>${esc(x.date)}</b>` : `<a href="/?d=${encodeURIComponent(x.date)}">${esc(x.date)}</a>`).join(' · ')}</p>`;
    return res.status(200).send(html
      .replace('<head>', '<head><title>Cutsign</title><meta name="viewport" content="width=device-width,initial-scale=1">')
      .replace('<div class="w">', `<div class="w">${nav}`));
  } catch (e) {
    return res.status(500).send(shell(`<p>Error rendering page: ${esc(e.message)}</p>`));
  }
}
