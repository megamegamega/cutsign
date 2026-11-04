// A verdict card as a PDF: GET /cards/<slug>.pdf (vercel.json rewrites it to /api/pdf?slug=…).
// Hand-written cards (lib/cards.js) and published AI cards; anything else is a 404, answered before
// Chromium starts (lib/pdfrender.js). The edge caches the file, so a card is rendered about once per
// cache window.

import { CARDS } from '../lib/cards.js';
import { validSlug } from '../lib/pdf.js';
import { renderPdf } from '../lib/pdfrender.js';

export const config = { maxDuration: 60 };
const SITE = () => process.env.PUBLIC_BASE_URL || 'https://cutsign.vercel.app';

export default async function handler(req, res, { fetchImpl = fetch } = {}) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  const fail = (code, text) => { res.statusCode = code; res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'text/plain; charset=utf-8'); return res.end(text); };
  const slug = String(req.query?.slug || '').toLowerCase();
  if (!validSlug(slug)) return fail(404, 'No such card.');
  // one cache key per card: any other query (a cache-buster) is sent to the plain URL
  if (Object.keys(req.query || {}).some((k) => k !== 'slug')) { res.statusCode = 308; res.setHeader('Location', `/cards/${slug}.pdf`); return res.end(); }
  const hand = CARDS.find((c) => c.slug === slug);
  const page = `${SITE()}${hand ? hand.url : `/cards/${slug}`}`;
  // an AI card exists when its page does: asked with a plain fetch first, so an unknown slug never starts Chromium
  if (!hand) {
    let status = 0;
    try { status = (await fetchImpl(page, { signal: AbortSignal.timeout(10_000) })).status; } catch { status = 0; }
    if (status === 404) return fail(404, 'No such card.');
    if (status !== 200) return fail(502, 'The card page did not answer; try again shortly.');
  }
  let pdf;
  try { pdf = await renderPdf(page); } catch (e) {
    console.error('card pdf render failed:', slug, String(e?.message || e).slice(0, 300));
    return fail(502, 'The PDF could not be rendered; the card itself is at ' + page);
  }
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="cutsign-${slug}.pdf"`);
  res.setHeader('Cache-Control', 'public, s-maxage=600, stale-while-revalidate=3600');
  return res.end(pdf);
}
