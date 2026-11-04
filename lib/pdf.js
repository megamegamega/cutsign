// Verdict cards as PDF, the mail side: /cards/<slug>.pdf (api/pdf.js, printed by lib/pdfrender.js)
// is fetched by a subscriber mail (lib/subscribe.js) and attached. Nothing here imports Chromium, so the
// functions that send card mail never bundle it; only api/pdf.js does.

export const PDF_MAX_BYTES = 8 * 1024 * 1024;
const SLUG_RE = /^[a-z0-9-]{1,80}$/;

export const validSlug = (s) => SLUG_RE.test(String(s || ''));

/** The card page and PDF URLs for a card URL on this site (hand cards end .html), or null. */
export function cardPdfUrl(cardUrl) {
  const m = String(cardUrl || '').match(/^(https?:\/\/[^/]+)\/cards\/([a-z0-9-]{1,80})(?:\.html)?$/);
  return m ? { url: `${m[1]}/cards/${m[2]}.pdf`, slug: m[2] } : null;
}

/**
 * A card's PDF as a mail attachment ({ filename, content }), fetched from /cards/<slug>.pdf so the
 * render runs in its own function. Null on any failure: the mail then goes out without it.
 */
export async function fetchCardPdf(cardUrl, { fetchImpl = fetch, timeoutMs = 45_000 } = {}) {
  const t = cardPdfUrl(cardUrl);
  if (!t) return null;
  try {
    const r = await fetchImpl(t.url, { signal: AbortSignal.timeout(timeoutMs) });
    if (r.status !== 200 || !/^application\/pdf\b/i.test(r.headers.get('content-type') || '')) return null;
    const content = Buffer.from(await r.arrayBuffer());
    if (content.length > PDF_MAX_BYTES || content.subarray(0, 5).toString('latin1') !== '%PDF-') return null;
    return { filename: `cutsign-${t.slug}.pdf`, content };
  } catch { return null; }
}
