// Card subscriptions (lib/subscribe.js). Public, unauthenticated by design:
//   POST /api/subscribe            form fields email (+ honeypot "website")  → confirmation mail
//   GET  /api/subscribe?confirm=T  the link in that mail                     → subscribed
//   GET|POST /api/subscribe?unsub=T  the link in every card mail, or the one-click List-Unsubscribe POST
// Answers are small HTML pages that never echo the address.

import { supabaseStore } from '../lib/db.js';
import { subscribe, confirm, unsubscribe, resultPage, validToken } from '../lib/subscribe.js';

const MAX_BYTES = 10_000;

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) return req.body; // the platform parsed it already
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > MAX_BYTES) throw new Error('body too large'); chunks.push(c); }
  return Buffer.concat(chunks).toString('utf8');
}
function fields(body, type = '') {
  if (body && typeof body === 'object') return body;
  const s = String(body || '');
  if (/json/i.test(type)) { try { return JSON.parse(s) || {}; } catch { return {}; } }
  return Object.fromEntries(new URLSearchParams(s));
}
const page = (res, status, html) => { res.statusCode = status; res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(html); };

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  const url = new URL(req.url, 'http://x');
  const unsub = url.searchParams.get('unsub');
  const conf = url.searchParams.get('confirm');
  try {
    const store = supabaseStore();
    if (unsub !== null) return page(res, 200, resultPage(validToken(unsub) && await unsubscribe(store, unsub) ? 'unsubscribed' : 'unknown'));
    if (conf !== null) return page(res, 200, resultPage(validToken(conf) && await confirm(store, conf) ? 'confirmed' : 'unknown'));
    if (req.method !== 'POST') { res.statusCode = 302; res.setHeader('Location', '/?view=cards'); return res.end(''); }
    const f = fields(await readBody(req), req.headers['content-type'] || '');
    const r = await subscribe(store, { email: f.email, honeypot: f.website });
    return page(res, r.status === 'invalid' ? 400 : 200, resultPage(r.status));
  } catch (e) {
    const m = String(e?.message || e);
    if (/subscribers/.test(m) && /does not exist|could not find|schema cache/i.test(m)) return page(res, 503, resultPage('unavailable'));
    return page(res, 500, resultPage('error'));
  }
}
