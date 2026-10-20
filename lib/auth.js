// Bearer-secret check shared by the cron and the internal chain endpoint. Vercel cron sends
// `Authorization: Bearer $CRON_SECRET`; the self-chain reuses the same secret.

import { timingSafeEqual } from 'node:crypto';

export function authorized(req) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  const a = Buffer.from(req.headers.authorization || '');
  const b = Buffer.from(`Bearer ${secret}`);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function baseUrl() {
  const u = process.env.PUBLIC_BASE_URL
    || (process.env.VERCEL_PROJECT_PRODUCTION_URL && `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`)
    || (process.env.VERCEL_URL && `https://${process.env.VERCEL_URL}`);
  return (u || 'http://localhost:3000').replace(/\/$/, '');
}

/** Start another invocation of /api/advance (which returns 202 at once and works in the background). */
export async function kickAdvance() {
  try {
    const r = await fetch(`${baseUrl()}/api/advance`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` },
      signal: AbortSignal.timeout(10000),
    });
    return r.status === 202;
  } catch (e) {
    console.error('kickAdvance failed:', e?.message);
    return false;
  }
}
