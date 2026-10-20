// Signed, stateless tokens (ported from Daybreak): HMAC-SHA256 over the payload — v1 seam for pack/feedback links
// with TOKEN_SECRET. No DB lookup needed to validate; tokens carry {id, purpose, exp}.

import { createHmac, timingSafeEqual } from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function secret() {
  const s = process.env.TOKEN_SECRET;
  if (!s) throw new Error('TOKEN_SECRET not set');
  return s;
}

/** Create a signed token. purpose ∈ {'confirm','unsubscribe'}. */
export function signToken(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/** Verify a token; returns the payload or null if invalid/tampered. */
export function verifyToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = createHmac('sha256', secret()).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}
