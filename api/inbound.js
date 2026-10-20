// Manual intake: POST a raw brief (RFC 822 / .eml) and run it through the same path as the Gmail poll —
// Message-ID dedupe, sender allowlist, then the stages. For re-feeding a brief or testing without Gmail.
//   curl -X POST -H "Authorization: Bearer $CRON_SECRET" --data-binary @brief.eml https://…/api/inbound[?dry=1]

import { waitUntil } from '@vercel/functions';
import { supabaseStore } from '../lib/db.js';
import { intake } from '../lib/intake.js';
import { driveRuns } from '../lib/pipeline.js';
import { authorized, kickAdvance } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';

export const config = { maxDuration: 300 };
const MAX_BYTES = 2_000_000;
const BUDGET_MS = 270_000;

async function readBody(req) {
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > MAX_BYTES) throw new Error('body too large'); chunks.push(c); }
  return Buffer.concat(chunks).toString('utf8');
}

export default async function handler(req, res) {
  if (req.method !== 'POST' || !authorized(req)) { res.statusCode = 401; return res.json({ ok: false }); }
  const dry = new URL(req.url, 'http://x').searchParams.get('dry') === '1';
  let raw;
  try { raw = await readBody(req); } catch (e) { res.statusCode = 413; return res.json({ ok: false, error: e.message }); }
  if (!/^message-id:/im.test(raw)) { res.statusCode = 400; return res.json({ ok: false, error: 'not an RFC 822 message (no Message-ID header)' }); }
  const store = supabaseStore();
  const received = await intake(store, { dry, messages: [{ getRaw: async () => raw }] });
  const deadline = Date.now() + BUDGET_MS;
  waitUntil((async () => {
    try { if (await driveRuns(store, { deadline })) await kickAdvance(); }
    catch (e) { await postDiscord(`Cutsign ✖ inbound error=${String(e?.message || e).slice(0, 300)}`); }
  })());
  res.statusCode = 202;
  return res.json({ ok: true, received });
}
