// Inbound via Resend Receiving: the brief is delivered (Gmail filter-forward, or the sender adds the
// address) to BRIEF_INBOUND_ADDRESS, Resend stores it, and the cron polls Resend's API for it.
// No webhook, so nothing is lost if a run fails — Resend keeps the mail.
//   GET /emails/receiving          list (newest first)
//   GET /emails/receiving/{id}     one email: message_id, authentication, raw.download_url (signed)
// Uses the same EMAIL_API_KEY as sending (needs full access).

const API = 'https://api.resend.com/emails/receiving';
const LOOKBACK_MS = 3 * 86400000;

async function api(path = '') {
  const key = process.env.EMAIL_API_KEY;
  if (!key) throw new Error('EMAIL_API_KEY not set');
  const r = await fetch(API + path, { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`resend receiving ${path || 'list'}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

const addrs = (v) => (Array.isArray(v) ? v : [v]).filter(Boolean).map((a) => String(a).toLowerCase().match(/[^<\s]+@[^>\s]+/)?.[0]).filter(Boolean);

/**
 * True only if the message's DKIM check passed. Resend reports SPF/DKIM/DMARC per received email; the
 * exact shape is matched loosely (string or object) so a format change fails closed with a visible reason.
 */
export function dkimPassed(auth) {
  if (!auth) return false;
  const d = auth.dkim ?? auth.DKIM;
  const vals = Array.isArray(d) ? d : [d];
  return vals.some((v) => /\bpass\b/i.test(typeof v === 'string' ? v : JSON.stringify(v ?? '')));
}

/** Same shape as gmail.listBriefMessages: [{ messageId, receivedAt, auth, getRaw() }] */
export async function listBriefMessages() {
  const inbound = (process.env.BRIEF_INBOUND_ADDRESS || '').trim().toLowerCase();
  if (!inbound) throw new Error('BRIEF_INBOUND_ADDRESS not set');
  const list = await api('?limit=50');
  const out = [];
  for (const m of list.data || []) {
    if (Date.now() - new Date(m.created_at) > LOOKBACK_MS) continue;
    // Forwarded copies keep the brief's original To: header, so filter on the envelope recipient
    // (received_for) when Resend gives it; otherwise everything on our receiving domain is ours.
    const envelope = addrs(m.received_for);
    if (envelope.length && !envelope.includes(inbound)) continue;
    out.push({
      resendId: m.id,
      messageId: (m.message_id || `<resend-${m.id}>`).trim(),
      receivedAt: m.created_at,
      async getRaw() {
        const full = await api(`/${m.id}`);
        this.auth = full.authentication || null;
        const url = full.raw?.download_url;
        if (!url) throw new Error(`resend receiving ${m.id}: no raw download_url`);
        const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!r.ok) throw new Error(`resend raw download ${m.id}: ${r.status}`);
        return r.text();
      },
    });
  }
  return out;
}
