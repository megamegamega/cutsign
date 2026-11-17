// Outbound mail via Resend (EMAIL_FROM must be on a domain verified in Resend).
// The operator's mail (the daily read, alerts, card notices) goes to one recipient, EMAIL_TO, through
// sendDigest. Subscriptions (lib/subscribe.js) send one message per confirmed address through sendMail,
// with List-Unsubscribe headers: a copy of the daily read, and card mail.

import { Resend } from 'resend';

let _resend;
function resend() {
  if (_resend) return _resend;
  const key = process.env.EMAIL_API_KEY;
  if (!key) throw new Error('EMAIL_API_KEY not set');
  _resend = new Resend(key);
  return _resend;
}

const need = (k) => { const v = process.env[k]; if (!v) throw new Error(`${k} is not set`); return v; };
const FROM = () => need('EMAIL_FROM');       // a sender on the Resend-verified domain, e.g. "Cutsign <cutsign@example.test>"
const TO = () => need('EMAIL_TO');
const REPLY_TO = () => process.env.EMAIL_REPLY_TO || TO();

// Tests swap this to capture mail instead of sending.
let sink = null;
export function _setEmailSink(fn) { sink = fn; }

// Resend limits requests per second; a run of messages (one per subscriber) is spaced out, not burst.
export const SEND_GAP_MS = 600;
let lastSendAt = 0;
async function deliver(msg) {
  if (sink) { sink(msg); return { id: 'test' }; }
  const wait = lastSendAt + SEND_GAP_MS - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastSendAt = Date.now();
  // Resend's SDK resolves with { data, error } instead of throwing — surface failures.
  const { data, error } = await resend().emails.send(msg);
  if (error) throw new Error('resend: ' + (error.message || JSON.stringify(error)));
  return data;
}

/** Send the daily read to the operator. Throws on failure (the send stage turns that into a ✖ + retry). */
export async function sendDigest({ subject, html, text }) {
  return deliver({ from: FROM(), to: TO(), replyTo: REPLY_TO(), subject, html, text });
}

/** One message to one address (subscriptions). Same sender; `headers` carries List-Unsubscribe,
 *  `attachments` the card's PDF ([{ filename, content }]). Throws on failure. */
export async function sendMail({ to, subject, html, text, headers = null, attachments = null }) {
  return deliver({ from: FROM(), to, replyTo: REPLY_TO(), subject, html, text, ...(headers ? { headers } : {}), ...(attachments?.length ? { attachments } : {}) });
}
