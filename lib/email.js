// Outbound mail via Resend (EMAIL_FROM must be on a domain verified in Resend).
// v0 has exactly one recipient (EMAIL_TO). The community share (later) gets its own sender with
// List-Unsubscribe headers; this module stays single-recipient.

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

/** Send the daily read. Throws on failure (the send stage turns that into a ✖ + retry). */
export async function sendDigest({ subject, html, text }) {
  const msg = { from: FROM(), to: TO(), replyTo: REPLY_TO(), subject, html, text };
  if (sink) { sink(msg); return { id: 'test' }; }
  // Resend's SDK resolves with { data, error } instead of throwing — surface failures.
  const { data, error } = await resend().emails.send(msg);
  if (error) throw new Error('resend: ' + (error.message || JSON.stringify(error)));
  return data;
}
