// Outbound mail via Resend (same verified domain as Daybreak: mail.liberto.us).
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

const FROM = () => process.env.EMAIL_FROM || 'Cutsign <cutsign@mail.liberto.us>';
const TO = () => process.env.EMAIL_TO || 'marcus@liberto.us';
const REPLY_TO = () => process.env.EMAIL_REPLY_TO || 'dispatch@liberto.us';

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
