// The "received" stage: poll the inbound source (Resend Receiving by default, or Gmail), dedupe on Message-ID BEFORE anything expensive, apply the sender
// allowlist, and create a run for each new accepted brief. No LLM call can happen before this check.

import * as gmail from './gmail.js';
import * as resend from './inbound-resend.js';
import { parseMime, briefDateFromSubject, isTestBrief } from './parse-brief.js';
import { postDiscord } from './discord.js';

// No built-in senders: BRIEF_SENDER_ALLOWLIST must name the brief's sender(s) or every message is rejected.
export const DEFAULT_ALLOWLIST = '';

const allowlist = () => (process.env.BRIEF_SENDER_ALLOWLIST || DEFAULT_ALLOWLIST)
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

/**
 * @param store
 * @param {{dry?: boolean, messages?: Array}} opts  `messages` overrides Gmail (tests, local runs):
 *        [{ messageId, receivedAt, getRaw }]
 * @returns counts { seen, new, accepted, rejected, ignored }
 */
export async function intake(store, { dry = false, messages } = {}) {
  const source = (process.env.INBOUND_SOURCE || 'resend') === 'gmail' ? gmail : resend;
  const list = messages || await source.listBriefMessages();
  const c = { seen: list.length, new: 0, accepted: 0, rejected: 0, ignored: 0 };
  for (const m of list) {
    if (m.messageId && await store.briefExists(m.messageId)) continue; // re-delivery → no-op
    const raw = await m.getRaw();
    const mime = await parseMime(raw);
    const messageId = m.messageId || mime.messageId;
    if (!messageId || await store.briefExists(messageId)) continue;
    c.new++;
    const base = {
      message_id: messageId, gmail_id: m.gmailId || null, received_at: m.receivedAt || mime.date || new Date().toISOString(),
      from_addr: mime.from, subject: mime.subject, brief_date: briefDateFromSubject(mime.subject),
    };
    // Mail that reached us through Resend must carry a passing DKIM signature: the From: allowlist alone
    // is spoofable on a public inbound address. (Gmail-polled and hand-POSTed briefs are trusted paths.)
    if (m.resendId && !resend.dkimPassed(m.auth)) {
      await store.insertBrief({ ...base, status: 'rejected', status_reason: 'DKIM did not pass' });
      await postDiscord(`Cutsign ⚠ rejected inbound mail from ${mime.from || '(none)'} — DKIM did not pass (auth: ${JSON.stringify(m.auth).slice(0, 300)}) — subject “${mime.subject.slice(0, 120)}”`);
      c.rejected++; continue;
    }
    if (!allowlist().includes(mime.from)) {
      // stored (without the body) so it's never re-processed; nothing else happens
      await store.insertBrief({ ...base, status: 'rejected', status_reason: 'sender not on allowlist' });
      await postDiscord(`Cutsign ⚠ rejected a brief-looking message from non-allowlisted sender ${mime.from || '(none)'} — subject “${mime.subject.slice(0, 120)}”`);
      c.rejected++; continue;
    }
    if (isTestBrief(mime.subject)) {
      await store.insertBrief({ ...base, status: 'ignored', status_reason: 'test send' });
      c.ignored++; continue;
    }
    // An allowlisted sender also writes ordinary mail (a note about the brief, a reply). Only a
    // dated brief subject starts a run; anything else is stored as ignored and never retried.
    if (!base.brief_date) {
      await store.insertBrief({ ...base, status: 'ignored', status_reason: 'not a brief (no date in the subject)' });
      await postDiscord(`Cutsign · ignored mail from ${mime.from} that is not a brief — subject “${mime.subject.slice(0, 120)}”`);
      c.ignored++; continue;
    }
    if (base.brief_date && await store.acceptedBriefForDate(base.brief_date)) {
      await store.insertBrief({ ...base, status: 'ignored', status_reason: `already processed a brief for ${base.brief_date}` });
      c.ignored++; continue;
    }
    const brief = await store.insertBrief({ ...base, status: 'accepted', raw_mime: raw });
    if (!brief) continue; // lost a race with a concurrent poll — theirs wins
    await store.insertRun({ brief_id: brief.id, dry });
    c.accepted++;
  }
  return c;
}
