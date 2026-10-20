// The "received" stage: poll Gmail, dedupe on Message-ID BEFORE anything expensive, apply the sender
// allowlist, and create a run for each new accepted brief. No LLM call can happen before this check.

import { listBriefMessages } from './gmail.js';
import { parseMime, briefDateFromSubject, isTestBrief } from './parse-brief.js';
import { postDiscord } from './discord.js';

export const DEFAULT_ALLOWLIST = 'brief@example.test,briefs@example.test';

const allowlist = () => (process.env.BRIEF_SENDER_ALLOWLIST || DEFAULT_ALLOWLIST)
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

/**
 * @param store
 * @param {{dry?: boolean, messages?: Array}} opts  `messages` overrides Gmail (tests, local runs):
 *        [{ messageId, receivedAt, getRaw }]
 * @returns counts { seen, new, accepted, rejected, ignored }
 */
export async function intake(store, { dry = false, messages } = {}) {
  const list = messages || await listBriefMessages();
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
