// Card subscriptions: an address signs up on the site, confirms by link, and gets one mail per new
// verdict card (AI-published by lib/hype.js, or hand-written and announced when it first appears in
// the manifest), each with an unsubscribe link and List-Unsubscribe headers. The address is stored
// in the subscribers table (migration 0006) for this and nothing else: it is never rendered on a
// page, never written to a log line, never sent anywhere but the mail sender. No model is involved.

import { randomBytes } from 'node:crypto';
import { sendMail } from './email.js';
import { activeCards } from './cards.js';

const SITE = () => process.env.PUBLIC_BASE_URL || 'https://cutsign.vercel.app';
const DAY = 86_400_000;
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const MAX_REQUESTS_PER_HOUR = 30;     // sign-up requests, site-wide: a flood of addresses is a bot, not readers
export const ANNOUNCE_WINDOW_DAYS = 3;       // a hand-written card older than this when first seen is marked, not mailed
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const TOKEN_RE = /^[a-f0-9]{48}$/;

export const normalizeEmail = (s) => String(s || '').trim().toLowerCase().slice(0, 254);
export const validEmail = (s) => EMAIL_RE.test(normalizeEmail(s));
export const validToken = (s) => TOKEN_RE.test(String(s || ''));
const newToken = () => randomBytes(24).toString('hex');

/** The two links a token opens. */
export const links = (token, site = SITE()) => ({ confirm: `${site}/api/subscribe?confirm=${token}`, unsubscribe: `${site}/api/subscribe?unsub=${token}` });
const unsubHeaders = (l) => ({ 'List-Unsubscribe': `<${l.unsubscribe}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' });
const footer = (l) => ({
  html: `<p style="color:#777;font-size:12px">You asked for one email per new Cutsign verdict card. <a href="${esc(l.unsubscribe)}">Unsubscribe</a> any time. Public OSINT only; nothing here is reviewed by a person before it is sent.</p>`,
  text: `\n\nYou asked for one email per new Cutsign verdict card. Unsubscribe: ${l.unsubscribe}\nPublic OSINT only.`,
});

/**
 * A sign-up request from the site. Returns { status }: 'pending' (confirmation mail sent),
 * 'confirmed' (already subscribed; a reminder with the unsubscribe link is sent instead),
 * 'invalid', 'bot' (honeypot filled) or 'capped'. The page shown for bot/capped is the pending one.
 */
export async function subscribe(store, { email, honeypot = '', now = Date.now(), site = SITE() } = {}) {
  if (honeypot) return { status: 'bot' };
  const addr = normalizeEmail(email);
  if (!validEmail(addr)) return { status: 'invalid' };
  const at = new Date(now).toISOString();
  const existing = await store.getSubscriberByEmail(addr);
  if (existing?.status === 'confirmed') {
    const l = links(existing.token, site);
    const f = footer(l);
    await sendMail({ to: addr, subject: 'Cutsign: you are already subscribed to new verdict cards', headers: unsubHeaders(l),
      html: `<p>This address is already subscribed to Cutsign verdict cards, so nothing changed.</p>${f.html}`, text: `This address is already subscribed to Cutsign verdict cards, so nothing changed.${f.text}` });
    return { status: 'confirmed' };
  }
  if (!existing && (await store.countSubscribersSince(new Date(now - 3600_000).toISOString())) >= MAX_REQUESTS_PER_HOUR) return { status: 'capped' };
  const token = newToken();
  if (existing) await store.updateSubscriber(existing.id, { token, status: 'pending', requested_at: at });
  else await store.insertSubscriber({ email: addr, token, status: 'pending', requested_at: at });
  const l = links(token, site);
  await sendMail({ to: addr, subject: 'Cutsign: confirm your verdict-card subscription',
    html: `<p>Someone, we hope you, asked for an email each time Cutsign publishes a new verdict card.</p><p><a href="${esc(l.confirm)}">Confirm the subscription</a></p><p style="color:#777;font-size:12px">If that was not you, ignore this message: nothing is sent without this confirmation. Cards: <a href="${esc(site)}/?view=cards">${esc(site)}/?view=cards</a></p>`,
    text: `Someone, we hope you, asked for an email each time Cutsign publishes a new verdict card.\n\nConfirm: ${l.confirm}\n\nIf that was not you, ignore this message: nothing is sent without this confirmation.` });
  return { status: 'pending' };
}

/** A confirmation link. Returns 'confirmed' (now or already) or null when the token is unknown or spent. */
export async function confirm(store, token, { now = Date.now() } = {}) {
  if (!validToken(token)) return null;
  const row = await store.getSubscriberByToken(token);
  if (!row || row.status === 'unsubscribed') return null;
  if (row.status !== 'confirmed') await store.updateSubscriber(row.id, { status: 'confirmed', confirmed_at: new Date(now).toISOString() });
  return 'confirmed';
}

/** An unsubscribe link (GET from the mail, or the one-click POST). Returns true when a row was turned off. */
export async function unsubscribe(store, token, { now = Date.now() } = {}) {
  if (!validToken(token)) return false;
  const row = await store.getSubscriberByToken(token);
  if (!row) return false;
  if (row.status !== 'unsubscribed') await store.updateSubscriber(row.id, { status: 'unsubscribed', unsubscribed_at: new Date(now).toISOString() });
  return true;
}

/**
 * One mail per confirmed subscriber about a card that just went live. Never throws; a failed send
 * is counted, not retried (the card is on the site either way). Returns the number sent.
 */
export async function notifyCardPublished(store, { title, url, summary = '', lane = '', priority = '', kind = 'ai', site = SITE() } = {}) {
  let subs = [];
  try { subs = await store.listSubscribers({ status: 'confirmed' }); } catch { return 0; } // table missing: nobody to tell
  if (!subs.length) return 0;
  const chips = [lane, priority].filter(Boolean).join(' · ');
  const made = kind === 'ai' ? 'AI-generated and published automatically by the pipeline, not reviewed by a person; re-issued in place as the evidence changes.' : 'Hand-written one-page verdict.';
  let sent = 0;
  for (const s of subs) {
    const l = links(s.token, site);
    const f = footer(l);
    try {
      await sendMail({ to: s.email, subject: `Cutsign ▣ new verdict card: ${title}`, headers: unsubHeaders(l),
        html: `<p><b><a href="${esc(url)}">${esc(title)}</a></b>${chips ? ` <span style="color:#777">· ${esc(chips)}</span>` : ''}</p>${summary ? `<p>${esc(summary)}</p>` : ''}<p style="color:#777;font-size:12px">${esc(made)}</p>${f.html}`,
        text: `${title}${chips ? ` · ${chips}` : ''}\n${url}\n\n${summary}\n\n${made}${f.text}` });
      sent++;
    } catch { /* one address failing never blocks the rest */ }
  }
  return sent;
}

/**
 * Hand-written cards are published by a commit, so the pipeline notices them here: every active
 * manifest card not yet announced is mailed once (when its as-of date is recent; an older card
 * first seen is marked without mail), and the mark is written on the card's story row, the same
 * row that carries its coverage check. Runs with the coverage sweep. Returns the number of mails.
 */
export async function announceHandCards(store, { now = Date.now(), site = SITE() } = {}) {
  const cards = activeCards();
  let rows = [];
  try { rows = await store.getStories(cards.flatMap((c) => c.story_ids)); } catch { return 0; }
  let sent = 0;
  for (const card of cards) {
    const mine = rows.filter((r) => card.story_ids.includes(r.id));
    if (!mine.length || mine.some((r) => r.raw_iocs?.hype?.card_announced)) continue;
    const holder = mine.find((r) => r.raw_iocs?.hype?.card_coverage) || mine.find((r) => r.id === card.story_ids.at(-1)) || mine[0];
    const fresh = now - Date.parse(card.date) < ANNOUNCE_WINDOW_DAYS * DAY;
    const n = fresh ? await notifyCardPublished(store, { title: card.title, url: `${site}${card.url}`, summary: card.summary, lane: card.lane, kind: 'hand', site }) : 0;
    try { await store.updateStory(holder.id, { raw_iocs: { ...(holder.raw_iocs || {}), hype: { ...(holder.raw_iocs?.hype || {}), card_announced: { at: new Date(now).toISOString(), notified: n, fresh } } } }); } catch { /* re-tried next sweep */ }
    sent += n;
  }
  return sent;
}

/** The sign-up form, for the cards index and every card page. The second field is a honeypot. */
export function subscribeForm() {
  return `<form class="sub" method="post" action="/api/subscribe"><label for="sub-e"><b>Email me each new verdict card</b></label>`
    + `<div><input id="sub-e" type="email" name="email" required maxlength="254" placeholder="you@example.test" autocomplete="email">`
    + `<input type="text" name="website" tabindex="-1" autocomplete="off" aria-hidden="true" class="hp"><button type="submit">Subscribe</button></div>`
    + `<span class="s">One mail per new card, after you confirm by link; an unsubscribe link in every mail. The address is used for nothing else.</span></form>`;
}

/** The page /api/subscribe answers with, by outcome. Never echoes the address. */
export function resultPage(kind) {
  const text = {
    pending: ['Check your inbox', 'A confirmation link is on its way. Nothing is sent until you open it.'],
    bot: ['Check your inbox', 'A confirmation link is on its way. Nothing is sent until you open it.'],
    capped: ['Check your inbox', 'A confirmation link is on its way. Nothing is sent until you open it.'],
    confirmed: ['Subscribed', 'You will get one email each time a new verdict card is published. Every mail carries an unsubscribe link.'],
    invalid: ['That does not look like an email address', 'Go back and check the spelling.'],
    unsubscribed: ['Unsubscribed', 'No more card mail to this address. Sign up again from the cards page any time.'],
    unknown: ['This link is not valid any more', 'It was already used, or a newer request replaced it. Sign up again from the cards page if you want the mail.'],
    unavailable: ['Subscriptions are not available yet', 'The site is not set up for them at the moment. Try again later.'],
  }[kind] || ['Something went wrong', 'Try again from the cards page.'];
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Cutsign — ${esc(text[0])}</title>`
    + `<style>body{margin:0;background:#0f1115;color:#e6e8ee;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}main{max-width:560px;margin:14vh auto 0;padding:0 20px}h1{font-size:22px;margin:0 0 10px}p{color:#a9afbd}a{color:#8ab4ff}.brand{font-weight:800;letter-spacing:.08em;font-size:12px;color:#a9afbd}</style></head>`
    + `<body><main><div class="brand">CUTSIGN</div><h1>${esc(text[0])}</h1><p>${esc(text[1])}</p><p><a href="/?view=cards">Verdict cards</a> · <a href="/">Cutsign</a></p></main></body></html>`;
}
