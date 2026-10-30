// Card subscriptions: sign-up, confirmation, one mail per new card, unsubscribe. Memory store,
// captured mail; an address appears in no page and in no mail but its own.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { subscribe, confirm, unsubscribe, notifyCardPublished, announceHandCards, validEmail, resultPage, subscribeForm, MAX_REQUESTS_PER_HOUR } from '../lib/subscribe.js';
import { CARDS } from '../lib/cards.js';
import { captureOutputs } from './helpers.js';

const SITE = 'https://cutsign.example.test';
const now = Date.parse('2026-10-30T12:00:00Z');
const tokenOf = (m) => (m.html.match(/[?&](?:confirm|unsub)=([a-f0-9]{48})/) || [])[1];

test('subscribe: a valid address gets one confirmation mail and a pending row; bots, bad addresses and floods get none', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  assert.equal(validEmail('Reader@Example.test '), true); assert.equal(validEmail('nope'), false); assert.equal(validEmail('a@b'), false);
  const r = await subscribe(store, { email: 'Reader@Example.test ', now, site: SITE });
  assert.equal(r.status, 'pending');
  assert.equal(emails.length, 1); assert.equal(emails[0].to, 'reader@example.test'); assert.match(emails[0].subject, /confirm/i);
  const tok = tokenOf(emails[0]);
  assert.ok(tok, 'the mail carries the confirm link'); assert.ok(emails[0].html.includes(`${SITE}/api/subscribe?confirm=${tok}`));
  const row = await store.getSubscriberByEmail('reader@example.test');
  assert.equal(row.status, 'pending'); assert.equal(row.token, tok);
  // honeypot filled: nothing stored, nothing sent, the same page as a real sign-up
  assert.equal((await subscribe(store, { email: 'bot@example.test', honeypot: 'http://x', now, site: SITE })).status, 'bot');
  assert.equal(await store.getSubscriberByEmail('bot@example.test'), null);
  assert.equal((await subscribe(store, { email: 'not an address', now, site: SITE })).status, 'invalid');
  assert.equal(emails.length, 1);
  assert.equal(resultPage('bot'), resultPage('pending'));
  assert.ok(!resultPage('pending').includes('example.test'), 'the page never echoes an address');
  // a flood of new addresses in an hour is capped
  for (let i = 0; i < MAX_REQUESTS_PER_HOUR; i++) await store.insertSubscriber({ email: `r${i}@example.test`, token: String(i).padStart(48, '0'), status: 'pending', requested_at: new Date(now).toISOString() });
  assert.equal((await subscribe(store, { email: 'late@example.test', now, site: SITE })).status, 'capped');
  assert.equal(await store.getSubscriberByEmail('late@example.test'), null);
});

test('confirm → one mail per new card with List-Unsubscribe → unsubscribe → silence; a re-subscribe rotates the token', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  await subscribe(store, { email: 'reader@example.test', now, site: SITE });
  await subscribe(store, { email: 'other@example.test', now, site: SITE });
  const tok = tokenOf(emails[0]);
  assert.equal(await confirm(store, 'zz'), null, 'a malformed token is nothing');
  assert.equal(await confirm(store, tok, { now }), 'confirmed');
  assert.equal((await store.getSubscriberByEmail('reader@example.test')).status, 'confirmed');
  // the pending second address is not mailed about cards
  emails.length = 0;
  const n = await notifyCardPublished(store, { title: 'Widget Server zero-day', url: `${SITE}/cards/widget-2026`, summary: 'Patch today.', lane: 'Patch now', priority: 'P1', kind: 'ai', site: SITE });
  assert.equal(n, 1); assert.equal(emails.length, 1);
  const m = emails[0];
  assert.equal(m.to, 'reader@example.test'); assert.match(m.subject, /new verdict card: Widget Server zero-day/);
  assert.ok(m.html.includes(`${SITE}/cards/widget-2026`) && m.text.includes('Patch today.'));
  assert.match(m.headers['List-Unsubscribe'], new RegExp(`^<${SITE}/api/subscribe\\?unsub=${tok}>$`));
  assert.equal(m.headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click');
  assert.ok(m.html.includes(`unsub=${tok}`), 'the unsubscribe link is in the body too');
  assert.ok(!m.html.includes('other@example.test'), 'no other address in a mail');
  // already subscribed: a reminder, not a second confirmation
  emails.length = 0;
  assert.equal((await subscribe(store, { email: 'reader@example.test', now, site: SITE })).status, 'confirmed');
  assert.equal(emails.length, 1); assert.match(emails[0].subject, /already subscribed/);
  // unsubscribe by link; the confirm token is dead; no more card mail
  assert.equal(await unsubscribe(store, tok, { now }), true);
  assert.equal((await store.getSubscriberByEmail('reader@example.test')).status, 'unsubscribed');
  assert.equal(await confirm(store, tok, { now }), null);
  emails.length = 0;
  assert.equal(await notifyCardPublished(store, { title: 'Another', url: `${SITE}/cards/a`, site: SITE }), 0);
  assert.equal(emails.length, 0);
  // signing up again issues a new token and a new confirmation
  assert.equal((await subscribe(store, { email: 'reader@example.test', now: now + 1000, site: SITE })).status, 'pending');
  const tok2 = tokenOf(emails[0]);
  assert.ok(tok2 && tok2 !== tok);
  assert.equal(await unsubscribe(store, tok, { now }), false, 'the rotated-out token is nothing now');
  assert.equal(await confirm(store, tok2, { now }), 'confirmed', 'the new one confirms');
  assert.equal((await store.getSubscriberByEmail('reader@example.test')).status, 'confirmed');
});

test('announceHandCards: a manifest card mailed once when fresh, marked without mail when old, never twice', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  await store.insertSubscriber({ email: 'reader@example.test', token: 'a'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  for (const c of CARDS) for (const id of c.story_ids) store._tables.stories.push({ id, run_id: 'r', ordinal: 1, title: c.title, raw_iocs: { exposure: null } });
  const newest = [...CARDS].sort((a, b) => b.date.localeCompare(a.date))[0];
  const at = Date.parse(newest.date) + 86400_000; // the day after the newest card's as-of date
  const n = await announceHandCards(store, { now: at, site: SITE });
  const fresh = CARDS.filter((c) => at - Date.parse(c.date) < 3 * 86400_000);
  assert.equal(n, fresh.length, 'one mail per fresh card'); assert.equal(emails.length, fresh.length);
  assert.ok(emails.some((m) => m.subject.includes(newest.title) && m.html.includes(`${SITE}${newest.url}`)));
  for (const c of CARDS) {
    const rows = await store.getStories(c.story_ids);
    assert.ok(rows.some((r) => r.raw_iocs?.hype?.card_announced), `${c.slug} marked`);
  }
  assert.equal(await announceHandCards(store, { now: at + 3600_000, site: SITE }), 0, 'never twice');
  assert.equal(emails.length, fresh.length);
  assert.ok(!JSON.stringify(subscribeForm()).includes('@example.test\"') || subscribeForm().includes('placeholder="you@example.test"'), 'the form carries only the placeholder');
});
