// Card subscriptions: sign-up, confirmation, one mail per new card, unsubscribe. Memory store,
// captured mail; an address appears in no page and in no mail but its own.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { readFileSync } from 'node:fs';
import { subscribe, confirm, unsubscribe, unsubscribeRequest, unsubscribeAskPage, notifyCardPublished, notifyDailyReport, announceHandCards, validEmail, resultPage, subscribeForm, MAX_REQUESTS_PER_HOUR } from '../lib/subscribe.js';
import { CARDS } from '../lib/cards.js';
import { cardPdfUrl, fetchCardPdf, PDF_MAX_BYTES } from '../lib/pdf.js';
import { captureOutputs } from './helpers.js';

const SITE = 'https://cutsign.example.test';
const now = Date.parse('2026-10-30T12:00:00Z');
const tokenOf = (m) => (m.html.match(/[?&](?:confirm|unsub)=([a-f0-9]{48})/) || [])[1];
const PDF = Buffer.from('%PDF-1.7\n% a card\n%%EOF\n', 'latin1');
/** A fake network for /cards/<slug>.pdf: `answer(url)` → Response; every URL asked is recorded. */
const pdfNet = (answer = () => new Response(PDF, { status: 200, headers: { 'content-type': 'application/pdf' } })) => {
  const impl = async (url) => { impl.calls.push(String(url)); return answer(String(url)); };
  impl.calls = [];
  return impl;
};

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
  const net = pdfNet();
  const n = await notifyCardPublished(store, { title: 'Widget Server zero-day', url: `${SITE}/cards/widget-2026`, summary: 'Patch today.', lane: 'Patch now', priority: 'P1', kind: 'ai', site: SITE, fetchImpl: net });
  assert.equal(n, 1); assert.equal(emails.length, 1);
  const m = emails[0];
  assert.deepEqual(net.calls, [`${SITE}/cards/widget-2026.pdf`]);
  assert.equal(m.attachments.length, 1); assert.equal(m.attachments[0].filename, 'cutsign-widget-2026.pdf');
  assert.ok(m.attachments[0].content.equals(PDF)); assert.match(m.html, /attached as a PDF/); assert.match(m.text, /attached as a PDF/);
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

test('unsubscribe link: opening it (a mail gateway or link scanner does, before any person) changes nothing; only a POST turns the mail off', async () => {
  captureOutputs();
  const store = memoryStore();
  const tok = 'd'.repeat(48);
  await store.insertSubscriber({ email: 'reader@example.test', token: tok, status: 'confirmed', requested_at: new Date(now).toISOString() });
  // GET and HEAD, as often as a scanner likes: still subscribed, and the page asks
  for (const method of ['GET', 'HEAD', 'get']) assert.equal(await unsubscribeRequest(store, tok, method, { now }), 'ask');
  assert.equal((await store.getSubscriberByEmail('reader@example.test')).status, 'confirmed');
  const ask = unsubscribeAskPage(tok);
  assert.match(ask, new RegExp(`<form method="post" action="/api/subscribe\\?unsub=${tok}"><button type="submit">Unsubscribe</button></form>`));
  assert.ok(!ask.includes('example.test'), 'the page never echoes an address');
  // the button, or a mail client's one-click POST to the same URL
  assert.equal(await unsubscribeRequest(store, tok, 'POST', { now }), 'unsubscribed');
  assert.equal((await store.getSubscriberByEmail('reader@example.test')).status, 'unsubscribed');
  assert.equal(await unsubscribeRequest(store, tok, 'GET', { now }), 'unsubscribed', 'the link then says so, with no button');
  // tokens that are nothing
  for (const bad of ['', 'nope', 'e'.repeat(48)]) for (const method of ['GET', 'POST']) assert.equal(await unsubscribeRequest(store, bad, method, { now }), 'unknown');
  assert.equal(unsubscribeAskPage('"><script>'), resultPage('unknown'), 'a malformed token is never put in a page');
  // the endpoint goes through this and nothing else
  const api = readFileSync(new URL('../api/subscribe.js', import.meta.url), 'utf8');
  assert.match(api, /unsubscribeRequest\(store, unsub, req\.method\)/);
  assert.ok(!/[^a-zA-Z]unsubscribe\(store/.test(api), 'the endpoint never unsubscribes without the method check');
});

test('daily report: every confirmed subscriber gets the operator\'s read with its own unsubscribe link, once; nobody else does', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  await store.insertSubscriber({ email: 'a@example.test', token: 'a'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  await store.insertSubscriber({ email: 'b@example.test', token: 'b'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  await store.insertSubscriber({ email: 'gone@example.test', token: 'c'.repeat(48), status: 'unsubscribed', requested_at: new Date(now).toISOString() });
  await store.insertSubscriber({ email: 'owner@example.test', token: 'd'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  const html = '<!doctype html><html><body><div class="w"><p>the read</p></div></body></html>';
  const n = await notifyDailyReport(store, { subject: 'Cutsign — 2026-10-30 — 3 stories', html, text: 'the read', skip: ['Owner@Example.test ', undefined], site: SITE });
  assert.equal(n, 2); assert.deepEqual(emails.map((m) => m.to).sort(), ['a@example.test', 'b@example.test']);
  for (const m of emails) {
    const tok = m.to[0].repeat(48);
    assert.equal(m.subject, 'Cutsign — 2026-10-30 — 3 stories');
    assert.match(m.headers['List-Unsubscribe'], new RegExp(`^<${SITE}/api/subscribe\\?unsub=${tok}>$`));
    assert.equal(m.headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click');
    assert.match(m.html, new RegExp(`<p>the read</p>.*unsub=${tok}.*</div></body></html>$`), 'the footer sits inside the page, after the read');
    assert.ok(m.text.startsWith('the read') && m.text.includes(`unsub=${tok}`));
    assert.ok(!m.html.includes('b@example.test') && !m.html.includes('owner@example.test'), 'no address but its own is anywhere in it');
  }
  // a body that does not end the usual way still gets the footer; a missing table is nobody, not an error
  emails.length = 0;
  await notifyDailyReport(store, { subject: 's', html: '<p>x</p>', text: 'x', skip: ['owner@example.test', 'b@example.test'], site: SITE });
  assert.equal(emails.length, 1); assert.match(emails[0].html, /^<p>x<\/p><p style=.*unsub=a{48}/);
  assert.equal(await notifyDailyReport({ listSubscribers: async () => { throw new Error('relation "card_subscribers" does not exist'); } }, { subject: 's', html: 'x' }), 0);
});

test('card update mail: says it is an update, which version and what changed', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  await store.insertSubscriber({ email: 'a@example.test', token: 'a'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  const n = await notifyCardPublished(store, { title: 'Widget', url: `${SITE}/cards/widget-2026`, summary: 'Patch now.', site: SITE, fetchImpl: pdfNet(), update: { version: 4, changes: ['1 new KEV listing', '<b>1 new fix version</b>'] } });
  assert.equal(n, 1);
  assert.equal(emails[0].subject, 'Cutsign ▣ verdict card updated: Widget');
  assert.ok(emails[0].html.includes('Updated (version 4): 1 new KEV listing; &lt;b&gt;1 new fix version&lt;/b&gt;.'), emails[0].html);
  assert.ok(emails[0].text.includes('Updated (version 4): 1 new KEV listing;'));
  assert.equal(emails[0].attachments?.length, 1);
});

test('announceHandCards: a manifest card mailed once when fresh, marked without mail when old, never twice', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  await store.insertSubscriber({ email: 'reader@example.test', token: 'a'.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  for (const c of CARDS) for (const id of c.story_ids) store._tables.stories.push({ id, run_id: 'r', ordinal: 1, title: c.title, raw_iocs: { exposure: null } });
  // a card with no brief story (a retrospective carded on request) has no story row to carry the mark: it is never announced
  // archived cards are out of the announcement, like the daily checks
  const storied = CARDS.filter((c) => c.status === 'active' && c.story_ids.length); const storyless = CARDS.filter((c) => !c.story_ids.length);
  const newest = [...storied].sort((a, b) => b.date.localeCompare(a.date))[0];
  const at = Date.parse(newest.date) + 86400_000; // the day after the newest card's as-of date
  const net = pdfNet();
  const n = await announceHandCards(store, { now: at, site: SITE, fetchImpl: net });
  const fresh = storied.filter((c) => at - Date.parse(c.date) < 3 * 86400_000);
  assert.equal(n, fresh.length, 'one mail per fresh card'); assert.equal(emails.length, fresh.length);
  assert.ok(emails.some((m) => m.subject.includes(newest.title) && m.html.includes(`${SITE}${newest.url}`)));
  // a hand card's page ends .html; its PDF does not
  assert.ok(net.calls.includes(`${SITE}/cards/${newest.slug}.pdf`), JSON.stringify(net.calls));
  assert.ok(emails.every((m) => m.attachments?.[0]?.filename.startsWith('cutsign-')));
  assert.ok(!emails.some((m) => storyless.some((c) => m.subject.includes(c.title))), 'a card without a story is not mailed');
  for (const c of storied) {
    const rows = await store.getStories(c.story_ids);
    assert.ok(rows.some((r) => r.raw_iocs?.hype?.card_announced), `${c.slug} marked`);
  }
  assert.equal(await announceHandCards(store, { now: at + 3600_000, site: SITE, fetchImpl: net }), 0, 'never twice');
  assert.equal(emails.length, fresh.length);
  assert.ok(!JSON.stringify(subscribeForm()).includes('@example.test\"') || subscribeForm().includes('placeholder="you@example.test"'), 'the form carries only the placeholder');
});

test('card PDF: rendered once per card, not per subscriber; anything but a real PDF leaves the mail link-only', async () => {
  const { emails } = captureOutputs();
  const store = memoryStore();
  for (const who of ['a', 'b']) await store.insertSubscriber({ email: `${who}@example.test`, token: who.repeat(48), status: 'confirmed', requested_at: new Date(now).toISOString() });
  const card = { title: 'Widget', url: `${SITE}/cards/widget-2026`, site: SITE };
  const net = pdfNet();
  assert.equal(await notifyCardPublished(store, { ...card, fetchImpl: net }), 2);
  assert.equal(net.calls.length, 1, 'one render for both mails');
  assert.ok(emails.every((m) => m.attachments?.length === 1));
  const bad = {
    'a 502': () => new Response('render failed', { status: 502, headers: { 'content-type': 'text/plain' } }),
    'an HTML page': () => new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    'a PDF type with other bytes': () => new Response('<html>', { status: 200, headers: { 'content-type': 'application/pdf' } }),
    'an oversize file': () => new Response(Buffer.concat([PDF, Buffer.alloc(PDF_MAX_BYTES)]), { status: 200, headers: { 'content-type': 'application/pdf' } }),
    'a network error': () => { throw new TypeError('fetch failed'); },
  };
  for (const [what, answer] of Object.entries(bad)) {
    emails.length = 0;
    assert.equal(await notifyCardPublished(store, { ...card, fetchImpl: pdfNet(answer) }), 2, what);
    assert.ok(emails.every((m) => !m.attachments && !/attached/.test(m.html)), `${what}: link only`);
  }
  // nobody confirmed: nothing is rendered
  const empty = memoryStore(); const quiet = pdfNet();
  assert.equal(await notifyCardPublished(empty, { ...card, fetchImpl: quiet }), 0);
  assert.equal(quiet.calls.length, 0);
  // only this site's card URLs map to a PDF
  assert.deepEqual(cardPdfUrl(`${SITE}/cards/php2shell-2026.html`), { url: `${SITE}/cards/php2shell-2026.pdf`, slug: 'php2shell-2026' });
  assert.equal(cardPdfUrl(`${SITE}/?view=draft&id=1`), null);
  assert.equal(cardPdfUrl(`${SITE}/cards/../api/x`), null);
  assert.equal(await fetchCardPdf('not a url', { fetchImpl: quiet }), null);
});
