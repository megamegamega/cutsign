// Reader-supplied updates: an "update:" mail from the digest's recipient names a CVE and links;
// the links are read as developments of the stored story and the card loop runs for its run.
// Memory store, fake network, fake models; nothing in the mail is trusted beyond the links.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { parseUpdateMail, applyUpdate, findStory, updateSenders, UPDATE_RE } from '../lib/update.js';
import { fixtureMessage, withHeaders, installFakeLLM, captureOutputs, defaultResponder } from './helpers.js';

const CVE = 'CVE-2026-104935';
const U1 = 'https://news.example.test/2026/10/cisa-urges-ivanti.html?m=1';
const U2 = 'https://news.example.test/2026/10/attackers-chain-three-ivanti.html';
const U3 = 'https://news.example.test/2026/10/unrelated-router-botnet.html';
const page = (title, body) => new Response(`<html><head><title>${title}</title></head><body><article><h1>${title}</h1><p>${body}</p><p>${'More detail about the matter. '.repeat(20)}</p></article></body></html>`, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
const net = async (url) => {
  const u = String(url);
  if (u.endsWith('/robots.txt')) return new Response('User-agent: *\nAllow: /', { status: 200 });
  if (u.startsWith(U1.split('?')[0])) return page('CISA urges immediate patching of Connect Secure', `CISA added ${CVE} to KEV and set a federal deadline; exploitation continues against unpatched appliances.`);
  if (u === U2) return page('Attackers chain three Connect Secure flaws', `Researchers describe a chain of ${CVE} with two further bugs to reach root; webshells observed.`);
  if (u === U3) return page('Router botnet grows', 'A botnet of small-office routers keeps growing; nothing to do with VPN appliances.');
  return new Response('nope', { status: 404 });
};

async function world() {
  const out = captureOutputs();
  const store = memoryStore();
  const brief = await store.insertBrief({ message_id: 'm-ivanti', brief_date: '2026-10-15', subject: 'brief', received_at: '2026-10-15T11:00:00Z', status: 'accepted' });
  const run = await store.insertRun({ brief_id: brief.id, stage: 'sent' });
  store._tables.stories.push({ id: 's-ivanti', run_id: run.id, ordinal: 1, status: 'extracted', selected: false, priority: 1, title: 'Ivanti Connect Secure authentication-bypass zero-day CVE-2026-104935 exploited since October 1',
    summary: 'Per the brief, exploited since October 1; no source text was available.', cves: [CVE], threat_actor: null, malware_family: null, source_urls: [], raw_iocs: { exposure: null, iocs: [] }, created_at: '2026-10-15T12:00:00Z' });
  return { out, store, run };
}

test('parseUpdateMail: the keyword opens the subject; CVEs, links and a quoted title come from subject and body', () => {
  assert.ok(UPDATE_RE.test('update: CVE-2026-1')); assert.ok(UPDATE_RE.test('Re: Fwd: Update — "Ivanti Connect Secure"')); assert.ok(UPDATE_RE.test('sources for CVE-2026-1'));
  assert.equal(parseUpdateMail({ subject: 'Cyber Threat Brief - 2026-10-31', text: 'update: nothing' }), null, 'a brief is never an update');
  assert.equal(parseUpdateMail({ subject: 'an update on things', text: '' }), null, 'the keyword must open the subject');
  const p = parseUpdateMail({ subject: 'update: CVE-2026-104935', text: `see\n${U1}\nand ${U2}.\nagain: ${U1.replace('?m=1', '')}\nhttp://www.news.example.test/2026/10/attackers-chain-three-ivanti.html/` });
  assert.deepEqual(p.cves, [CVE]); assert.deepEqual(p.urls, [U1, U2], 'the same page in other spellings is one link'); assert.equal(p.title, null);
  const q = parseUpdateMail({ subject: 'Re: update — "Ivanti Connect Secure"', html: '<p>Link: <a href="https://a.example.test/x">https://a.example.test/x</a></p>' });
  assert.equal(q.title, 'Ivanti Connect Secure'); assert.deepEqual(q.urls, ['https://a.example.test/x']);
  assert.deepEqual(updateSenders(), ['reader@example.test'], 'defaults to the digest recipient');
});

test('intake: an update from the digest recipient is handed back, stored as ignored and starts no run; from a stranger it is rejected', async () => {
  const { store } = await world();
  const c = await intake(store, { messages: [fixtureMessage('update-ivanti.eml')] });
  assert.equal(c.updates.length, 1); assert.deepEqual(c.updates[0].cves, [CVE]); assert.equal(c.updates[0].urls.length, 3); assert.equal(c.updates[0].from, 'reader@example.test');
  assert.equal(c.accepted, 0); assert.equal(store._tables.runs.length, 1, 'no run for an update');
  assert.match(store._tables.briefs.at(-1).status_reason, /update mail/);
  const c2 = await intake(store, { messages: [withHeaders('update-ivanti.eml', { From: 'Stranger <stranger@example.test>', 'Message-ID': '<fixture-update-stranger@mail.example.test>' })] });
  assert.equal(c2.rejected, 1); assert.equal(c2.updates, undefined);
});

test('applyUpdate: links are read as developments of the story, an unrelated one is skipped, the watch is created and the card loop runs for the story\'s run', async (t) => {
  const { out, store, run } = await world();
  const calls = installFakeLLM((u, n, req) => req.schemaName === 'watch_assessment'
    ? (/router botnet/i.test(u) ? { relates: false, material: false, kinds: [], summary: 'about routers', new_iocs: [], title_outdated: false, revised_title: null }
      : { relates: true, material: true, kinds: ['exploitation'], summary: /KEV/.test(u) ? 'CISA listed the CVE; exploitation continues.' : 'A three-bug chain to root is described.', new_iocs: [], title_outdated: false, revised_title: null })
    : req.schemaName === 'card_draft' ? { title: 'incomplete' } : defaultResponder(u, n, req));
  assert.equal(await findStory(store, { cves: ['CVE-2026-999999'] }), null);
  assert.equal((await findStory(store, { title: 'ivanti connect secure' })).id, 's-ivanti', 'a quoted title finds the story too');
  // a newer roundup that lists the CVE among many is not the story the update is about
  store._tables.stories.push({ id: 's-roundup', run_id: run.id, ordinal: 2, status: 'extracted', selected: true, priority: 2, title: 'Report warns exploited flaws expose management interfaces', summary: 'roundup', cves: ['CVE-2026-1', 'CVE-2026-2', CVE, 'CVE-2026-4'], source_urls: [], raw_iocs: { exposure: null, iocs: [] }, created_at: '2026-10-29T12:00:00Z' });
  assert.equal((await findStory(store, { cves: [CVE] })).id, 's-ivanti', 'the most specific story wins over the newest');
  const r = await applyUpdate(store, { cves: [CVE], urls: [U1, U2, U3], from: 'reader@example.test', fetchImpl: net, now: Date.parse('2026-10-31T13:00:00Z') });
  assert.equal(r.ok, true); assert.equal(r.story_id, 's-ivanti');
  assert.deepEqual(r.read, [U1, U2]); assert.ok(r.skipped.some((s) => s.startsWith(U3) && /not about this story/.test(s)));
  assert.equal(r.events, 2); assert.equal(r.high, 2);
  const w = store._tables.watches.find((x) => x.id === r.watch_id);
  assert.equal(w.story_id, 's-ivanti'); assert.deepEqual(w.urls, [U1, U2]); assert.ok(w.state.pages[U1] && w.state.pages[U2]); assert.equal(w.state.revived_by, 'update mail');
  const ev = store._tables.watch_events;
  assert.equal(ev.length, 2); assert.ok(ev.every((e) => e.kind === 'new_source' && e.level === 'HIGH' && e.assessment.supplied && /^new_source\|news\.example\.test\//.test(e.assessment.text_hash)));
  assert.ok(calls.filter((c) => c.schemaName === 'watch_assessment').length === 3, 'each link read once');
  assert.ok(r.hype && r.hype.scored >= 1, JSON.stringify(r.hype));
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ▣ update applied to "Ivanti Connect Secure') && /2 sources read \(2 HIGH\)/.test(l)));
  // the same mail again: nothing is read twice
  const again = await applyUpdate(store, { cves: [CVE], urls: [U1, U2], fetchImpl: net, now: Date.parse('2026-10-31T13:10:00Z') });
  assert.deepEqual(again.read, []); assert.ok(again.skipped.every((s) => /already read/.test(s))); assert.equal(store._tables.watch_events.length, 2);
  // no story: said, nothing read
  const none = await applyUpdate(store, { cves: ['CVE-2026-999999'], urls: [U1], fetchImpl: net });
  assert.equal(none.ok, false); assert.ok(out.discord.some((l) => /no stored story names CVE-2026-999999/.test(l)));
});
