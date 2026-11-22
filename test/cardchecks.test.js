// The stale-card checks (lib/cardchecks.js): what a card page says, what the distros say, and the six
// checks on a fake network and the in-memory store. No model is called by the checks; the one test
// that reaches a model is the KEV listing handed to the card loop, which writes the re-issue draft.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { memoryStore } from '../lib/store-memory.js';
import { CARDS } from '../lib/cards.js';
import { hypeSweep } from '../lib/hype.js';
import { RECHECK_MS } from '../lib/coverage.js';
import { installFakeLLM, captureOutputs } from './helpers.js';
import { _resetBatchMode } from '../lib/batchmode.js';
import {
  cardClaims, advisoryLinks, debianStatus, ubuntuStatus, updatedDates, ownStory,
  checkKev, checkDistro, checkAdvisories, checkExploitation, checkHygiene, checkArchive,
  cardChecksSweep, CHECKS, DIGEST_ROW, MIGRATION,
} from '../lib/cardchecks.js';

process.env.CARD_AUTOPUBLISH = '0';
process.env.CARD_ACTIONS = '0';
process.env.LLM_BATCH = '0';

const SITE = 'https://cutsign.example.test';
const NOW = Date.parse('2026-11-22T15:00:00Z');
const DAY = 86_400_000;
const CVE = 'CVE-2026-424242';
const widget = (over = {}) => ({ slug: 'widget-2026', title: 'Widget RCE', date: '2026-11-18', lane: 'Patch now', summary: '', cves: [CVE], story_ids: [], status: 'active', url: '/cards/widget-2026.html', ...over });
const kevMap = (o = {}) => new Map(Object.entries({ 'CVE-2020-0001': { dateAdded: '2020-01-01', dueDate: null }, ...o })); // never empty: an empty catalog reads as a failed fetch

/** A card page in the house layout: chips, opening paragraph, a fixed-versions table, a coverage table, a timeline, sources. */
const cardPage = ({ chips = ['Patch now'], lead = '', fixed = [], coverage = [], timeline = [], sources = [] } = {}) => `<!doctype html><html><body><div class="card">
  <div class="lane">${chips.map((c) => `<span class="tag">${c}</span>`).join('')}<span class="asof">as of 2026-11-18</span></div>
  <p class="sub">${lead}</p>
  <h2>Fixed versions</h2><table><tr><th>Product</th><th>Fixed in</th><th>Note</th></tr>${fixed.join('')}</table>
  <h2>Detection coverage</h2><table><tr><th>Category</th><th>Vendor</th><th>Status</th></tr>${coverage.join('')}</table>
  <h2>Timeline</h2><ul class="tl">${timeline.map((t) => `<li><span class="d">Nov 18</span><span>${t}</span></li>`).join('')}</ul>
  <h2>Sources</h2><p class="src">${sources.map(([u, t]) => `<a href="${u}">${t}</a>`).join(' · ')}</p>
</div></body></html>`;
const UNFIXED = cardPage({
  chips: ['Patch now + mitigate', 'No exploitation reported', 'Not in KEV', 'Distro packages unfixed'],
  lead: '<b>As of Nov 18 no source reports exploitation in the wild</b> and the CVE is not in the catalog.',
  fixed: [
    '<tr><td>Widget</td><td><span class="v">1.2.3</span></td><td><span class="ok">released Nov 18</span></td></tr>',
    '<tr><td>Debian packages</td><td><span class="bad">unfixed</span></td><td>every release marked vulnerable</td></tr>',
    '<tr><td>Ubuntu / Red Hat packages</td><td><span class="bad">no fix listed</span></td><td>no errata yet</td></tr>',
  ],
  coverage: [
    '<tr><td rowspan="2">Vendor</td><td><a href="https://vendor.example.test/advisory/1">Widget Inc</a> / <a href="https://cert.example.test/note/7">CERT</a></td><td><span class="ok">Fixed Nov 18</span></td></tr>',
    '<tr><td><a href="https://finder.example.test/writeup">Finder</a></td><td><span class="ok">Root cause published</span></td></tr>',
    '<tr><td>VM scanners</td><td><a href="https://scanner.example.test/post">Scanner</a></td><td><span class="bad">Nothing published</span>; Debian images are flagged</td></tr>',
  ],
  timeline: ['Debian marks every release vulnerable. No exploitation reported; not in KEV'],
  sources: [['https://news.example.test/story', 'News — write-up'], ['https://gov.example.test/alert', 'Agency alert, Nov 17'], ['https://security-tracker.debian.org/tracker/' + CVE, 'Debian tracker advisory'], ['https://vendor.example.test/advisory/1', 'Widget Inc — security advisory']],
});
const FIXED = cardPage({
  chips: ['Patch now', 'Exploit attempts on sensors · no confirmed compromise', 'Distro fixes out · bundled runtimes lag'],
  lead: '<b>As of Nov 22 attempts are reported, and no source confirms a compromise</b>.',
  fixed: [
    '<tr><td>Debian / Ubuntu packages</td><td><span class="ok">fixed through the security archives</span></td><td>testing still vulnerable</td></tr>',
    '<tr><td>Red Hat OpenJDK packages (RHEL 8/9/10)</td><td><span class="v">1.2.3</span></td><td><span class="ok">errata out</span></td></tr>',
    '<tr><td>Red Hat products that bundle a runtime</td><td><span class="bad">still listed affected</span></td><td>no erratum</td></tr>',
  ],
  timeline: ['stable Debian and Ubuntu packages still vulnerable. No exploitation reported'],
});

const html = (body, status = 200) => new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
/** A fake network: canned answers by URL substring (a function is called each time), 404 for everything else. */
function net(routes = {}) {
  const impl = async (url) => {
    const u = String(url); impl.calls.push(u);
    for (const [k, v] of Object.entries(routes)) if (u.includes(k)) { const r = typeof v === 'function' ? v() : v; return r instanceof Response ? r.clone() : typeof r === 'string' ? html(r) : json(r); }
    return html('not found', 404);
  };
  impl.calls = [];
  return impl;
}
const DEBIAN = (rows) => `<html><body><table><tr><td><b>References</b></td><td><a href="/tracker/DSA-6642-1">DSA-6642-1</a></td></tr></table>
<table><tr><th>Source Package</th><th>Release</th><th>Version</th><th>Status</th></tr>${rows.map(([rel, ver, st]) => `<tr><td></td><td>${rel}</td><td>${ver}</td><td>${st === 'vulnerable' ? '<span class="red">vulnerable</span>' : st}</td></tr>`).join('')}</table></body></html>`;
const DEBIAN_UNFIXED = DEBIAN([['bookworm', '1.0-1', 'vulnerable'], ['bookworm (security)', '1.0-1', 'vulnerable'], ['sid', '1.2.3-1', 'fixed']]).replaceAll('DSA-6642-1', 'none');
const DEBIAN_FIXED = DEBIAN([['bookworm', '1.0-1', 'vulnerable'], ['bookworm (security)', '1.0-1+deb12u1', 'fixed'], ['trixie (security)', '1.1-1+deb13u1', 'fixed'], ['forky, sid', '1.2.3-1', 'fixed']]);
const UBUNTU = (status) => ({ id: CVE, notices: status === 'released' ? [{ id: 'USN-9159-1' }] : [], packages: [{ name: 'widget', statuses: [{ release_codename: 'upstream', status: 'released', description: '1.2.3' }, { release_codename: 'noble', status, description: status === 'released' ? '1.0-1ubuntu0.1' : '' }, { release_codename: 'jammy', status: 'DNE', description: '' }] }] });
const REDHAT = (errata) => ({ threat_severity: 'Critical', affected_release: errata.map((a) => ({ advisory: a, product_name: 'Red Hat Enterprise Linux 9' })), package_state: [{ fix_state: 'Affected' }] });
const article = (lines) => `<html><body><article>${lines.map((l) => `<p>${l}</p>`).join('\n')}</article></body></html>`;
const ADVISORY_V1 = ['Widget Inc security advisory for the remote code execution flaw in Widget Server.', 'Customers should upgrade Widget Server to the release named in the table below as soon as possible.', 'Widget Inc thanks the researchers who reported this issue through coordinated disclosure.', 'This page lists the affected products and the releases that carry the correction for each of them.', 'Further questions can be sent to the product security team through the customer support portal.'];
const flagsOf = async (store, slug = 'widget-2026') => ((await store.listCardChecks()).find((r) => r.slug === slug)?.state?.flags || []);
const sweep = (store, card, routes, opts = {}) => cardChecksSweep(store, { cards: [card], fetchImpl: net({ '/cards/widget-2026.html': UNFIXED, ...routes }), now: NOW, site: SITE, kevOf: async () => kevMap(), ...opts });

// ---- reading the card ------------------------------------------------------------------------------

test('cardClaims: a status is read from the row that names the distro; the timeline and prose are history, not claims', () => {
  const c = cardClaims(UNFIXED);
  assert.deepEqual(c.distro, { debian: 'unfixed', ubuntu: 'unfixed', redhat: 'unfixed' });
  assert.equal(c.exploitation, 'none'); assert.equal(c.kev, 'not listed');
  // a card that shows the fix has acknowledged it, whatever else it lists as lagging; its timeline still says "vulnerable"
  const f = cardClaims(FIXED);
  assert.deepEqual(f.distro, { debian: 'fixed', ubuntu: 'fixed', redhat: 'fixed' });
  assert.equal(f.exploitation, null, '"no confirmed compromise" is not "no exploitation reported"'); assert.equal(f.kev, null);
  // a distro only mentioned in another row's status prose is not a claim about it, and a card that says nothing claims nothing
  const other = cardClaims(cardPage({ coverage: ['<tr><td>VM scanners</td><td>Scanner</td><td><span class="bad">Nothing published</span>; Debian and Ubuntu images are flagged</td></tr>'] }));
  assert.deepEqual(other.distro, { debian: null, ubuntu: null, redhat: null }); assert.equal(other.exploitation, null);
  assert.deepEqual(cardClaims('').distro, { debian: null, ubuntu: null, redhat: null });
  // the chip alone speaks for all three
  assert.deepEqual(cardClaims(cardPage({ chips: ['Many distro and bundled runtimes unfixed'] })).distro, { debian: 'unfixed', ubuntu: 'unfixed', redhat: 'unfixed' });
  assert.equal(cardClaims(cardPage({ lead: '<b>No report of exploitation in the wild found as of Nov 22</b>' })).exploitation, 'none');
});

test('advisoryLinks: the Vendor rows of the coverage table (across a rowspan) and sources that call themselves advisories; trackers are left to their own check', () => {
  const links = advisoryLinks(UNFIXED);
  assert.deepEqual(links.map((l) => l.url), ['https://vendor.example.test/advisory/1', 'https://cert.example.test/note/7', 'https://finder.example.test/writeup', 'https://gov.example.test/alert']);
  assert.equal(links[0].label, 'Widget Inc');
  assert.equal(advisoryLinks(UNFIXED, { max: 2 }).length, 2);
});

test('every hand-written card page is readable: claims come back in shape, with nothing thrown', () => {
  for (const c of CARDS) {
    const claims = cardClaims(readFileSync(new URL(`../public/cards/${c.slug}.html`, import.meta.url), 'utf8'));
    for (const d of ['debian', 'ubuntu', 'redhat']) assert.ok([null, 'fixed', 'unfixed'].includes(claims.distro[d]), `${c.slug} ${d}`);
    assert.ok([null, 'none'].includes(claims.exploitation) && [null, 'not listed'].includes(claims.kev), c.slug);
    assert.ok(claims.advisories.length <= 8 && claims.advisories.every((a) => /^https?:\/\//.test(a.url) && a.label), c.slug);
  }
});

test('distro parsers: Debian is fixed when the security archive carries it, not when only unstable does; Ubuntu when a release has it', () => {
  assert.deepEqual(debianStatus(DEBIAN_UNFIXED), { isFixed: false, fixed: [], advisories: [] });
  const d = debianStatus(DEBIAN_FIXED);
  assert.equal(d.isFixed, true); assert.deepEqual(d.fixed.map((f) => f.release), ['bookworm', 'trixie']); assert.deepEqual(d.advisories, ['DSA-6642-1']);
  assert.equal(ubuntuStatus(UBUNTU('needed')).isFixed, false, 'an upstream release is not an Ubuntu fix');
  const u = ubuntuStatus(UBUNTU('released'));
  assert.equal(u.isFixed, true); assert.deepEqual(u.fixed.map((f) => f.release), ['noble']); assert.deepEqual(u.notices, ['USN-9159-1']);
  assert.equal(ubuntuStatus(null).isFixed, false);
  assert.deepEqual(updatedDates('Last updated: 19 November 2026, 08:00 UTC. Updated November 20, 2026, 03:19. We recently updated our product survey. modified 2026-11-21'), ['2026-11-19', '2026-11-20', '2026-11-21']);
});

// ---- 1. KEV ------------------------------------------------------------------------------------------

test('KEV: a declared CVE listed after the card date is a flag, said once; a listing the chip denies is one too; an empty catalog is not "nothing listed"', async () => {
  const { discord, emails } = captureOutputs();
  const card = widget();
  assert.deepEqual(checkKev({ card, kev: kevMap() }), []);
  assert.deepEqual(checkKev({ card, kev: kevMap({ [CVE]: { dateAdded: '2026-11-10', dueDate: null } }) }), [], 'listed before the card was written and not denied by it');
  assert.equal(checkKev({ card, claims: { kev: 'not listed' }, kev: kevMap({ [CVE]: { dateAdded: '2026-11-10', dueDate: null } }) }).length, 1);
  assert.deepEqual(checkKev({ card: widget({ cves: [] }), kev: kevMap({ [CVE]: '2026-11-20' }) }), [], 'only the CVEs the card declares');

  const store = memoryStore();
  const listed = async () => kevMap({ [CVE]: { dateAdded: '2026-11-20', dueDate: '2026-11-23' } });
  const c1 = await sweep(store, card, {}, { kevOf: listed });
  assert.equal(c1.checked, 1); assert.equal(c1.errors, 0, JSON.stringify(c1));
  const f = (await flagsOf(store)).filter((x) => x.check === 'kev');
  assert.equal(f.length, 1); assert.equal(f[0].key, `kev:${CVE}`); assert.match(f[0].text, /added 2026-11-20 \(federal due 2026-11-23\), after the card's date/);
  const line = discord.find((l) => l.startsWith('Cutsign ⚑ card widget-2026 (as of 2026-11-18) may be stale'));
  assert.ok(line, discord.join('\n')); assert.match(line, /\[kev\] CISA KEV lists CVE-2026-424242/);
  // no brief story carries the card, so there is no run to draft from: the line says so
  assert.deepEqual(c1.runs, []); assert.match(line, /no brief story carries this card, so no AI draft can be written/);
  assert.match(line, /Flag only: nothing was changed, archived or published/);
  // the same tick block: not asked again; the next day: still open, not said as new, carried in the digest once
  const c2 = await sweep(store, card, {}, { kevOf: listed, now: NOW + 3600_000 });
  assert.equal(c2.checked, 0); assert.equal(c2.flags_open > 0, true);
  const said = discord.length;
  const c3 = await sweep(store, card, {}, { kevOf: listed, now: NOW + DAY });
  assert.equal(c3.checked, 1); assert.equal(c3.digest, 1);
  assert.equal(discord.filter((l) => l.includes('may be stale')).length, 1, 'a flag is raised once');
  assert.equal(discord.length, said + 1); assert.match(discord.at(-1), /open flags? on 1 hand-written card/); assert.match(discord.at(-1), /widget-2026 \(as of 2026-11-18\): .*kev.*oldest since 2026-11-22/);
  const c4 = await sweep(store, card, {}, { kevOf: listed, now: NOW + DAY + 3600_000 });
  assert.equal(c4.digest, undefined, 'one digest a day'); assert.equal(discord.length, said + 1);
  // a catalog that could not be read keeps what was known rather than clearing it
  await sweep(store, card, {}, { kevOf: async () => new Map(), now: NOW + 2 * DAY });
  assert.equal((await flagsOf(store)).filter((x) => x.check === 'kev').length, 1);
  assert.equal(emails.length, 0); assert.equal(store._tables.card_drafts.length, 0, 'the checks write no draft and publish nothing themselves');
});

const uuid = (n) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;
const DRAFT = {
  title: 'Vendor appliance zero-day exploited; patch and hunt', verdict: 'Patch today; hunt for shells from the appliance process. [S1]', lane: 'Hunt / IR + patch',
  confidence: 'high', confidence_reason: 'Vendor primary source confirms exploitation.',
  what_happened: ['Vendor confirmed exploitation. [S1]', 'CISA added the CVE to KEV. [S2]'],
  timeline: [{ date: '2026-10-15', event: 'Advisory published', source: 'S1' }],
  detect: [{ name: 'Shell from appliance process', log_source: 'appliance syslog', spl: 'index=* parent=httpd child=sh | stats count',
    esql: 'FROM logs-* | WHERE process.parent.name == "httpd" AND process.name == "sh" | STATS count = COUNT(*)', hit_means: 'post-exploitation' }],
  verify: ['Confirm the child process is not the vendor backup job.'],
  triage: { priority: 'P1', why: 'Exploited in the wild, internet-facing.' },
  scope: { affected: ['Appliance versions before 1.2'], only_if: ['management interface exposed'], not_affected_if: ['1.2 or later'], fixed_in: '1.2', enumerate: ['Every appliance and its version'] },
  contain: ['Patch to 1.2', 'Rotate credentials'], eradicate: ['Remove the SUID binary'], recover: ['Validate from a clean image'],
  reenter_when: ['A second product is named'], debrief: ['Record patch dates'],
  coverage_checks: [{ category: 'vulnerability scanner', check: 'look up the CVE in the vendor KB' }],
  open_questions: [], changes_since_prior: [],
  sources: [{ ref: 'S1', url: 'https://www.cisa.gov/news-events/alerts/x', publisher: 'CISA' }],
};

test('KEV: a new listing hands the card\'s run to the card loop, which writes the AI re-issue draft; the checks themselves call no model', async () => {
  const { discord } = captureOutputs(); _resetBatchMode();
  const calls = installFakeLLM(() => DRAFT);
  const card = CARDS.find((c) => c.status === 'active' && c.cves.length && c.story_ids.length);
  const store = memoryStore();
  const brief = await store.insertBrief({ message_id: 'm1', brief_date: card.date, subject: 'brief', received_at: `${card.date}T11:00:00Z` });
  const run = await store.insertRun({ brief_id: brief.id, stage: 'sent' });
  store._tables.stories.push({ id: card.story_ids[0], run_id: run.id, ordinal: 1, status: 'extracted', title: card.title, summary: 'What happened, in two sentences.', priority: 1, selected: true,
    cves: card.cves, threat_actor: 'UNC0000', raw_iocs: { exposure: { only_if: ['internet-exposed'] } }, source_urls: ['https://www.cisa.gov/news-events/alerts/x'], sources: [], guidance: [], behaviors: [], samples: [], newIocs: [], repeatIocs: [], updates_story_id: null, created_at: `${card.date}T12:00:00Z` });
  const added = new Date(Date.parse(card.date) + DAY).toISOString().slice(0, 10);
  const now = Date.parse(card.date) + 5 * DAY;
  const c = await cardChecksSweep(store, { cards: [card], fetchImpl: net({ [card.url]: cardPage() }), now, site: SITE, kevOf: async () => kevMap({ [card.cves[0]]: { dateAdded: added, dueDate: null } }) });
  assert.deepEqual(c.runs, [run.id], JSON.stringify(c));
  assert.equal(calls.length, 0, 'no model call from the checks');
  assert.match(discord.find((l) => l.includes(`card ${card.slug}`) && l.includes('may be stale')), /the card loop is asked for an AI re-issue draft this tick/);
  // what api/watch.js then does with `runs`: the card loop for that run
  const kevNet = async (url) => (String(url).includes('cisa.gov/sites/default/files/feeds') ? json({ vulnerabilities: [{ cveID: card.cves[0], dateAdded: added }] }) : html('nope', 404));
  const h = await hypeSweep(store, { run, fetchImpl: kevNet, now });
  assert.equal(h.stale, 1, JSON.stringify(h)); assert.equal(h.drafted, 1);
  const drafts = await store.listCardDrafts();
  assert.equal(drafts.length, 1); assert.ok(drafts[0].reasons.includes(`re-issue of card ${card.slug}`)); assert.equal(drafts[0].status, 'draft', 'a draft, not a publication');
  // the next day's check hands the run over once more (a tick can run out of time before the loop): the loop
  // has already raised and drafted the listing, so nothing is written twice; after that it is left alone
  const again = { cards: [card], fetchImpl: net({ [card.url]: cardPage() }), site: SITE, kevOf: async () => kevMap({ [card.cves[0]]: { dateAdded: added, dueDate: null } }) };
  const c2 = await cardChecksSweep(store, { ...again, now: now + DAY });
  assert.deepEqual(c2.runs, [run.id]);
  const h2 = await hypeSweep(store, { run, fetchImpl: kevNet, now: now + DAY });
  assert.equal(h2.drafted + h2.revised, 0, JSON.stringify(h2)); assert.equal((await store.listCardDrafts()).length, 1); assert.equal(calls.length, 1);
  assert.deepEqual((await cardChecksSweep(store, { ...again, now: now + 2 * DAY })).runs, []);
  assert.equal(discord.filter((l) => l.includes('may be stale')).length, 1);
});

// ---- 2. distro fixes ---------------------------------------------------------------------------------

test('distro: where the card says unfixed, each distro is re-asked and a fix is a flag; where it says fixed, nothing is asked; a failed source is not a finding', async () => {
  const { discord } = captureOutputs();
  const card = widget(); const store = memoryStore();
  const routes = { 'security-tracker.debian.org': DEBIAN_UNFIXED, 'ubuntu.com/security/cves': UBUNTU('needed'), 'access.redhat.com/hydra': REDHAT([]) };
  await sweep(store, card, routes);
  assert.deepEqual((await flagsOf(store)).filter((f) => f.check === 'distro'), [], 'the card is right: nothing to say');
  assert.ok(!discord.some((l) => l.includes('[distro]')));
  // the next day Debian's security archive and Red Hat carry the fix; Ubuntu's page is down
  const fetchImpl = net({ '/cards/widget-2026.html': UNFIXED, 'security-tracker.debian.org': DEBIAN_FIXED, 'ubuntu.com/security/cves': () => html('gateway', 502), 'access.redhat.com/hydra': REDHAT(['RHSA-2026:100744', 'RHSA-2026:100745']) });
  await cardChecksSweep(store, { cards: [card], fetchImpl, now: NOW + DAY, site: SITE, kevOf: async () => kevMap() });
  const f = (await flagsOf(store)).filter((x) => x.check === 'distro');
  assert.deepEqual(f.map((x) => x.key), ['distro:debian', 'distro:redhat']);
  assert.match(f[0].text, /the card says Debian is unfixed or pending; Debian now shows CVE-2026-424242: bookworm, trixie fixed through the security archive \(DSA-6642-1\)/);
  assert.match(f[1].text, /Red Hat now shows CVE-2026-424242: errata RHSA-2026:100744, RHSA-2026:100745/);
  assert.equal(f[0].url, `https://security-tracker.debian.org/tracker/${CVE}`);
  assert.ok(discord.some((l) => l.includes('may be stale') && l.includes('[distro]')));
  // the card is re-worded (same date): the page now shows the fix, the flags are gone, and no distro is asked
  const after = net({ '/cards/widget-2026.html': FIXED, 'security-tracker.debian.org': DEBIAN_FIXED });
  await cardChecksSweep(store, { cards: [card], fetchImpl: after, now: NOW + 2 * DAY, site: SITE, kevOf: async () => kevMap() });
  assert.deepEqual((await flagsOf(store)).filter((x) => x.check === 'distro'), []);
  assert.ok(!after.calls.some((u) => /debian|ubuntu|redhat/.test(u)), after.calls.join('\n'));
  // on its own: every declared CVE is asked, and the flag names the ones that are fixed
  const two = await checkDistro({ card: widget({ cves: [CVE, 'CVE-2026-424243'] }), claims: { distro: { debian: 'unfixed', ubuntu: null, redhat: null } }, fetchImpl: net({ 'security-tracker.debian.org': DEBIAN_FIXED }) });
  assert.equal(two.length, 1); assert.match(two[0].text, /\(and CVE-2026-424243\)/);
});

// ---- 3. vendor advisories ----------------------------------------------------------------------------

test('advisories: first sight is a baseline; new advisory-shaped text is a flag once and stays until the card is re-issued; a cosmetic change and an old card are left alone', async () => {
  const { discord } = captureOutputs();
  const card = widget(); const store = memoryStore();
  let body = article(ADVISORY_V1);
  const routes = { 'vendor.example.test/advisory/1': () => html(body) };
  await sweep(store, card, routes);
  assert.deepEqual((await flagsOf(store)).filter((f) => f.check === 'advisory'), [], 'baseline');
  // a banner changes: nothing an advisory would say
  body = article([...ADVISORY_V1, 'Sign up for the Widget Inc newsletter to hear about our spring conference.']);
  await sweep(store, card, routes, { now: NOW + DAY });
  assert.deepEqual((await flagsOf(store)).filter((f) => f.check === 'advisory'), []);
  // the advisory itself moves
  body = article([...ADVISORY_V1, 'Widget Server 1.2.4 replaces 1.2.3: the first fixed release did not cover the clustered configuration.']);
  await sweep(store, card, routes, { now: NOW + 2 * DAY });
  let f = (await flagsOf(store)).filter((x) => x.check === 'advisory');
  assert.equal(f.length, 1); assert.equal(f[0].url, 'https://vendor.example.test/advisory/1');
  assert.match(f[0].text, /^Widget Inc: new text since 2026-11-2\d — "Widget Server 1\.2\.4 replaces 1\.2\.3/);
  assert.equal(discord.filter((l) => l.includes('[advisory]')).length, 1);
  // unchanged the day after: the flag stays open and is not said again
  await sweep(store, card, routes, { now: NOW + 3 * DAY });
  f = (await flagsOf(store)).filter((x) => x.check === 'advisory');
  assert.equal(f.length, 1); assert.equal(discord.filter((l) => l.includes('[advisory]')).length, 1);
  // the card is re-issued (a later date): a clean slate and a new baseline
  await sweep(store, widget({ date: '2026-11-25' }), routes, { now: NOW + 4 * DAY });
  assert.deepEqual(await flagsOf(store), []);

  // an "updated" date after the card's date is a flag at first sight
  const s2 = memoryStore();
  const dated = { 'vendor.example.test/advisory/1': () => html(article(['Last updated: 20 November 2026, 08:00 UTC', ...ADVISORY_V1])) };
  await sweep(s2, card, dated);
  f = (await flagsOf(s2)).filter((x) => x.check === 'advisory');
  assert.equal(f.length, 1); assert.match(f[0].text, /the page says it was updated 2026-11-20, after the card's date/);
  // a card older than 30 days: its advisories are not fetched at all
  const old = net({ '/cards/widget-2026.html': UNFIXED, 'vendor.example.test/advisory/1': html(article(ADVISORY_V1)) });
  await cardChecksSweep(memoryStore(), { cards: [widget({ date: '2026-10-01' })], fetchImpl: old, now: NOW, site: SITE, kevOf: async () => kevMap() });
  assert.ok(!old.calls.some((u) => u.includes('vendor.example.test')), old.calls.join('\n'));
  // a page that cannot be read keeps its baseline instead of becoming one
  const r = await checkAdvisories({ card, claims: { advisories: [{ url: 'https://vendor.example.test/advisory/1', label: 'Widget Inc' }] }, prev: { 'https://vendor.example.test/advisory/1': { at: '2026-11-20T00:00:00Z', updated: null, hashes: ['abc'] } }, now: NOW, fetchImpl: net({}) });
  assert.deepEqual(r.flags, []); assert.deepEqual(r.state['https://vendor.example.test/advisory/1'].hashes, ['abc']);
});

// ---- 4. exploitation ---------------------------------------------------------------------------------

test('exploitation: while the card says none is reported, a KEV listing or an exploitation development on the card\'s own story is a flag; a roundup\'s is not', async () => {
  captureOutputs();
  const card = widget(); const store = memoryStore();
  const t = store._tables;
  t.stories.push({ id: uuid(1), run_id: 'r1', status: 'extracted', title: 'Widget RCE', cves: [CVE], created_at: '2026-11-19T12:00:00Z' });
  t.stories.push({ id: uuid(2), run_id: 'r1', status: 'extracted', title: 'Weekly roundup', cves: [CVE, 'CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3'], created_at: '2026-11-20T12:00:00Z' });
  t.watches.push({ id: 'w1', story_id: uuid(1), title: 'Widget RCE', status: 'active' }, { id: 'w2', story_id: uuid(2), title: 'Weekly roundup', status: 'active' });
  const ev = (id, watch_id, summary, kinds = ['exploitation'], created_at = '2026-11-20T15:00:00Z') => ({ id, watch_id, created_at, kind: 'page_changed', level: 'HIGH', url: 'https://labs.example.test/post', summary, assessment: { relates: true, material: true, kinds, summary } });
  t.watch_events.push(ev('e1', 'w1', 'Sensors record exploitation attempts against Widget Server; no compromise confirmed.'));
  t.watch_events.push(ev('e2', 'w2', 'A different product in the roundup is now exploited in the wild.'));
  t.watch_events.push(ev('e3', 'w1', 'A fixed build is out for another platform.', ['fix_available']));
  t.watch_events.push(ev('e4', 'w1', 'Exploitation was reported before the card was written.', ['exploitation'], '2026-11-17T09:00:00Z'));
  await sweep(store, card, {});
  const f = (await flagsOf(store)).filter((x) => x.check === 'exploitation');
  assert.deepEqual(f.map((x) => x.key), ['exploited:event:e1']);
  assert.match(f[0].text, /the card says no exploitation is reported; 2026-11-20: Sensors record exploitation attempts/); assert.equal(f[0].url, 'https://labs.example.test/post');
  // a roundup's development counts once it names the card's CVE
  t.watch_events.push(ev('e5', 'w2', `${CVE} is now being exploited, per the roundup's update.`, ['exploitation'], '2026-11-21T10:00:00Z'));
  assert.deepEqual(checkExploitation({ card, claims: { exploitation: 'none' }, kev: kevMap(), events: await store.listWatchEvents({}), stories: t.stories }).map((x) => x.key), ['exploited:event:e5', 'exploited:event:e1']);
  // a listing in the catalog is the strongest report there is
  assert.deepEqual(checkExploitation({ card, claims: { exploitation: 'none' }, kev: kevMap({ [CVE]: { dateAdded: '2026-11-21' } }), events: [], stories: [] }).map((x) => x.key), [`exploited:kev:${CVE}`]);
  // a card that does not say "none" has nothing to contradict
  assert.deepEqual(checkExploitation({ card, claims: { exploitation: null }, kev: kevMap({ [CVE]: { dateAdded: '2026-11-21' } }), events: await store.listWatchEvents({}), stories: t.stories }), []);
  const s2 = memoryStore(); Object.assign(s2._tables, { stories: t.stories, watches: t.watches, watch_events: t.watch_events });
  await cardChecksSweep(s2, { cards: [card], fetchImpl: net({ '/cards/widget-2026.html': FIXED }), now: NOW, site: SITE, kevOf: async () => kevMap() });
  assert.deepEqual((await flagsOf(s2)).filter((x) => x.check === 'exploitation'), []);
  assert.equal(ownStory(card, t.stories[0]), true); assert.equal(ownStory(card, t.stories[1]), false);
  assert.equal(ownStory(widget({ story_ids: [uuid(2)] }), t.stories[1]), true, 'a story the manifest names is the card\'s own');
});

// ---- 5. coverage hygiene -----------------------------------------------------------------------------

test('hygiene: automated coverage rows for a CVE the card does not declare are a flag; a card that declares none uses its thread\'s by design', async () => {
  captureOutputs();
  const cov = { checked_at: '2026-11-22T10:00:00Z', cves: [CVE, 'CVE-2026-109618'], lanes: [
    { id: `kev:${CVE}`, status: 'nothing found' }, { id: 'kev:CVE-2026-109618', status: 'published' }, { id: 'redhat:CVE-2026-109618', status: 'published' }, { id: 'wiz', status: 'published' }] };
  const card = widget({ story_ids: [uuid(1)] }); const store = memoryStore();
  store._tables.stories.push({ id: uuid(1), run_id: 'r1', status: 'extracted', title: 'Widget RCE', cves: [CVE], raw_iocs: { hype: { card_coverage: cov } }, created_at: '2026-11-19T12:00:00Z' });
  await sweep(store, card, {});
  const f = (await flagsOf(store)).filter((x) => x.check === 'hygiene');
  assert.equal(f.length, 1); assert.match(f[0].text, /carries 2 rows for a CVE this card does not declare: CVE-2026-109618/);
  assert.deepEqual(checkHygiene({ card: widget({ cves: [] }), coverage: cov }), [], 'no declared CVE: the thread\'s CVEs are the card\'s');
  assert.deepEqual(checkHygiene({ card, coverage: { ...cov, cves: [CVE], lanes: cov.lanes.filter((l) => !l.id.includes('109618')) } }), []);
  assert.deepEqual(checkHygiene({ card, coverage: null }), []);
  // the rows are gone after the next coverage check: so is the flag
  store._tables.stories[0].raw_iocs.hype.card_coverage = { ...cov, cves: [CVE], lanes: cov.lanes.filter((l) => !l.id.includes('109618')) };
  await sweep(store, card, {}, { now: NOW + DAY });
  assert.deepEqual((await flagsOf(store)).filter((x) => x.check === 'hygiene'), []);
});

// ---- 6. archive --------------------------------------------------------------------------------------

test('archive: a card past 30 days with no active watch is listed, and only listed; one with an active watch is not', async () => {
  const { discord } = captureOutputs();
  const before = JSON.stringify(CARDS.map((c) => [c.slug, c.status, c.archived_on]));
  const old = widget({ date: '2026-10-20', story_ids: [uuid(1)] }); const store = memoryStore();
  store._tables.stories.push({ id: uuid(1), run_id: 'r1', status: 'extracted', title: 'Widget RCE', cves: [CVE], created_at: '2026-10-20T12:00:00Z' });
  store._tables.watches.push({ id: 'w1', story_id: uuid(1), title: 'Widget RCE', status: 'expired', expires_at: '2026-11-03T00:00:00Z', last_change_at: '2026-10-22T00:00:00Z' });
  await sweep(store, old, { '/cards/widget-2026.html': cardPage() });
  const f = (await flagsOf(store)).filter((x) => x.check === 'archive');
  assert.equal(f.length, 1); assert.match(f[0].text, /eligible to archive \(card dated 2026-10-20, all watches expired, last development 2026-10-22\); a human sets the status/);
  assert.ok(discord.some((l) => l.includes('[archive]') && l.includes('Flag only: nothing was changed, archived or published')));
  assert.equal(before, JSON.stringify(CARDS.map((c) => [c.slug, c.status, c.archived_on])), 'the manifest is untouched');
  // said once: a card someone decided to keep is not in the daily digest
  const said = discord.length;
  const next = await sweep(store, old, { '/cards/widget-2026.html': cardPage() }, { now: NOW + DAY });
  assert.equal(next.digest, undefined); assert.equal(discord.length, said); assert.equal((await flagsOf(store)).filter((x) => x.check === 'archive').length, 1);
  // an active watch, a recent development or a young card: not a candidate
  assert.deepEqual(checkArchive({ card: old, watchRows: [{ story_id: uuid(1), status: 'active', last_change_at: null }], now: NOW }), []);
  assert.deepEqual(checkArchive({ card: old, watchRows: [{ story_id: uuid(1), status: 'expired', last_change_at: '2026-11-15T00:00:00Z' }], now: NOW }), []);
  assert.deepEqual(checkArchive({ card: widget({ story_ids: [uuid(1)] }), watchRows: [], now: NOW }), []);
  assert.equal(checkArchive({ card: widget({ date: '2026-10-20' }), watchRows: [], now: NOW }).length, 1, 'a card with no story has no watch to wait for');
});

// ---- the sweep ---------------------------------------------------------------------------------------

test('sweep: without its table it says which migration to apply and does nothing; past its deadline it defers; a card it cannot read keeps its flags', async () => {
  const { discord, emails } = captureOutputs();
  const card = widget();
  const noTable = { ...memoryStore(), listCardChecks: async () => { throw new Error('db: relation "public.card_checks" does not exist'); } };
  const fetchImpl = net({ '/cards/widget-2026.html': UNFIXED });
  const c = await cardChecksSweep(noTable, { cards: [card], fetchImpl, now: NOW, site: SITE, kevOf: async () => kevMap() });
  assert.equal(c.skipped, `apply ${MIGRATION}`); assert.equal(c.checked, 0); assert.equal(fetchImpl.calls.length, 0); assert.equal(discord.length, 0);
  // any other database failure is an error, not a skip
  const broken = { ...memoryStore(), listCardChecks: async () => { throw new Error('db: connection refused'); } };
  assert.equal((await cardChecksSweep(broken, { cards: [card], fetchImpl, now: NOW, site: SITE })).errors, 1);

  const store = memoryStore();
  const late = await cardChecksSweep(store, { cards: [card, widget({ slug: 'gadget-2026', url: '/cards/gadget-2026.html' })], fetchImpl, now: NOW, site: SITE, deadline: Date.now() - 1, kevOf: async () => { throw new Error('must not be fetched'); } });
  assert.equal(late.deferred, 2); assert.equal(late.checked, 0); assert.equal(fetchImpl.calls.length, 0);
  assert.deepEqual(await store.listCardChecks(), []);

  // stalest first: a card never checked goes before one checked yesterday
  await store.putCardCheck('widget-2026', { card_date: card.date, checked_at: new Date(NOW - RECHECK_MS - 1000).toISOString(), flags: [], raised: [], advisories: {} });
  const order = net({ '/cards/': cardPage() });
  await cardChecksSweep(store, { cards: [card, widget({ slug: 'gadget-2026', url: '/cards/gadget-2026.html' })], fetchImpl: order, now: NOW, site: SITE, kevOf: async () => kevMap() });
  assert.deepEqual(order.calls.filter((u) => u.includes('/cards/')).map((u) => u.split('/cards/')[1]), ['gadget-2026.html', 'widget-2026.html']);

  // the card page is down: the checks that read it keep what they last said, and the round is counted as an error
  const s2 = memoryStore();
  await sweep(s2, card, { 'security-tracker.debian.org': DEBIAN_FIXED });
  assert.deepEqual((await flagsOf(s2)).map((f) => f.key), ['distro:debian']);
  const down = await cardChecksSweep(s2, { cards: [card], fetchImpl: net({}), now: NOW + DAY, site: SITE, kevOf: async () => kevMap() });
  assert.equal(down.errors, 1); assert.deepEqual((await flagsOf(s2)).map((f) => f.key), ['distro:debian']);
  assert.equal(emails.length, 0);
  assert.deepEqual(CHECKS, ['kev', 'distro', 'advisory', 'exploitation', 'hygiene', 'archive']);
  assert.ok((await s2.listCardChecks()).every((r) => r.slug !== DIGEST_ROW || r.state.day));
});

test('sweep: the stored state holds flags, keys, dates and line hashes, never page text', async () => {
  captureOutputs();
  const store = memoryStore();
  await sweep(store, widget(), { 'vendor.example.test/advisory/1': html(article(ADVISORY_V1)), 'security-tracker.debian.org': DEBIAN_FIXED });
  const [row] = await store.listCardChecks();
  assert.deepEqual(Object.keys(row.state).sort(), ['advisories', 'asked', 'card_date', 'checked_at', 'claims', 'flags', 'raised']);
  const kept = JSON.stringify(row.state.advisories);
  assert.ok(!kept.includes('Widget Inc thanks'), 'no advisory text is stored');
  assert.ok(Object.values(row.state.advisories).every((a) => a.hashes.every((h) => /^[0-9a-f]{10}$/.test(h))));
  assert.deepEqual(row.state.claims, { distro: { debian: 'unfixed', ubuntu: 'unfixed', redhat: 'unfixed' }, exploitation: 'none', kev: 'not listed', advisories: 4 });
});
