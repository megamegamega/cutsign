// The Actors tab: attribution read from each story's actor field, title and summary (lib/actors.js)
// and the page drawn from it (lib/actorsview.js). Names and phrasings are the shapes real public
// reporting uses; a language, a stance or a victim never places an actor in a country.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { actorKey, nameBasis, parseActorField, readStory, actorReport } from '../lib/actors.js';
import { actorsBody, worldMap } from '../lib/actorsview.js';
import { memoryStore } from '../lib/store-memory.js';

const TODAY = '2026-11-03';
let n = 0;
const story = (o) => ({ id: `s${String(++n).padStart(3, '0')}-0000-0000`, title: '', summary: '', threat_actor: null, malware_family: null, updates_story_id: null, brief_date: '2026-10-30', ...o });

test('the actor field: aliases, several actors, descriptions and annotations', () => {
  assert.deepEqual(parseActorField('Warp Panda (also Armory Castle, UNC5221, Clay Typhoon, VerdantBamboo)').names,
    [['Warp Panda', 'Armory Castle', 'UNC5221', 'Clay Typhoon', 'VerdantBamboo']]);
  assert.deepEqual(parseActorField('Salt Typhoon; VYPR; Interlock').names, [['Salt Typhoon'], ['VYPR'], ['Interlock']]);
  assert.deepEqual(parseActorField('UNC7228 (STORM-0940)').names, [['UNC7228', 'STORM-0940']]);
  // two vendors' names for one cluster alias; one vendor's two numbers, or a known group beside another, are two actors
  const kz = parseActorField('UAT-6275 / TAG-193 (suspected Kazakhstan-linked)');
  assert.deepEqual(kz.names, [['UAT-6275', 'TAG-193']]);
  assert.ok(kz.cues.includes('suspected Kazakhstan-linked'));
  assert.deepEqual(parseActorField('Storm-2990 / Storm-3119 (YAM Store)').names, [['Storm-2990'], ['Storm-3119', 'YAM Store']]);
  assert.deepEqual(parseActorField('UAC-0099 / Sandworm').names, [['UAC-0099'], ['Sandworm']]);
  // descriptive words fall away from a name and become cues; an annotation is never an alias
  assert.deepEqual(parseActorField('INC and The Gentlemen ransomware affiliates (Russian-speaking, as assessed)').names, [['INC'], ['The Gentlemen']]);
  assert.deepEqual(parseActorField('Artem Aleksandrovych Stryzhak (Hive and Nefilim affiliate)').names, [['Artem Aleksandrovych Stryzhak']]);
  assert.deepEqual(parseActorField('APT41 (medium confidence, per Kaspersky)').names, [['APT41']]);
  // a description names no one
  for (const d of ['Suspected China-nexus actor (unnamed)', 'Belarus-linked actors (unnamed)', 'North Korean IT worker operations',
    'Financially motivated, Chinese-speaking operator (attribution per Pluto Security)', 'Serbian government (as alleged by researchers)']) {
    assert.deepEqual(parseActorField(d).names, [], d);
  }
});

test('names: one key per actor however it is written, and what a name alone says', () => {
  assert.equal(actorKey('ARMORY CASTLE'), actorKey('Armory Castle'));
  assert.equal(actorKey('Lazarus Group'), actorKey('Lazarus'));
  assert.equal(actorKey('The Gentlemen'), actorKey('Gentlemen'));
  assert.equal(nameBasis('Volt Typhoon').cc, 'CN');
  assert.equal(nameBasis('FANCY BEAR').cc, 'RU');
  assert.equal(nameBasis('Bronze Sandcastle').cc, 'CN');
  assert.equal(nameBasis('Jade Sleet').cc, 'KP');
  assert.equal(nameBasis('Muddled Libra').cat, 'crime');
  assert.equal(nameBasis('CL-STA-0954').cat, 'state');
  assert.equal(nameBasis('CL-STA-0954').cc, null);
  assert.equal(nameBasis('UNC7228'), null);
});

test('a language, a stance, a victim or a government\'s policy places no actor in a country', () => {
  const none = (s) => {
    const r = readStory(story(s));
    const ccs = [...r.actors.flatMap((a) => a.basis.map((b) => b.cc)), ...(r.unnamed?.basis || []).map((b) => b.cc)].filter(Boolean);
    assert.deepEqual(ccs, [], JSON.stringify(s));
  };
  none({ threat_actor: 'Storm-2990 / Storm-3119 (YAM Store)', summary: 'Microsoft detailed a Chinese-language PhaaS ecosystem: Storm-2990 develops kits.' });
  none({ threat_actor: 'Black Spark', title: "Black Spark hacktivists disrupt Russia's Edutest school platform", summary: 'Pro-Ukrainian hacktivist group Black Spark claimed the outage.' });
  none({ threat_actor: 'INC and The Gentlemen ransomware affiliates (Russian-speaking, as assessed)' });
  none({ title: 'South Korean police identify seven suspects in ARTEX AI-assisted breaches of 90+ organizations' });
  none({ title: 'DHS orders DeepSeek products removed from federal civilian agencies', summary: 'The order cites concerns about Chinese government access to DeepSeek infrastructure.' });
  none({ threat_actor: 'Hotejka', summary: 'The TDS feeds the Russian-language affiliate program Hotejka.' });
  none({ title: 'Attackers hit US-based hospitals and a Russian healthcare organization', summary: 'Arctic Wolf researchers saw the intrusions.' });
  none({ title: 'Democrat lawmakers say Russia, China, Iran and North Korea running influence ops ahead of midterms' });
});

test('the sources\' own words attach a country to a name, and a story naming no one counts one unnamed actor', () => {
  const r = readStory(story({ threat_actor: 'UNC7228 (STORM-0940)', title: 'Threat actors incl. PRC-nexus UNC7228 use agentic frameworks ARTEX, PentAGI, CAIRN' }));
  assert.ok(r.actors[0].basis.some((b) => b.cc === 'CN' && /PRC-nexus UNC7228/.test(b.text)));
  const iran = readStory(story({ threat_actor: 'Prince of Persia (Infy)', summary: 'Semperis reports that Iranian state-sponsored Prince of Persia (also tracked as Infy) resumed.' }));
  assert.ok(iran.actors[0].basis.some((b) => b.cc === 'IR' && /Iranian state-sponsored Prince of Persia/.test(b.text)));
  const after = readStory(story({ threat_actor: 'Bronze Sandcastle', summary: 'Researchers disclosed Bronze Sandcastle, a China-aligned espionage cluster.' }));
  assert.ok(after.actors[0].basis.some((b) => b.cc === 'CN' && b.rank === 4));
  const kp = readStory(story({ title: 'North Korean threat actors use AI across lures, personas, and tooling' }));
  assert.equal(kp.unnamed.basis[0].cc, 'KP');
  // …but not when the story names that country's actors itself
  const named = readStory(story({ title: 'North Korean threat actors use AI across lures', summary: 'Microsoft reports multiple North Korean actors (Jade Sleet, Onyx Sleet) used it.' }));
  assert.deepEqual(named.actors.map((a) => a.aliases[0]), ['Jade Sleet', 'Onyx Sleet']);
  assert.equal(named.unnamed, null);
});

// a small corpus in the shape the store returns
function corpus() {
  n = 0;
  const c = story({ threat_actor: 'Storm-0940', title: 'Storm-0940 uses ARTEX agentic AI in ConnectWise Cloud Backup supply chain compromise', malware_family: 'ARTEX', brief_date: '2026-10-22' });
  return [
    story({ threat_actor: 'Warp Panda', title: 'China-nexus Warp Panda exploited VMware ESXi logging flaw', brief_date: '2026-10-29' }),
    story({ threat_actor: 'ARMORY CASTLE', title: 'BeyondTrust Remote Support zero-day exploited by ARMORY CASTLE', summary: 'Exploited by suspected PRC-nexus actor ARMORY CASTLE (UNC5221/Warp Panda).', brief_date: '2026-10-16' }),
    c,
    story({ threat_actor: 'UNC7228 (STORM-0940)', title: 'Threat actors incl. PRC-nexus UNC7228 use agentic frameworks ARTEX, PentAGI, CAIRN', malware_family: 'ARTEX', updates_story_id: c.id, brief_date: '2026-11-02' }),
    story({ title: 'North Korean threat actors use AI across lures, personas, and tooling, including the ARTEX agentic pentest framework',
      summary: 'Microsoft reports multiple North Korean actors (Jade Sleet, Onyx Sleet) used AI.', brief_date: '2026-10-30' }),
    story({ threat_actor: 'TraderTraitor', title: "FBI attributes crypto theft to North Korea's TraderTraitor", summary: 'The FBI says TraderTraitor (Lazarus, APT38) laundered the funds.', brief_date: '2026-11-02' }),
    story({ title: 'South Korean police identify seven suspects in ARTEX AI-assisted breaches of 90+ organizations', brief_date: '2026-10-27' }),
    story({ threat_actor: 'INC and The Gentlemen ransomware affiliates (Russian-speaking, as assessed)', title: 'Ransomware affiliates deploy new tooling', brief_date: '2026-10-26' }),
    story({ threat_actor: 'Black Spark', title: "Black Spark hacktivists disrupt Russia's Edutest school assessment platform", brief_date: '2026-10-21' }),
    story({ threat_actor: 'Lazarus Group', title: 'Lazarus campaign delivers Cubridge backdoor to South Korean firms', brief_date: '2026-10-22' }),
    story({ title: 'DHS orders DeepSeek products removed', summary: 'The order cites concerns about Chinese government access.', brief_date: '2026-10-21' }),
    story({ threat_actor: 'Brazilian credit card skimming group (unnamed)', title: 'Attackers skim card data on Brazilian checkouts', brief_date: '2026-10-28' }),
    story({ threat_actor: 'Salt Typhoon; VYPR; Interlock', malware_family: 'VYPR ransomware; BadCandy', title: 'Salt Typhoon, VYPR ransomware and Interlock target telecoms', brief_date: '2026-10-30' }),
    story({ threat_actor: 'Volt Typhoon', title: 'Volt Typhoon returns', brief_date: '2026-08-01' }),
  ];
}

test('the report: countries, adversaries, stories as update chains, and the tools seen across them', () => {
  const r = actorReport(corpus(), { days: 30, today: TODAY });
  const cc = (x) => r.countries.find((c) => c.cc === x);
  assert.deepEqual(r.countries.map((c) => c.cc), ['CN', 'KP', 'BR']);
  // Warp Panda and ARMORY CASTLE are one actor (UNC5221/Warp Panda in the summary), two stories;
  // Storm-0940 and its update are one story
  assert.deepEqual(cc('CN').actors.map((a) => [a.name, a.stories]), [['Warp Panda', 2], ['Salt Typhoon', 1], ['Storm-0940', 1]]);
  assert.equal(cc('CN').stories, 4);
  assert.ok(cc('CN').actors[0].aliases.includes('ARMORY CASTLE'));
  // TraderTraitor and Jade Sleet are one actor under two vendors' names; "TraderTraitor (Lazarus,
  // APT38)" names three settled groups and merges none of them; the AI story's named actors leave
  // no unnamed one behind
  assert.deepEqual(cc('KP').actors.map((a) => a.name).sort(), ['APT38', 'Lazarus Group', 'Onyx Sleet', 'TraderTraitor']);
  const tt = cc('KP').actors.find((a) => a.name === 'TraderTraitor');
  assert.deepEqual(tt.aliases, ['Jade Sleet']);
  assert.equal(cc('KP').actors.find((a) => a.name === 'Lazarus Group').stories, 2);
  assert.deepEqual(cc('KP').actors.find((a) => a.name === 'Lazarus Group').aliases, [], 'Lazarus is Lazarus Group, not an alias');
  assert.deepEqual(cc('CN').actors.find((a) => a.name === 'Storm-0940').aliases, ['UNC7228'], 'STORM-0940 is Storm-0940, not an alias');
  assert.equal(cc('KP').adversaries, 4);
  assert.equal(cc('BR').actors[0].category, 'crime');
  assert.equal(cc('BR').actors[0].unnamed, true);
  // kinds without a country are listed, not mapped
  assert.deepEqual(r.no_country.crime.map((a) => a.name).sort(), ['INC', 'Interlock', 'The Gentlemen', 'VYPR']);
  assert.deepEqual(r.no_country.hacktivist.map((a) => a.name), ['Black Spark']);
  // ARTEX: three stories (the Storm-0940 chain once), across China, North Korea and one story attributing no one
  const artex = r.tools.find((t) => t.name === 'ARTEX');
  assert.equal(artex.stories, 3);
  assert.deepEqual(artex.by.map((b) => [b.cc, b.stories]), [['CN', 1], ['KP', 1], [null, 1]]);
  // an actor outside the window is not counted in it, and is in "all"
  assert.ok(!cc('CN').actors.some((a) => a.name === 'Volt Typhoon'));
  const all = actorReport(corpus(), { days: null, today: TODAY });
  assert.ok(all.countries.find((c) => c.cc === 'CN').actors.some((a) => a.name === 'Volt Typhoon'));
  // a kind filter keeps only that kind's actors
  assert.deepEqual(actorReport(corpus(), { days: 30, category: 'crime', today: TODAY }).countries.map((c) => c.cc), ['BR']);
  assert.ok(r.countries.every((c) => c.actors.every((a) => a.basis.length || a.unnamed)), 'every attribution says why');
});

test('the trend: Monday weeks from the first stored brief, and the last 7 days against the 7 before', () => {
  n = 0;
  const rows = [
    story({ threat_actor: 'Volt Typhoon', brief_date: '2026-10-15' }),
    story({ threat_actor: 'Salt Typhoon', brief_date: '2026-10-23' }),
    story({ threat_actor: 'Flax Typhoon', brief_date: '2026-10-28' }),
    story({ threat_actor: 'APT41', brief_date: '2026-11-02' }),
    story({ threat_actor: 'Warp Panda', brief_date: '2026-11-03' }),
  ];
  const r = actorReport(rows, { days: 30, today: TODAY });
  assert.deepEqual(r.weeks, ['2026-10-12', '2026-10-19', '2026-10-26', '2026-11-02']);
  const cn = r.countries[0];
  assert.deepEqual(cn.weekly, [1, 1, 1, 2]);
  assert.equal(cn.last7, 3); // Oct 28, Nov 2, Nov 3
  assert.equal(cn.prev7, 1); // Oct 23
  // with under two weeks of briefs there is nothing honest to compare against
  assert.equal(actorReport(rows.slice(3), { days: 30, today: TODAY }).countries[0].prev7, null);
});

test('the page: map shaded and linked to each country\'s card, cards, tools, and the method', () => {
  const r = actorReport(corpus(), { days: 30, today: TODAY });
  const html = actorsBody(r, { w: '30', cat: null, m: 'stories' });
  assert.ok(worldMap(), 'lib/worldmap.json loads');
  assert.match(html, /<svg viewBox="0 0 1000 \d+" role="img" aria-label="World map shaded by stories attributed to each country: China 4, North Korea 3, Brazil 1"/);
  assert.match(html, /<a href="#c-cn"><path class="am-c am-s5"/);
  assert.match(html, /<div class="am-card" id="c-cn">/);
  assert.match(html, /<td><a href="\/\?q=ARTEX">ARTEX<\/a><\/td><td>3 stories<\/td>/);
  assert.match(html, /How attribution is read/);
  assert.match(html, /<span>30 days<\/span>/); // the window in force is the one not linked
  assert.match(html, /href="\/\?view=actors&amp;w=90"/);
  // by stories China (4) leads; shaded by adversaries the cards follow that count: North Korea (4) over China (3)
  assert.ok(html.indexOf('id="c-cn"') < html.indexOf('id="c-kp"'));
  const adv = actorsBody(r, { w: '30', cat: null, m: 'adversaries' });
  assert.ok(adv.indexOf('id="c-kp"') < adv.indexOf('id="c-cn"'));
  assert.doesNotMatch(html, /undefined|NaN/);
  // an empty corpus renders the empty state, not an error
  assert.match(actorsBody(actorReport([], { days: 30, today: TODAY }), { w: '30', cat: null, m: 'stories' }), /No story in this window names an adversary/);
});

test('the store: sent, non-dry runs only, and one run per brief date (the newest)', async () => {
  const store = memoryStore();
  const t = store._tables;
  t.briefs.push({ id: 'b1', brief_date: '2026-10-30' }, { id: 'b2', brief_date: '2026-10-31' });
  t.runs.push({ id: 'r-old', brief_id: 'b1', stage: 'sent', dry: false, started_at: '2026-10-30T11:00:00Z' },
    { id: 'r-new', brief_id: 'b1', stage: 'sent', dry: false, started_at: '2026-10-30T12:00:00Z' },
    { id: 'r-dry', brief_id: 'b2', stage: 'sent', dry: true, started_at: '2026-10-31T11:00:00Z' });
  for (const [id, run] of [['x1', 'r-old'], ['x2', 'r-new'], ['x3', 'r-dry']]) {
    t.stories.push({ id, run_id: run, status: 'extracted', title: id, summary: '', threat_actor: 'APT41', malware_family: null, created_at: '2026-10-30T12:00:00Z' });
  }
  const rows = await store.listActorStories();
  assert.deepEqual(rows.map((r) => [r.id, r.brief_date]), [['x2', '2026-10-30']]);
});

test('the page handler module loads', async () => {
  const mod = await import('../api/page.js');
  assert.equal(typeof mod.default, 'function');
});
