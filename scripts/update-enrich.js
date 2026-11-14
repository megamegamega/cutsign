// Refreshes the two committed files the response-action rules read facts from (lib/enrich.js):
//   lib/topsites.json    the top 10,000 domains of the current Tranco list (https://tranco-list.eu)
//   lib/handenrich.json  owner and registration lookups for the hand-written cards' indicators
// AI cards get theirs from the watch tick (enrichOnlySweep, lib/hype.js). Run: npm run update-enrich
// `--hand` skips the list download.

import { writeFileSync, readFileSync } from 'node:fs';
import { HAND_ACTIONS } from '../lib/handactions.js';
import { wantedKeys, lookup, enrichDue } from '../lib/enrich.js';
import { sharedPlatform } from '../lib/actions.js';

const TOP_COUNT = 10_000;
const out = (name) => new URL(`../lib/${name}`, import.meta.url);
const today = new Date().toISOString().slice(0, 10);

if (!process.argv.includes('--hand')) {
  const id = (await (await fetch('https://tranco-list.eu/top-1m-id')).text()).trim();
  if (!/^[A-Z0-9]{4,8}$/.test(id)) throw new Error(`unexpected Tranco list id: ${id.slice(0, 40)}`);
  const csv = await (await fetch(`https://tranco-list.eu/download/${id}/${TOP_COUNT}`)).text();
  const domains = csv.split(/\r?\n/).map((l) => l.split(',')[1]?.trim().toLowerCase()).filter((d) => d && /^[a-z0-9.-]+\.[a-z0-9-]+$/.test(d));
  if (domains.length < TOP_COUNT * 0.9) throw new Error(`Tranco list came back short: ${domains.length} domains`);
  writeFileSync(out('topsites.json'), `${JSON.stringify({ source: `https://tranco-list.eu/list/${id}`, generated: today, domains })}\n`);
  console.log(`topsites.json: ${domains.length} domains from Tranco list ${id}`);
}

let prev = {};
try { prev = JSON.parse(readFileSync(out('handenrich.json'), 'utf8')).facts || {}; } catch { /* first run */ }
const keys = new Set();
for (const stored of Object.values(HAND_ACTIONS)) for (const k of wantedKeys(stored, { skipHost: sharedPlatform })) keys.add(k);
const facts = {}; const asns = new Map(); let asked = 0; let failed = 0;
const budget = { peeringdb: 500, paceMs: 4000 }; // PeeringDB allows an anonymous caller a few questions a minute
for (const k of [...keys].sort()) {
  if (!enrichDue(prev[k])) { facts[k] = prev[k]; continue; }
  try { facts[k] = await lookup(k, { asns, budget, prev: prev[k] }); asked++; } catch (e) { failed++; if (prev[k] && !prev[k].fail) facts[k] = prev[k]; console.warn(`  no answer for ${k}: ${e.message}`); }
  if (k.startsWith('dom|')) await new Promise((r) => setTimeout(r, 1200)); // rdap.org asks for a slow pace
}
writeFileSync(out('handenrich.json'), `${JSON.stringify({ generated: today, facts }, null, 1)}\n`);
console.log(`handenrich.json: ${Object.keys(facts).length} of ${keys.size} indicators have facts (${asked} asked, ${failed} without an answer)`);
