// Banner spellings from the model: validated hard (filter list, specific values, no vendor alone,
// no generic word, no scope), cached by input key, never trusted before Shodan counts them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scannerNames, cleanNames, aliasKey, MAX_ALIASES, FILTERS } from '../lib/scannernames.js';
import { installFakeLLM } from './helpers.js';

const products = [
  { part: 'a', vendor: 'cisco', product: 'catalyst_sd-wan_manager', cpe23: 'cpe:2.3:a:cisco:catalyst_sd-wan_manager', ranges: ['< 20.9.8.2'] },
  { part: 'a', vendor: 'arista', product: 'velocloud_orchestrator', cpe23: 'cpe:2.3:a:arista:velocloud_orchestrator', ranges: [] },
];
const affected = ['VeloCloud Orchestrator (CVE-2026-16812)', 'Cisco Catalyst SD-WAN (CVE-2026-20127)', 'Versa Director (CVE-2024-39717)'];

test('cleanNames: keeps specific banner strings, drops vendors alone, generic words, operators, scope and duplicates', () => {
  const keys = products.map((p) => `${p.vendor}:${p.product}`);
  const out = cleanNames([
    { for: 'cisco:catalyst_sd-wan_manager', filter: 'http.title', value: 'Cisco vManage', why: 'former name of Catalyst SD-WAN Manager' },
    { for: 'cisco:catalyst_sd-wan_manager', filter: 'product', value: 'vManage', why: 'former name' },
    { for: 'arista:velocloud_orchestrator', filter: 'http.title', value: ' VeloCloud  Orchestrator ', why: 'console title' },
    { for: 'card', filter: 'http.title', value: 'Versa Director', why: 'console title' },
    { for: 'nobody:knows', filter: 'http.html', value: 'Versa Networks Director', why: 'login page' },
    { for: 'card', filter: 'http.title', value: 'Cisco', why: 'vendor' },                       // vendor alone
    { for: 'card', filter: 'product', value: 'Orchestrator', why: 'generic' },                 // generic alone
    { for: 'card', filter: 'product', value: 'Management Console', why: 'generic words' },  // nothing specific in it
    { for: 'card', filter: 'net', value: '10.0.0.0/8', why: 'scope' },                         // not a listed filter
    { for: 'card', filter: 'http.title', value: 'org:"Example"', why: 'operator' },            // quotes and colon
    { for: 'card', filter: 'http.title', value: 'KACE', why: 'short plain word' },             // too short to be specific
    { for: 'card', filter: 'http.title', value: 'cisco vmanage', why: 'duplicate, other case' },
    { for: 'card', filter: 'product', value: 'Gotenberg', why: 'already a query on the card' },
  ], { keys, vendors: ['cisco', 'arista'], existing: ['product:"Gotenberg"'] });
  assert.deepEqual(out.map((a) => a.query), ['http.title:"Cisco vManage"', 'product:"vManage"', 'http.title:"VeloCloud Orchestrator"', 'http.title:"Versa Director"', 'http.html:"Versa Networks Director"']);
  assert.deepEqual(out.map((a) => a.for), ['cisco:catalyst_sd-wan_manager', 'cisco:catalyst_sd-wan_manager', 'arista:velocloud_orchestrator', 'card', 'card']);
  assert.match(out[0].note, /suggested by the model.*former name of Catalyst SD-WAN Manager.*counted against Shodan before it was shown/);
  assert.ok(out.every((a) => !/net:|org:|hostname:/.test(a.query)));
  assert.equal(cleanNames(Array.from({ length: 20 }, (_, i) => ({ for: 'card', filter: 'http.title', value: `Product Console ${i}`, why: '' }))).length, MAX_ALIASES);
  assert.deepEqual(FILTERS, ['http.title', 'product', 'http.component', 'http.html', 'ssl']);
});

test('scannerNames: one light call, validated, cached on the previous block by key; a failed call costs nothing more than itself', async () => {
  const calls = installFakeLLM(() => ({ names: [
    { for: 'cisco:catalyst_sd-wan_manager', filter: 'http.title', value: 'Cisco vManage', why: 'former name' },
    { for: 'card', filter: 'http.title', value: 'Cisco', why: 'vendor' },
  ] }));
  const r = await scannerNames({ products, affected, title: 'Volt Typhoon relay chain', summary: 'Four zero-days.', existing: ['vuln:CVE-2026-20127'] });
  assert.equal(calls.length, 1); assert.equal(calls[0].schemaName, 'scanner_names'); assert.equal(calls[0].tier, 'light');
  assert.match(calls[0].messages[0].content, /cisco:catalyst_sd-wan_manager — Catalyst Sd-wan Manager \(affected < 20\.9\.8\.2\)/);
  assert.match(calls[0].messages[0].content, /Versa Director \(CVE-2024-39717\)/);
  assert.deepEqual(r.aliases.map((a) => a.query), ['http.title:"Cisco vManage"']);
  assert.ok(r.cost > 0); assert.equal(r.cached, false); assert.equal(r.key, aliasKey({ products, affected, title: 'Volt Typhoon relay chain' }));
  // the same inputs again, with the stored block: no call
  const prev = { aliases: r.aliases, aliases_key: r.key, aliases_model: r.model };
  const again = await scannerNames({ products, affected, title: 'Volt Typhoon relay chain', prev });
  assert.equal(calls.length, 1); assert.equal(again.cached, true); assert.deepEqual(again.aliases, r.aliases); assert.equal(again.cost, 0);
  // a changed card text asks again
  await scannerNames({ products, affected: [...affected, 'Quest KACE'], title: 'Volt Typhoon relay chain', prev });
  assert.equal(calls.length, 2);
  // nothing to name: no call
  assert.deepEqual(await scannerNames({ products: [], affected: [] }), { aliases: [], cost: 0, model: null, key: null, cached: false });
  // the model answering nonsense yields no aliases, not an exception
  installFakeLLM(() => ({ nonsense: true }));
  const bad = await scannerNames({ products, affected, title: 'x' });
  assert.deepEqual(bad.aliases, []); assert.ok(bad.cost > 0);
});
