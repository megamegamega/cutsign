// Refresh lib/attack-ids.json from MITRE's ATT&CK Enterprise STIX bundle (~45 MB download).
// Valid = attack-pattern objects that are neither revoked nor deprecated. Run when ATT&CK ships a
// release (twice a year); the result is committed so CI and runs never need the network for it.
//   npm run update-attack

import { writeFileSync } from 'node:fs';

const URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const bundle = await (await fetch(URL)).json();
const ids = {};
let version = null;
for (const o of bundle.objects) {
  if (o.type === 'x-mitre-collection') version = o.x_mitre_version;
  if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
  const ref = (o.external_references || []).find((r) => r.source_name === 'mitre-attack');
  if (ref?.external_id) ids[ref.external_id] = o.name;
}
const sorted = Object.fromEntries(Object.entries(ids).sort(([a], [b]) => a.localeCompare(b)));
writeFileSync(new globalThis.URL('../lib/attack-ids.json', import.meta.url),
  JSON.stringify({ version, fetched: new Date().toISOString().slice(0, 10), techniques: sorted }, null, 0) + '\n');
console.log(`ATT&CK v${version}: ${Object.keys(sorted).length} techniques`);
