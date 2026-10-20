// ATT&CK Enterprise technique-ID validation against the committed mirror (lib/attack-ids.json,
// refreshed by `npm run update-attack`). Revoked and deprecated techniques are not in the mirror.

import { readFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('./attack-ids.json', import.meta.url), 'utf8'));
export const ATTACK_VERSION = data.version;

export const isValidTechnique = (id) => typeof id === 'string' && Object.hasOwn(data.techniques, id.trim().toUpperCase());
export const techniqueName = (id) => data.techniques[String(id || '').trim().toUpperCase()] || null;
export const normTechnique = (id) => String(id || '').trim().toUpperCase();
