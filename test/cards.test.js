// Verdict cards: the manifest (lib/cards.js) and the static pages (public/cards/) must agree,
// and every page must keep the hooks the live scripts and site chrome depend on. These are the
// offline halves of api/selfcheck.js, which validates the same contracts against production.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { CARDS, cardByStory } from '../lib/cards.js';

const dir = new URL('../public/cards/', import.meta.url);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

test('every manifest card has a page, and every page is in the manifest', () => {
  const files = readdirSync(dir).filter((f) => f.endsWith('.html'));
  const slugs = CARDS.map((c) => c.slug);
  assert.deepEqual(new Set(files), new Set(slugs.map((s) => `${s}.html`)));
  assert.equal(new Set(slugs).size, slugs.length, 'duplicate slug');
});

test('manifest entries are well-formed and story ids are unique UUIDs', () => {
  for (const c of CARDS) {
    assert.ok(c.title && c.lane && c.summary, `${c.slug}: title/lane/summary required`);
    assert.match(c.date, /^\d{4}-\d{2}-\d{2}$/, `${c.slug}: bad date`);
    for (const id of c.story_ids) assert.match(id, UUID, `${c.slug}: bad story id ${id}`);
    for (const v of c.cves) assert.match(v, /^CVE-\d{4}-\d{4,}$/, `${c.slug}: bad CVE ${v}`);
  }
  assert.equal(cardByStory.size, CARDS.flatMap((c) => c.story_ids).length, 'story id mapped to two cards');
});

test('every card page keeps the blocks the live scripts and format depend on', () => {
  for (const c of CARDS) {
    const t = readFileSync(new URL(`${c.slug}.html`, dir), 'utf8');
    for (const [needle, why] of [
      ['<!doctype html>', 'standalone page'],
      ['id="pubguid"', 'live published-guidance target'],
      ['id="since"', 'live staleness-strip target'],
      [`QUERY = '`, 'live-fetch topic'],
      ['Inferred detections', 'inferred section'],
      ['@media print', 'print CSS'],
      ['print-color-adjust:exact', 'dark PDF'],
      ['Public OSINT only', 'OSINT footer'],
      ['/?view=cards', 'back link to cards index'],
    ]) assert.ok(t.includes(needle), `${c.slug}: missing ${why} (${needle})`);
    // the live script needs the as-of date to match the manifest date
    assert.ok(t.includes(`AS_OF = '${c.date}'`), `${c.slug}: AS_OF differs from manifest date`);
  }
});
