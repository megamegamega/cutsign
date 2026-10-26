// Verdict cards: the manifest (lib/cards.js) and the static pages (public/cards/) must agree,
// and every page must keep the hooks the live scripts and site chrome depend on. These are the
// offline halves of api/selfcheck.js, which validates the same contracts against production.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { CARDS, STATUSES, cardByStory, activeCards, archiveCandidates } from '../lib/cards.js';

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
      ['/cards/lifecycle.js', 'lifecycle banner script'],
    ]) assert.ok(t.includes(needle), `${c.slug}: missing ${why} (${needle})`);
    // the live script needs the as-of date to match the manifest date
    assert.ok(t.includes(`AS_OF = '${c.date}'`), `${c.slug}: AS_OF differs from manifest date`);
  }
});

test('lifecycle fields are consistent', () => {
  const slugs = new Set(CARDS.map((c) => c.slug));
  for (const c of CARDS) {
    assert.ok(STATUSES.includes(c.status), `${c.slug}: bad status ${c.status}`);
    if (c.status !== 'active') assert.match(String(c.archived_on), /^\d{4}-\d{2}-\d{2}$/, `${c.slug}: archived cards need archived_on`);
    if (c.superseded_by) { assert.equal(c.status, 'superseded'); assert.ok(slugs.has(c.superseded_by), `${c.slug}: superseded_by unknown slug`); }
  }
  assert.ok(activeCards().length >= 1);
});

test('archive candidates: quiet, watch-expired, 30+ day old cards only', () => {
  const now = Date.parse('2026-12-01T00:00:00Z');
  const cards = [
    { slug: 'old-quiet', status: 'active', date: '2026-10-01', story_ids: ['a'] },
    { slug: 'old-watched', status: 'active', date: '2026-10-01', story_ids: ['b'] },
    { slug: 'old-recent-dev', status: 'active', date: '2026-10-01', story_ids: ['c'] },
    { slug: 'fresh', status: 'active', date: '2026-11-20', story_ids: ['d'] },
    { slug: 'done', status: 'archived', date: '2026-09-01', story_ids: ['e'] },
  ];
  const rows = [
    { story_id: 'a', status: 'expired', last_change_at: '2026-10-05T00:00:00Z' },
    { story_id: 'b', status: 'active', last_change_at: '2026-10-05T00:00:00Z' },
    { story_id: 'c', status: 'expired', last_change_at: '2026-11-25T00:00:00Z' },
  ];
  assert.deepEqual(archiveCandidates(cards, rows, now).map((c) => c.slug), ['old-quiet']);
  assert.match(archiveCandidates(cards, rows, now)[0].reason, /all watches expired/);
});
