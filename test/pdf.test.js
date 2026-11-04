// /cards/<slug>.pdf (api/pdf.js): slug checks before anything runs, one cache key per card, hand cards
// printed straight from their page, AI cards only when their page answers, failures never cached.
// Chromium is swapped for a stub and the network for a fake; nothing leaves the process.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/pdf.js';
import { _setRenderer, renderPdf } from '../lib/pdfrender.js';
import { CARDS } from '../lib/cards.js';

const SITE = 'https://cutsign.vercel.app';
const PDF = Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1');
const printed = [];
_setRenderer(async (url) => { printed.push(url); if (url.includes('broken')) throw new Error('page crashed'); return PDF; });
after(() => _setRenderer(null));

const noNet = async () => { throw new Error('no fetch expected'); };
async function get(query, fetchImpl = noNet) {
  const res = { statusCode: 200, headers: {}, body: null, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b ?? null; return this; } };
  await handler({ query }, res, { fetchImpl });
  return res;
}

test('pdf: malformed slugs are a 404 and a cache-buster is sent to the plain URL; neither prints anything', async () => {
  printed.length = 0;
  for (const slug of ['', '../api/cron', 'a/b', 'x'.repeat(81), 'card.html']) {
    const r = await get({ slug });
    assert.equal(r.statusCode, 404, slug); assert.equal(r.headers['cache-control'], 'no-store');
  }
  const r = await get({ slug: CARDS[0].slug, v: '2' });
  assert.equal(r.statusCode, 308); assert.equal(r.headers.location, `/cards/${CARDS[0].slug}.pdf`);
  assert.equal(printed.length, 0);
});

test('pdf: a hand card prints from its .html page without a lookup; the file is cached at the edge', async () => {
  printed.length = 0;
  const card = CARDS[0];
  const r = await get({ slug: card.slug });
  assert.equal(r.statusCode, 200);
  assert.deepEqual(printed, [`${SITE}/cards/${card.slug}.html`]);
  assert.equal(r.headers['content-type'], 'application/pdf');
  assert.equal(r.headers['content-disposition'], `inline; filename="cutsign-${card.slug}.pdf"`);
  assert.match(r.headers['cache-control'], /s-maxage=\d+/);
  assert.ok(r.body.equals(PDF));
});

test('pdf: an AI card prints only when its page answers; an unknown slug never starts the renderer', async () => {
  printed.length = 0;
  const pages = { [`${SITE}/cards/widget-2026`]: 200, [`${SITE}/cards/broken-2026`]: 200, [`${SITE}/cards/nope-2026`]: 404 };
  const net = async (url) => new Response('', { status: pages[String(url)] || 500 });
  const ok = await get({ slug: 'widget-2026' }, net);
  assert.equal(ok.statusCode, 200); assert.deepEqual(printed, [`${SITE}/cards/widget-2026`]);
  const missing = await get({ slug: 'nope-2026' }, net);
  assert.equal(missing.statusCode, 404); assert.equal(printed.length, 1);
  const down = await get({ slug: 'other-2026' }, net);
  assert.equal(down.statusCode, 502); assert.equal(down.headers['cache-control'], 'no-store'); assert.equal(printed.length, 1);
  const unreachable = await get({ slug: 'widget-2026' }, async () => { throw new TypeError('fetch failed'); });
  assert.equal(unreachable.statusCode, 502); assert.equal(printed.length, 1);
  // a render that fails is a 502 nobody caches, and it names the card page instead
  const broken = await get({ slug: 'broken-2026' }, net);
  assert.equal(broken.statusCode, 502); assert.equal(broken.headers['cache-control'], 'no-store');
  assert.match(String(broken.body), /cards\/broken-2026/);
});

test('pdf: the renderer prints pages of this site only', async () => {
  await assert.rejects(renderPdf('https://elsewhere.example.test/cards/x'), /this site only/);
  await assert.rejects(renderPdf(`${SITE}.example.test/cards/x`), /this site only/);
});

test('pdf: Chromium stays in one function — only api/pdf.js imports the renderer, and nothing else names the browser', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  for (const dir of ['api', 'lib']) {
    for (const f of readdirSync(new URL(`../${dir}/`, import.meta.url)).filter((x) => x.endsWith('.js'))) {
      const src = readFileSync(new URL(`../${dir}/${f}`, import.meta.url), 'utf8');
      const path = `${dir}/${f}`;
      if (path !== 'lib/pdfrender.js') assert.ok(!/puppeteer-core|@sparticuz\/chromium/.test(src), `${path} names the browser`);
      if (path !== 'api/pdf.js') assert.ok(!/(?:from\s*|import\(\s*)['"][^'"]*pdfrender\.js['"]/.test(src), `${path} imports the renderer`);
    }
  }
});
