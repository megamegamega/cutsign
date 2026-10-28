// Daily self-check of the public contracts the site and verdict cards depend on.
//   GET /api/selfcheck    Authorization: Bearer $CRON_SECRET  (Vercel cron, see vercel.json)
//
// Today's views are coupled: verdict cards fetch /?q= and /?view=agent JSON on page load,
// the analyst collapse and jump anchor key off render.js markup, and search deep-links off
// story anchors. All of it degrades silently, so this endpoint fails loudly instead: it
// fetches production's own pages, validates each contract, and posts to Discord on any miss.

import { authorized } from '../lib/auth.js';
import { postDiscord } from '../lib/discord.js';
import { CARDS, archiveCandidates } from '../lib/cards.js';
import { supabaseStore } from '../lib/db.js';

const BASE = process.env.SELFCHECK_BASE || 'https://cutsign.vercel.app';

async function get(path) {
  const r = await fetch(BASE + path, { headers: { 'Cache-Control': 'no-cache' } });
  return { status: r.status, text: await r.text() };
}

export default async function handler(req, res) {
  if (!authorized(req)) { res.statusCode = 401; return res.json({ ok: false, error: 'unauthorized' }); }
  const failures = [];
  const check = (cond, label) => { if (!cond) failures.push(label); };

  try {
    // root = CISO view; analyst day page renders with story anchors (search deep links + jump anchor depend on them)
    const root = await get('/');
    check(root.status === 200 && root.text.includes('<span>CISO</span>'), 'GET / -> ' + root.status + ' (expected CISO view)');
    const home = await get('/?view=analyst');
    check(home.status === 200, 'GET /?view=analyst -> ' + home.status);
    check(/<h1>20\d\d-\d\d-\d\d/.test(home.text), '/ missing day <h1>');
    check(home.text.includes('id="s-'), '/ missing story anchors (search deep links broken)');

    // agent JSON: the contract the cards' live-guidance fetch depends on
    const agent = await get('/?view=agent&format=json');
    check(agent.status === 200, 'agent json -> ' + agent.status);
    try {
      const a = JSON.parse(agent.text);
      const s = (a.stories || [])[0] || {};
      check(typeof s.id === 'string' && !!s.brief_date, 'agent json: stories missing id/brief_date');
      check('verdict_card' in s, 'agent json: stories missing verdict_card');
      check(Array.isArray(s.detection_guidance), 'agent json: stories missing detection_guidance[]');
    } catch { failures.push('agent json: not parseable'); }

    // search JSON: the contract the cards' staleness strip + guidance day-list depend on
    const q = await get('/?q=cve&format=json');
    try {
      const sj = JSON.parse(q.text);
      check(sj.kind === 'cutsign.search', 'search json: wrong kind');
      const st = (sj.stories || [])[0];
      check(!st || (typeof st.id === 'string' && 'brief_date' in st), 'search json: stories missing id/brief_date');
      const io = (sj.iocs || [])[0];
      check(!io || Array.isArray(io.stories), 'search json: iocs missing stories[]');
    } catch { failures.push('search json: not parseable'); }

    // corpus JSON
    const iocs = await get('/?view=iocs&format=json');
    try { check(JSON.parse(iocs.text).kind === 'cutsign.iocs', 'iocs json: wrong kind'); }
    catch { failures.push('iocs json: not parseable'); }

    // cards: index lists every manifest slug; each card page serves with its live hooks intact
    const cardsPage = await get('/?view=cards');
    check(cardsPage.status === 200, 'cards view -> ' + cardsPage.status);
    for (const c of CARDS) {
      check(cardsPage.text.includes(`/cards/${c.slug}.html`), `cards view missing ${c.slug}`);
      const page = await get(`/cards/${c.slug}.html`);
      check(page.status === 200, `card ${c.slug} -> ${page.status}`);
      check(page.text.includes('id="pubguid"') && page.text.includes('id="since"'),
        `card ${c.slug} missing live sections (pubguid/since)`);
      check(page.text.includes('Public OSINT only'), `card ${c.slug} missing OSINT footer`);
    }
  } catch (e) {
    failures.push('selfcheck crashed: ' + String(e?.message || e).slice(0, 200));
  }

  if (failures.length) await postDiscord(`Cutsign selfcheck ✖ ${failures.length} failure${failures.length === 1 ? '' : 's'}:\n` + failures.map((f) => '• ' + f).join('\n'));

  // Mondays: nominate quiet cards for archiving (a human decides; nothing changes here)
  let candidates = [];
  if (new Date().getUTCDay() === 1) {
    try {
      const active = CARDS.filter((c) => c.status === 'active');
      const rows = await supabaseStore().watchFacts(active.flatMap((c) => c.story_ids));
      candidates = archiveCandidates(active, rows);
      if (candidates.length) await postDiscord(`Cutsign ▣ ${candidates.length} card${candidates.length === 1 ? '' : 's'} eligible to archive (set status in lib/cards.js):\n` + candidates.map((c) => `• ${c.slug} — ${c.reason}`).join('\n'));
    } catch (e) { failures.push('archive check crashed: ' + String(e?.message || e).slice(0, 200)); }
  }
  return res.json({ ok: failures.length === 0, checked: new Date().toISOString(), failures, archive_candidates: candidates });
}
