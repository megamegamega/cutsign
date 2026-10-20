// Which stories earn the deep (Opus) read. Decided AFTER the cheap light read of every item, from what
// the sources actually contained — not from the brief's section headings. Pure function, no I/O.
//
// Weights (tune here; the email shows each deep story's score and reasons):
//   behaviors       vendor-stated 3 each, inferred 1 each (max 5 counted)
//   evidence        2 per printed sample (max 5)
//   guidance        2 per published detection item (max 3)
//   IoCs            1 per 3 (max 3)
//   KEV             +3          primary source fetched  +2      financial/all-sector  +1
//   light priority  P1 +2, P2 +1           brief severity  Critical +2, High +1
//   unconfirmed / single roundup           −3
//
// pickDeep never deep-reads a story the light read rated P3 (awareness only — e.g. research about AI models
// whose "behaviors" aren't an adversary's), and never gives two deep slots to the same campaign (shared CVE,
// or same actor + malware).

import { isPrimary } from './fetch-source.js';

const cap = (n, max) => Math.min(n, max);

export function scoreStory({ story, behaviors = [], evidence = [], iocCount = 0, sources = [] }) {
  const why = [];
  let score = 0;
  const add = (pts, label) => { if (pts) { score += pts; why.push(`${pts > 0 ? '+' : ''}${pts} ${label}`); } };

  const stated = behaviors.filter((b) => b.vendor_stated).length;
  const inferred = behaviors.length - stated;
  const counted = cap(behaviors.length, 5);
  const statedCounted = cap(stated, counted);
  add(statedCounted * 3 + (counted - statedCounted) * 1, `${behaviors.length} behavior${behaviors.length === 1 ? '' : 's'}${inferred ? ` (${inferred} inferred)` : ''}`);
  const samples = evidence.filter((e) => e.kind !== 'guidance').length;
  const guidance = evidence.filter((e) => e.kind === 'guidance').length;
  add(cap(samples, 5) * 2, `${samples} evidence sample${samples === 1 ? '' : 's'}`);
  add(cap(guidance, 3) * 2, `${guidance} detection guidance`);
  add(cap(Math.floor(iocCount / 3), 3), `${iocCount} IoCs`);

  const text = `${story.brief_text || ''} ${story.summary || ''}`;
  if (/\bKEV\b|known exploited vulnerabilit/i.test(text)) add(3, 'KEV');
  if (sources.some((s) => isPrimary(s.final_url || s.url))) add(2, 'primary source');
  if ((story.sector_relevance || []).some((t) => /financ|bank|all/i.test(t))) add(1, 'financial relevance');
  if (story.priority === 1) add(2, 'light read P1'); else if (story.priority === 2) add(1, 'light read P2');
  if (story.severity === 'Critical') add(2, 'Critical'); else if (story.severity === 'High') add(1, 'High');
  if (/\bunconfirmed\b|this roundup is the only source|roundup/i.test(story.brief_text || '')) add(-3, 'unconfirmed/roundup');

  return { score, why };
}

/**
 * Rank scored stories and pick up to `max` with score ≥ `min`. Ties break on brief order.
 * @param scored [{ story, score, why }]
 */
export function pickDeep(scored, { max = 6, min = 6 } = {}) {
  const picked = [];
  for (const s of [...scored].filter((x) => x.score >= min && x.story.priority !== 3).sort((a, b) => b.score - a.score || a.story.ordinal - b.story.ordinal)) {
    if (picked.length >= max) break;
    if (picked.some((p) => sameCampaign(p.story, s.story))) continue; // a second write-up of the same thing
    picked.push(s);
  }
  return picked;
}

const low = (x) => String(x || '').trim().toLowerCase();
function sameCampaign(a, b) {
  const ca = new Set((a.cves || []).map((c) => c.toUpperCase()));
  if ((b.cves || []).some((c) => ca.has(c.toUpperCase()))) return true;
  return !!(low(a.threat_actor) && low(a.threat_actor) === low(b.threat_actor) && low(a.malware_family) && low(a.malware_family) === low(b.malware_family));
}
