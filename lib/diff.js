// Day-over-day diffing. Pure functions, no I/O.
//
// Story updates: most of the brief is running coverage of the same campaigns. A story is an "update"
// of a prior one (trailing 14 days) when they share a CVE, OR name the same specific malware family,
// OR name the same threat actor AND share at least one IoC. (Actor alone is too loose — APT28 runs
// many unrelated campaigns.)
//
// Behavior novelty: a behavior is "seen before" when an earlier behavior has the same pattern_kind,
// the same parent (or both unknown), and children sets overlapping by at least half (Jaccard ≥ 0.5) —
// sources describe the same tradecraft with slightly different command lists day to day.

const norm = (x) => String(x ?? '').toLowerCase().replace(/[^a-z0-9.]+/g, ' ').trim();

// Families too generic to identify a campaign on their own.
const GENERIC_MALWARE = new Set(['', 'unknown', 'none', 'n a', 'ransomware', 'backdoor', 'webshell', 'web shell', 'rat',
  'infostealer', 'stealer', 'loader', 'cryptominer', 'miner', 'xmrig', 'cobalt strike', 'mimikatz', 'implant', 'trojan']);

export function storyKeys(s) {
  const malware = norm(s.malware_family);
  return {
    cves: new Set((s.cves || []).map((c) => String(c).toUpperCase())),
    actor: norm(s.threat_actor) || null,
    malware: GENERIC_MALWARE.has(malware) ? null : malware,
  };
}

/** Stable text fingerprint (stored on stories.fingerprint). */
export function fingerprint(s) {
  const k = storyKeys(s);
  return [...[...k.cves].sort().map((c) => `cve:${c}`), k.actor && `actor:${k.actor}`, k.malware && `malware:${k.malware}`]
    .filter(Boolean).join('|') || null;
}

/**
 * Find the prior story this one updates.
 * @param story  { cves, threat_actor, malware_family }
 * @param iocIds Set of this story's IoC ids
 * @param priors [{ story, iocIds:Set }] from other runs, any order
 * @returns the most recent matching prior story, or null
 */
export function findUpdatedStory(story, iocIds, priors) {
  const k = storyKeys(story);
  const hits = priors.filter(({ story: p, iocIds: pIocs }) => {
    const pk = storyKeys(p);
    if ([...k.cves].some((c) => pk.cves.has(c))) return true;
    if (k.malware && k.malware === pk.malware) return true;
    if (k.actor && k.actor === pk.actor && [...iocIds].some((id) => pIocs.has(id))) return true;
    return false;
  });
  hits.sort((a, b) => String(b.story.created_at).localeCompare(String(a.story.created_at)));
  return hits[0]?.story || null;
}

/**
 * Same-brief siblings: two items in one brief that are one campaign by the rule above (a brief
 * often carries two outlets' takes on a story, hours apart, and the model rates each item alone).
 * The later item — by first publication, then brief order — updates the earlier one, so the chain
 * stays linear even when the earlier item already updates yesterday's row; and a group takes its
 * strongest priority, with the reason saying so. Pure.
 * @param stories this run's extracted rows (priority, priority_reason, ordinal, first_published_at, created_at, cves, threat_actor, malware_family)
 * @param iocsOf  id → Set of IoC ids
 * @returns Map id → the fields to change: { updates_story_id } and/or { priority, priority_reason }
 */
export function linkSiblings(stories, iocsOf = () => new Set()) {
  const key = (s) => `${s.first_published_at || '9999-99-99'}|${String(s.ordinal ?? 0).padStart(6, '0')}|${s.created_at || ''}`;
  const sorted = [...stories].sort((a, b) => key(a).localeCompare(key(b)));
  const patch = new Map();
  const parent = new Map();
  const earlier = []; // as priors for findUpdatedStory; created_at stands in as the order key so "most recent" is the nearest earlier sibling
  for (const s of sorted) {
    const hit = findUpdatedStory(s, iocsOf(s.id), earlier);
    if (hit) { parent.set(s.id, hit.id); patch.set(s.id, { updates_story_id: hit.id }); }
    earlier.push({ story: { ...s, created_at: key(s) }, iocIds: iocsOf(s.id) });
  }
  const rootOf = (id) => { let cur = id; const seen = new Set(); while (parent.has(cur) && !seen.has(cur)) { seen.add(cur); cur = parent.get(cur); } return cur; };
  const groups = new Map();
  for (const s of sorted) { const r = rootOf(s.id); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(s); }
  for (const rows of groups.values()) {
    const best = Math.min(...rows.map((s) => s.priority ?? 3));
    for (const s of rows) {
      if ((s.priority ?? 3) <= best) continue;
      patch.set(s.id, { ...(patch.get(s.id) || {}), priority: best, priority_reason: `${s.priority_reason || ''} (raised to P${best}: the same brief carries a P${best} item on this campaign)`.trim() });
    }
  }
  return patch;
}

const childSet = (b) => new Set((b.children || []).map(norm).filter(Boolean));
function jaccard(a, b) {
  if (!a.size && !b.size) return 1;
  let inter = 0; for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

export function sameBehavior(a, b) {
  return a.pattern_kind === b.pattern_kind && norm(a.parent) === norm(b.parent) && jaccard(childSet(a), childSet(b)) >= 0.5;
}

/** True if no prior behavior matches. */
export const isNovelBehavior = (b, priorBehaviors) => !priorBehaviors.some((p) => sameBehavior(b, p));
