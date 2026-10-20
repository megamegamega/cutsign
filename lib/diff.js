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
