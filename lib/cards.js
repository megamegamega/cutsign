// Hand-curated verdict cards: one-page patch/incident verdicts served statically from
// public/cards/. Each entry maps a card to the extracted stories it covers, so story
// cards across the site (CISO view, IoC corpus, search) link to it — and the card
// links back to the live pipeline views. Public OSINT only, like everything here.
//
// Lifecycle: status 'active' (default) → 'archived' (page stays at its URL with a banner, leaves
// the Cards tab's main list and the hunt scope) → 'superseded' (archived + forward link to the
// successor card). Archiving is a human call; selfcheck only nominates candidates.
export const STATUSES = ['active', 'archived', 'superseded'];
const RAW = [
  {
    slug: 'beyondtrust-rs-2026',
    title: 'BeyondTrust Remote Support zero-day',
    date: '2026-10-23',
    lane: 'Hunt / IR + patch',
    summary: 'CVE-2026-102764 (BT26-05, CVSS 9.3) auth bypass exploited as a zero-day since late August by China-nexus ARMORY CASTLE (UNC5221): SAWFLY webshell, root via SUID, vault dump, reboot-surviving persistence. KEV Oct 16, federal deadline Oct 19. Assume-compromise for internet-facing appliances: hunt back to August, rotate the vault on any hit.',
    cves: ['CVE-2026-102764'],
    story_ids: ['10ee4006-d94c-4281-b4fe-338b8d012b81', '46453ee2-c47e-4337-9eb6-3601b097329d', '0534fe69-c7fd-47d2-a976-f962febb32e2'],
  },
  {
    slug: 'litellm-2026',
    title: 'LiteLLM 1.107.0 supply chain compromise',
    date: '2026-10-23',
    lane: 'Hunt + rotate',
    summary: 'Hijacked release workflow published a backdoored 1.107.0 to PyPI/Docker/GHCR on Oct 21 (~2h window): privcollect credential stealer runs at every Python start plus an hourly remote-code loader; stolen AWS creds confirmed abused (Bedrock/LLMjacking). If installed: isolate, rebuild, rotate everything. Socket flagged in ~50 min; OSV MAL-2026-2144 — SCA is the detection here.',
    cves: [],
    story_ids: ['95781545-2701-4c98-9db2-70eea2c6612a'],
  },
  {
    slug: 'm365-token-spray-2026',
    title: 'M365 token spray & replay campaign',
    date: '2026-10-23',
    lane: 'Hunt + harden',
    summary: 'Ten weeks of AiTM/device-code phishing capturing post-MFA sessions, replayed from 1337 Services /24: 497 successful sign-ins at 79 orgs, rogue Entra devices, MFA wipe-and-replace, hidden inbox rules for BEC/payroll fraud. Nothing to patch — properly scoped Conditional Access blocked it cold in four orgs; hunt the four behavior families and close CA gaps.',
    cves: [],
    story_ids: ['afb32de0-9381-4521-85d7-67321ef4c2bf'],
  },
  {
    slug: 'connectwise-m365-2026',
    title: 'ConnectWise Cloud Backup supply chain compromise',
    date: '2026-10-25',
    lane: 'Hunt / IR lane',
    summary: 'Stolen vendor app credentials minted Graph tokens across ~2,250 M365 tenants from Oct 15; Storm-0940 (China-aligned) via ARTEX agentic AI per Microsoft. No CVE — identity abuse: hunt the seven appIds (ex-customers too, per Sophos), review Entra audit since Oct 13. Microsoft + Huntress hunting content published.',
    cves: [],
    story_ids: ['e0286e2a-ef30-405c-b9ab-ed8fb6683b0a', '049583b9-bec9-4b9a-bf42-6154f5fe2bff'],
  },
  {
    slug: 'php2shell-2026',
    title: 'PHP2Shell emergency release',
    date: '2026-10-23',
    lane: 'Patch now + hunt',
    summary: 'Two unauthenticated RCEs in PHP core (CVE-2026-109618/109619, CVSS 9.2), leaked pre-disclosure, patched Oct 21 (8.5.12/8.4.27/8.3.36/8.2.35; EOL ≤8.1 gets no fix). Exploited in the wild (watchTowr); mass probing (Cloudflare: millions), Potassium botnet delivery attempts. Concrete hunt behaviors published.',
    cves: ['CVE-2026-109618', 'CVE-2026-109619'],
    story_ids: ['de24631e-e064-4ef2-a1a6-3fc5d22b027a', '85470616-e08f-4ec7-8108-9aa0d9495eb0', 'cd8144ae-4cd7-4330-a746-37fddc1309b8', 'd3d16df5-ae79-4ab0-99e9-7a26ba55d23d'],
  },
  {
    slug: 'gitlab-onigmo-2026',
    title: 'GitLab 19.5.1 critical release',
    date: '2026-10-23',
    lane: 'Patch lane',
    summary: 'CVSS 10.0 unauthenticated RCE (CVE-2026-110264) in the bundled Onigmo regex engine, reaching every self-managed release since 7.0. Patch trap: Oct 12 patches do not cover it. Public PoC circulating; no exploitation reported; GitLab shipped two Sigma detections; scanners had nothing published as of Oct 23.',
    cves: ['CVE-2026-110264'],
    story_ids: ['82bfed65-97f1-422b-8cef-3f7a8deada7e'],
  },
  {
    slug: 'emudhra-distrust-2026',
    title: 'eMudhra CA distrust',
    date: '2026-10-23',
    lane: 'Prepare lane',
    summary: 'Eight eMudhra intermediate CA certs with trivially recoverable keys (one key was the number 4); browsers blocked Oct 17–20, Chrome removes the emSign G3 root Oct 27 — expect PKIX breakage. No malicious use observed: certificate inventory and replacement, not hunting. Talos Snort SIDs 67363–67374.',
    cves: ['CVE-2026-111943'],
    story_ids: ['4436ad95-58c0-41be-bb51-1fc0e9c704d3', 'f3e86a49-604a-4191-832e-eb742e61a5f6'],
  },
  {
    slug: 'nodejs-oct-2026',
    title: 'Node.js October security releases',
    date: '2026-10-23',
    lane: 'Patch lane',
    summary: '10 CVEs fixed 2026-10-21 (4 high). Brotli decoder OOB write (CVE-2026-111497) demonstrated as code execution — no ITW exploitation, not in KEV, no vendor workarounds. Detection coverage: Qualys QID 389117 only; Tenable/Rapid7/EDR/WAF/container scanners had published nothing as of Oct 23.',
    cves: ['CVE-2026-111497'],
    story_ids: ['4284b37b-90df-4250-a4f7-15aad7237db3', '61b5d25c-e0eb-4f68-bcec-756b143eaf57'],
  },
];

export const CARDS = RAW.map((c) => ({ status: 'active', archived_on: null, superseded_by: null, ...c }));
export const activeCards = () => CARDS.filter((c) => c.status === 'active');
export const cardByStory = new Map(CARDS.flatMap((c) => c.story_ids.map((id) => [id, c])));

const DAY = 86_400_000;
/**
 * Active cards whose campaign has gone quiet: the card is older than `quietDays`, no watch on
 * its stories is still active, and the last material development is older than `quietDays`.
 * @param watchRows [{ story_id, status, last_change_at }] for the cards' stories
 */
export function archiveCandidates(cards, watchRows, now = Date.now(), quietDays = 30) {
  const cutoff = now - quietDays * DAY;
  return cards.filter((c) => c.status === 'active').flatMap((c) => {
    if (new Date(c.date).getTime() > cutoff) return [];
    const ws = watchRows.filter((w) => c.story_ids.includes(w.story_id));
    if (ws.some((w) => w.status === 'active')) return [];
    const last = ws.map((w) => w.last_change_at).filter(Boolean).sort().at(-1) || null;
    if (last && new Date(last).getTime() > cutoff) return [];
    return [{ slug: c.slug, reason: `card dated ${c.date}, ${ws.length ? 'all watches expired' : 'no watches'}, last development ${last ? last.slice(0, 10) : 'none'}` }];
  });
}
