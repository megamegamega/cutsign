// Hand-curated verdict cards: one-page patch/incident verdicts served statically from
// public/cards/. Each entry maps a card to the extracted stories it covers, so story
// cards across the site (CISO view, IoC corpus, search) link to it — and the card
// links back to the live pipeline views. Public OSINT only, like everything here.
export const CARDS = [
  {
    slug: 'connectwise-m365-2026',
    title: 'ConnectWise Cloud Backup supply chain compromise',
    date: '2026-10-23',
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

export const cardByStory = new Map(CARDS.flatMap((c) => c.story_ids.map((id) => [id, c])));
