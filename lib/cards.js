// Hand-curated verdict cards: one-page patch/incident verdicts served statically from
// public/cards/. Each entry maps a card to the extracted stories it covers, so story
// cards across the site (CISO view, IoC corpus, search) link to it — and the card
// links back to the live pipeline views. Public OSINT only, like everything here.
export const CARDS = [
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
