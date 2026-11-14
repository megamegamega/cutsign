# Cutsign

A personal, defensive threat-intelligence pipeline. Each weekday Cutsign ingests a public daily
cyber-threat brief (an emailed digest of published security news and vendor advisories), reads the
public sources behind each story, and produces a structured record for defenders:

- the adversary **behaviors** described, mapped to MITRE ATT&CK — the point of the whole system;
- the **evidence** the sources print (command lines, log lines, HTTP requests, file paths), byte-exact;
- the **detection guidance** vendors and researchers have published;
- the atomic **indicators** the sources state — last and least;
- an **exposure check**: affected and fixed versions, preconditions, quick exclusions.

It emails a morning brief, publishes the same material as a small site (analyst, CISO, agent-JSON,
IoC-corpus and search views), keeps a **watch** on ongoing stories so material developments —
new advisories, KEV listings, vendor fixes, confirmed exploitation — surface the same day (one
development, one line: a write-up that only reports a KEV listing the catalog probe caught in the
same tick folds into that event and lends it its link), and for
the stories that matter most carries hand-written one-page **verdict cards** (patch / hunt / prepare,
with detection coverage per vendor and tool-neutral inferred detections).

Named for the tracker's "cutting for sign": reading the sign an adversary can't avoid leaving.

Live: https://cutsign.vercel.app · License: Apache-2.0 · Built by Marcus Liberto.

## What it is not

Cutsign is blue-team only. It extracts what adversaries did and how defenders detect it. It does not
write exploits, payloads or attack tooling; it does not scan, probe or touch any system other than
reading public web pages; and nothing it produces is executed anywhere — detection logic is published
as text for a human to review and run. The material is intrinsically about attacks (CVEs, in-the-wild
exploitation, malware, command-and-control infrastructure, verbatim attacker artifacts) because that is
what detection engineering is made of; all of it comes from public reporting.

## The one rule: zero employer data

This system never receives, stores or references anything from the author's employer — no internal
hostnames, index names, sourcetypes, usernames, ticket numbers or results. Inputs are public OSINT
only (the brief and public URLs); outputs are generic. There is no table column that could hold an
internal value, and there must never be one. Every email says so in its banner. `test/hygiene.test.js`
fails the build on anything shaped like an internal identifier.

## How it runs

```
brief email ─ Resend inbound ─┐
Vercel crons (UTC) ───────────┴─ /api/cron ─ intake ─ driveRuns ─ stages… ─ email + site + Discord ✔/✖
daily 14:30–23:30, ten ticks ───  /api/watch  (story watches: page diffs, KEV, feeds, NVD, GitHub; batch answers; card coverage)
daily 13:45 ─────────────────────  /api/selfcheck (validates the public contracts the site and cards depend on)
```

**Inbound.** The brief is forwarded to a Resend receiving address. The `Message-ID` is checked before
the body is downloaded (re-delivery is a no-op); messages must carry a DKIM pass and a sender on
`BRIEF_SENDER_ALLOWLIST`, or they are stored as `rejected` with no body and a Discord warning.

**Stages.** `runs.stage` is always the last stage that completed; any error marks the run `failed`
and the next tick retries from that stage (3 attempts), resuming what was persisted.

| from → to | what happens |
|---|---|
| received → parsed | MIME → clean text; the brief split into one story per item |
| parsed → fetched | each story's sources, with timeouts, size caps, redirect limits, robots.txt, a 7-day cache, and a prompt-injection screen that excludes suspicious pages from extraction |
| fetched → extracted | a **light read** of every story, scored on what it found; the top stories get a **deep read** with more sources. Structured output validated by zod; ATT&CK IDs checked against a local mirror. Titles and summaries claim outcomes only as strongly as the sources confirm |
| extracted → normalized | IoCs refanged and canonicalized, placeholders and private ranges dropped, upserted on `(type, value)`; stories matched to the trailing 14 days and linked as updates; two items in one brief on one campaign (shared CVE, specific malware, or actor plus an IoC) are linked the later to the earlier and take the group's strongest priority, since the model rated each alone — the views say "continues an earlier item in today's brief", the card thread carries both, and the sweep scores the pair once |
| normalized → … → sent | email, site, Discord. The `validated` / `queried` stages are seams for the detection-validation companion (see below) |

**Watches.** Each day's deep-read stories become watches (14 days, extended by material changes,
capped at 30). Since 2026-11-12 the watch tick runs as one daily block after the brief has been read
(ten Vercel crons an hour apart, 14:30–23:30 UTC; it was hourly before, cut to stop paying for
re-reads through the day). Each watch is read once per block (`WATCH_MIN_INTERVAL_H`, 18): its pages
and the feeds are fetched in the block's first ticks, and a model runs only on a change, reading just
the added text. The rest of the block reads no page and assesses nothing: it collects the batched
answers, runs the free checks (KEV on every tick; NVD status and public PoC repos once a day per
watch, a few watches per tick, the one checked longest ago first, spaced by `WATCH_SLOW_GAP_MS`) and
spends what is left of each tick on card coverage. The one model call such a tick can still make is
the small title check, when a free check has just found something material. What changes overnight
is found at the next day's block. A
development that falsifies a title's outcome claim ("no confirmed compromises") retitles the story and
its watch in place. HIGH events post to Discord at once; only the major ones — a KEV listing, reported
exploitation, a fix, a public PoC with traction — also send a short mail, once per story and kind until
a week passes without that kind (`WATCH_ALERT_MAIL`: `major`, `all` or `off`). The model reads new text
against everything the watch already knows (summary, behaviors, IoCs, the developments already
reported), so a second outlet restating the same technique is not a development. Everything appears in
the next morning's email under "Developments on tracked stories"; there the low-signal updates (repo
mentions, status pings) are a count, and the page lists them. A change the model could not be asked
about writes no event and is held with the watch instead: under an API spend limit or the monthly cap
it waits for the next daily read (the article is kept, so it is still read after it leaves its feed);
after an outage it is asked again on the next tick, three times in all. One Discord line a run says
how many were put off and why, and names — watch, link, reason — each one given up: a text the model
declined or could not answer, a third failed try, a watch that ended first.

**Verdict cards** come two ways. Hand-written ones live in `public/cards/` (manifest in
`lib/cards.js`): one per campaign, re-issued in place (the as-of date and the manifest date move
together — a test enforces it), with a lifecycle of `active → archived → superseded`. Every card
ends with inferred, tool-neutral detections and a runnable hunt block in two dialects — Splunk over
`index=*` and Elastic ES|QL over `FROM logs-*` (ECS field names) — behind a Splunk | Elastic switch
(`public/cards/qswitch.js`; the choice is remembered for the whole site, PDFs print both); every bare
identifier printed is labeled. The pipeline's own cards are published automatically from the draft
loop below at `/cards/<slug>` and carry an "AI-generated, published automatically" banner. Both
kinds carry an **automated detection-coverage check** (next section) and both are kept current
without a hand: a hand-written card's page links the AI re-issue draft the pipeline writes when
something develops after its as-of date, and corrects its KEV row from the live catalog.

**AI drafts, the card loop** (`lib/hype.js`, `lib/carddraft.js`): after each brief is sent, and
again from the watch tick when something developed, every story thread is scored on what the
pipeline already knows — priority, deep read, a CISA KEV listing within three days, how many briefs
the story has run, distinct publishers, a primary source, stated internet-facing exposure, a named
actor, and 48 h of watch developments. Over `HYPE_NOMINATE` (6) the thread is nominated to Discord
with the signals that fired. A draft is written only for a card that will be published — a thread
over `HYPE_SURFACE`, or one of the brief's top P1s on day one (below) — once it has something actionable (published
guidance, a vendor-stated behavior, a fix version, a fresh KEV listing, evidence samples or IoCs);
a nominee under the bar gets its Discord line and is drafted the sweep it crosses, with everything
gathered by then (until 2026-11-04 every nominee was drafted, and half the drafts were previews of
stories that never crossed). The draft is one deep-tier call, shaped on the DAIR model (Detect, Verify
and Triage, the Scope / Contain / Eradicate / Recover loop, Debrief; Joshua Wright, *Dynamic
Incident Response*).
Each draft records the facts it holds, as stable keys that only accumulate (a KEV listing, a fix
version, a vendor-stated behavior by technique, a guidance item by link, a sample or IoC by value, a
material watch development). Only a fact it does not hold revises it, from the prior version as a
new row with a change list, the old one marked superseded; another day of coverage, more outlets, a
development aging out of the window, or the same facts read from another brief's copy of the story
revise nothing. A draft from before facts were kept is seeded from its whole thread, with no model call.
A fact that moves the story — a KEV listing, a fix version, a vendor-stated behavior, a material
development — revises the card at once; a sample, an IoC or a guidance link alone folds in once a
UTC day, together with whatever else landed. A revision is an edit of the prior draft against the
change list and runs at low effort; a first draft composes at medium. A card is revised at most
`CARD_REISSUES_PER_DAY` (3) times a UTC day; past that, Discord says so once and the new facts wait
for its first sweep after midnight.
A draft never invents hunts when its thread has proposer hunts (below): its Detect section is those,
lint-clean and in both dialects, and the model writes only what a hit means. Hunts the model writes
itself come in both dialects too (`spl` over `index=*`, `esql` over `FROM logs-*`; a concrete index
or data-stream name is rewritten to the wildcard), and every card page shows them behind the same
Splunk | Elastic switch as the hand-written cards. A card drafted before the dialect existed gets
its twins once, on the next daily sweep: one low-effort call translates its Splunk searches, each
answer is scrubbed and linted (a failure is stored as null), and the draft is patched in place with no
new version, since the card's text did not change.
Over `HYPE_SURFACE` (9), or **on day one for a brief's top P1 stories** (`CARD_P1_DAY_ONE`, default
on; the score measures how a story is developing, and a reader who sees a P1 needs a link that day,
not after the corroboration arrives — the banner says it is an early read and the card is revised
as the story develops; the first `CARD_P1_PER_DAY` (3) P1 threads in brief order get one, since each
draft is a deep-tier call and a brief carries five to nine P1s, and the others get their card the
sweep their score crosses the bar), the draft is **published** (`CARD_AUTOPUBLISH`, default on): it becomes
an AI verdict card at `/cards/<slug>`, with a "Verdict card" chip on its story in the CISO view,
`verdict_card` in the agent JSON, a place on the Cards tab, and a "published" email. Revisions
re-issue it in place (same URL, old version superseded) with a Discord line and no email;
dismissing the draft unpublishes it. No
person is in the loop: the banner says what it is. Drafts live in `card_drafts` (migrations 0004,
0005), render at `/?view=draft&id=…` behind an "AI-generated, unreviewed" banner until published,
and are scrubbed with the repo's hygiene rules.

**Detection coverage, checked automatically** (`lib/coverage.js`). The model never claims product
coverage; the pipeline asks the public sources instead and prints what each one said. Every draft
and every published card carries a table built from: the impacted vendor's own page (a primary
source among the thread's sources), CISA KEV, NVD (CVSS), Rapid7's vulnerability database (its
own InsightVM coverage flag), Qualys ThreatPROTECT and Security Blog posts (the QIDs they print; the
QID knowledge base itself needs a login, so a hand card's "nothing published" scanner row is
corrected on the page the day Qualys prints one), Red Hat security data
(errata), Tenable's plugin search (plugin ids and names), the Debian tracker, the Nuclei template
tree, Emerging Threats open rules (Suricata sids), the SigmaHQ, Elastic and Splunk rule
repositories (one GitHub code search per term — the legacy parser ANDs terms whatever "OR" says —
the campaign name first, then the CVE ids, three a card, spaced 7 s apart so a sweep over every
card stays under the API's ten a minute; a stated name's bracketed aliases are split into terms,
since whole they are a parser error), and the feeds and
changelogs of CrowdStrike, Microsoft Security, SentinelOne (Labs and the product blog), Cloudflare's
WAF managed ruleset, Akamai, Wiz, Talos, Elastic Security Labs, Unit 42, Huntress, Sophos, Arctic
Wolf and Rapid7. Each lane ends in one of four statuses — `published` (with the link), `nothing
found` (the source answered and had nothing; itself a finding), `not checkable` (the rule
repositories need `GITHUB_TOKEN` for GitHub code search) or `check failed` — so a dead feed never
reads as "nothing published". `GITHUB_TOKEN` must be a classic token (no scopes; the rule
repositories are public): GitHub's code search refuses a fine-grained token for any repository it
was not granted (HTTP 422). A failed search prints GitHub's own reason (a parser error names the
term; a token refusal names the token kind), and `/api/health` reports `github` from a one-result
code search so a token that cannot search never reads as `ok`. Feeds match on the CVE id anywhere in the item, or on the campaign's
nickname or product name in the title inside the campaign window (vendor feeds say "PHP2Shell" and
never print the CVE id); a plain capitalised word never matches. The check is
re-asked daily for every published card and every hand-written card (stored on the card's manifest
story row, rendered under the hand-written table by the card page's script), and a lane that moved
is posted to Discord.

**Exposure queries, generated automatically** (`lib/exposure.js`). The same check writes the
generic half of an external-attack-surface alert for every card: Shodan's `vuln:` query per CVE,
and, from the CPE configurations NVD publishes for the CVE, a Shodan `cpe:` query, a Shodan
`product:` query and a Censys `software.product` query per vulnerable product, each with NVD's
affected version ranges. The other half, the ranges, org name and domains that scope a query to one
estate, is never generated, stored or rendered: the section carries placeholders and tells the
reader to add the scope in Shodan Monitor or their EASM product, where that inventory already lives.
A CPE that NVD publishes later appears at the next daily re-check and is posted to Discord with the
coverage changes.

**Shodan counts, with `SHODAN_API_KEY`** (`lib/shodan.js`). With a key set, every Shodan query on
a card is counted against Shodan itself through its count endpoint (`/shodan/host/count`, which
spends no query credits; calls are spaced to the API's one a second and capped per card so they
fit inside the GitHub lane's wait). Each query line then says what Shodan returned: the
internet-wide total as of that day, or `0 services match this spelling` — NVD spells a product one
way (`product:"Panorama Virtual Appliance"`, `cpe:"cpe:/a:php:php"`) and Shodan often another, and
without the count a zero reads as "nothing exposed". When every query for a product is empty, the
check runs one text search for the product's distinctive words with the `product`, `http.component`
and `cpe` facets, keeps the facet values that share a word with the product (never a neighbour in
the same banners, such as the web server in front of PHP), counts each candidate, and adds the
ones that match as `discovered` rows labelled with the facet they came from; the `cpe:` row is told
when Shodan stores the CPE versioned. The totals are kept as one point a day (90 days) on the
card's coverage check and rendered as a trend table (first, latest, change) once a query has two
days of counts; a daily count moving is not posted to Discord, a spelling found or the key failing
is. Whether the key's plan has the `vuln:` filter is learned from Shodan itself, not from its price
list: a plan without the filter gets total 0 rather than an error, so once an hour the check counts
`vuln:CVE-2014-0160` (tagged on banners for a decade); a nonzero total means every `vuln:` zero after
it is a real zero ("Shodan has tagged no banner with this CVE yet"), a zero means the filter is off
and the CVE rows say so instead of claiming "0 services". The product queries are counted either
way. A product none of whose queries matched also says whether the text search for its name found
anything, or that Shodan refused the search. A check made without a key is stale the moment the key exists, and the watch
tick re-checks stale cards on its own, after the watches, in whatever the tick has left (no scoring,
no models, the KEV catalog fetched only when a card is actually stale; the stalest card first, none
started after 200 s, the rest take the next tick). With ten ticks a day instead of twenty-four a
card's check comes round every day or two rather than daily.

**Banner spellings** (`lib/scannernames.js`). NVD names a product as the vendor's catalogue does
today (Catalyst SD-WAN Manager, VeloCloud Orchestrator under Arista); Shodan's banners print the
name the device shipped with (vManage, VeloCloud). With a Shodan key set, one small model call per
card version reads the NVD names and the card's own affected text and proposes the strings a
scanner would show (`http.title`, `product`, `http.component`, `http.html`, `ssl`). Each proposal
is validated (a filter from that list, a specific plain value, never a vendor name or a generic word
alone, never scope), counted against Shodan, and shown as an `alias` row only when it matches
something; the card says how many were proposed and how many matched. The suggestions are cached on
the card's exposure block by a key over the inputs, so the model is asked again only when the
products or the card text change; the call's cost rides on the sweep's cost line. The discovery
search's facets also include `http.title`, and the per-card Shodan budget is 20 calls.

**Without an NVD CPE**, the exposure block falls back to the name the campaign gives the software
(from the card's title, never an actor or malware name): a `product:` and an `http.component:`
query per name, plus the Censys form, each carrying the card's own affected-version text, so a
card is not blind to its product while NVD catches up; NVD's rows replace them at the re-check
that finds the configuration.

**Circling back** (`lib/update.js`). A story that is thin on its day (the brief named it, no source
text was readable) is the one that develops later, so three things keep it in view. Every quick-read
story that names a CVE gets a watch, not only the deep-read ones: its CVE is enough for KEV, NVD,
the feeds and GitHub. A watch that keeps developing lives up to 60 days. And the card loop runs for
the run of every story that developed in a tick, not only for today's brief, so a two-week-old story
that lands in KEV or gets a new write-up is scored and carded where it lives. When the pipeline
still misses something, the reader supplies it: a mail to the inbound address from the digest's own
recipient (`UPDATE_SENDER_ALLOWLIST`, default `EMAIL_TO`; the brief senders may too) with a subject
starting `update:` and naming a CVE or a quoted title, links in the body. Each link is fetched with
the same guards as a watched page, assessed by the light model as a development of that story,
stored as a watch event (`new_source`, marked supplied), and the card loop then runs for the story's
run; a link that is not about the story, or was already read, is skipped and said. Nothing in the
mail is taken as fact.

**Card mail** (`lib/subscribe.js`, `api/subscribe.js`, table from `supabase/migrations/0006_card_subscribers.sql`).
The cards index and every AI card page carry a sign-up form; the hand-written cards get the same
form from `lifecycle.js`. An address is stored pending, mailed a confirmation link, and only after
that link is opened does it get mail: one message per new verdict card (an AI card at its first
publication, a hand-written card when the sweep first sees it in the manifest and its as-of date is
within three days), each with an unsubscribe link and `List-Unsubscribe` headers, one-click
included. Addresses are never rendered, logged or sent anywhere but the mail sender; the sign-up
page never echoes one; a honeypot field and a site-wide cap of thirty requests an hour keep bots
out. Revisions of a published card are not mailed.

**Card PDFs** (`lib/pdf.js`, `lib/pdfrender.js`, `api/pdf.js`). `/cards/<slug>.pdf` is the card printed by headless
Chromium (`@sparticuz/chromium` with `puppeteer-core`, both pinned) from its own print stylesheet:
the pages a reader gets from Print → Save as PDF, Letter, dark. The page may load only this site
and the two Google Fonts hosts while it prints. Hand-written cards print from their `.html`; an AI
card prints only when its page answers, so an unknown slug never starts the browser. The edge caches
the file (ten minutes, then served stale while it re-renders); any other query on the URL is
redirected to the plain one, so each card has one cache key. A card mail fetches that URL once per
card and attaches the file to every subscriber's message; a PDF that cannot be had (the render
failed, the answer is not a PDF, or it is over 8 MB) leaves the mail link-only. Only `api/pdf.js`
imports the renderer, so no other function bundles Chromium.
`/api/health` reports `shodan` from the key's account record (plan and query credits left, never
the key). Nothing but the generic filter ever leaves the host: the scope half stays placeholders.

A thread that already has a hand-written card is not scored, but it is kept honest: each sweep
compares the card's as-of date with what happened after it (a CISA KEV listing of a CVE the card
names, a HIGH watch development). Each development is raised once on Discord and folded into an AI
re-issue draft, which the card page folds in automatically: the re-issue's lane, verdict, change
list and post-card timeline render at the top of the hand-written card (its header tags corrected
where the re-issue or the live KEV catalog contradicts them), the Cards tab shows the re-issued date
and lane, and the hand-written verdict below stays as of its own date. Two things need
no re-issue at all: a story is linked to its card by CVE when the update chain misses, and every
card page corrects its KEV row from the live catalog (the cards JSON carries `kev`, `coverage` and
`reissue` per card). The draft call itself survives the API refusing a wide schema's grammar: it is
retried without the grammar and validated locally.

**Hunt-query proposals, the `queried` stage** (`lib/queries.js`, `lib/lint.js`,
`prompts/propose.system.md`): for each deep-read P1/P2 story a model reads the story record and
proposes the *shape* of a hunt — stages over the closed log-source vocabulary, with a join when the
activity spans two telemetry families (token issuance → use, exploit → shell), rendered once as SPL
and once as ES|QL over `index=<key>` / `FROM <key>` placeholders. Proposals are candidates, never
detections: each carries a hypothesis, a required `noise_hint`, `from` citations into the record,
an honest `confidence` (`stated` / `derived` / `speculative`) and `params` holding every
story-specific literal, so a consumer can re-parameterise it. Every proposal passes a deterministic
linter or is dropped with the reason recorded: the only index form is the placeholder, no literal
sourcetype, data stream, host, user or email, read-only commands only, and no literal the story
record does not print. A story whose telemetry is `other` only, or names a single family, gets no
call: single-source hunts are template territory for the consumer, and the proposer earns its cost
only where a hunt has to cross families. The proposer runs on
its own model tier (`LLM_MODEL_PROPOSE`; Claude Sonnet 5.5 since 2026-11-12, when the deep tier
moved to Sonnet too, at half Opus's price per token. It ran on Claude Opus 5.5 from 2026-11-04 and on
Claude Fable 5.1 before that, about $0.90 a day; `LLM_MODEL_PROPOSE` and `LLM_MODEL_DEEP` set to
`claude-opus-5-5` restore Opus) and falls back to the deep tier once
month-to-date spend passes 80% of `MAX_MONTHLY_USD`, marking the proposal `model_tier: deep`.
Each proposal records its `model`, so a drop in the lint pass rate after the switch is measurable.
Proposals appear in the agent JSON as `proposed_queries[]` (tier `proposed`), collapsed in the web
analyst view, and by name in search results; never in the email or the CISO view. Nothing here runs
against any SIEM.

**Batched model calls** (`lib/jobs.js`, `lib/batchmode.js`, table from
`supabase/migrations/0007_llm_jobs.sql`). Model work that can wait an hour or more — the proposals above and
the card loop's drafts, revisions and re-issue drafts — goes through the Batches API at half the
list price (`LLM_BATCH`, default on). The queried stage submits and the brief goes out without
waiting (its ✔ line says "n proposals pending (batch)"); the card loop submits a draft and leaves
the thread alone while its answer is in flight, and a day-one draft waits until its story's
proposals have landed, so its Detect section is still the proposer's hunts. Every watch tick
collects first: a proposal is linted onto its story and counted on its run; a card is published,
re-issued or revised exactly as the live path would have done it, with its coverage check, Discord
line and mail. Batches usually answer within the hour and are collected by the daily block of ticks:
proposals land at its first tick (one to two and a half hours after the digest), a day-one AI card
a tick later, and whatever is submitted by the block's last tick lands the next day. An answer the
API cannot give (an error, a refusal, a batch still running after six hours — then cancelled) is
finished by one live call at the list price, except a card draft whose batch failed more than 48
hours ago: that job is closed and the card loop drafts the story again (batched) if it still clears
the bar. A tick on which the batch API cannot be reached cancels nothing and asks again. An answer
nobody waits for any more (the head was dismissed or revised meanwhile) is
abandoned. Each job records its outcome and cost. With the table missing the same calls run live,
so the code deploys before the migration. The deep and light reads of the brief itself stay live:
batching them would hold the morning email.

**Actors tab.** `/actors` (`/?view=actors`) maps every stored story's adversary to the country the
public sources attribute it to: a world map shaded by stories (or adversaries), stories per week for
the leading countries, a card per country listing its actors with why each was placed there, the
tools seen in more than one story with the countries of the actors around them, and the actors
named with no country. Windows 14 / 30 / 90 days / all (`w=`), kinds nation-state / criminal /
hacktivist / commercial spyware (`cat=`). `lib/actors.js` reads the stored `threat_actor`, title and
summary deterministically, with no model call: a group whose attribution is settled in public
reporting, a vendor naming convention (Microsoft's Typhoon/Blizzard/Sandstorm/Sleet, CrowdStrike's
Panda/Bear/Kitten/Chollima, Unit 42's Taurus/Ursa/Serpens/Pisces, Secureworks' Bronze/Iron/Cobalt/
Nickel), or the sources' own words beside the name ("China-nexus Volt Typhoon", "North Korea's
TraderTraitor"); a story naming no actor but saying "North Korean threat actors" counts one unnamed
actor. A language ("Russian-speaking"), a stance ("pro-Ukrainian") or a victim places no one. Vendor
alias tables merge one actor's names (Jade Sleet = TraderTraitor), and two groups public reporting
keeps apart never merge, whatever a single story writes. A story is one update chain. The attribution
is the sources', never Cutsign's. The map is Natural Earth 1:110m projected once into
`lib/worldmap.json` (`npm run update-worldmap`), so the page draws with no script and no network.

**Exposure tab.** `/exposure` (`/?view=exposure`) puts every active card's internet-scanner queries
in one place: the Shodan and Censys queries each card already carries (built from its CVE ids and
NVD's CPE configurations, `lib/exposure.js`), Shodan's internet-wide count for each and its change
over seven days (`lib/shodan.js`), a ranking of the cards by how widespread their software is, and
the affected range to compare a banner against. It is a read of what the daily coverage check stored
on the cards: the tab counts nothing itself, calls no model and spends no Shodan call. Two
machine forms, `lib/exposureview.js`: `/exposure.json` (grouped by card, with notes and up to thirty
days of counts per query) and `/exposure.tsv`, one query per line with a header, columns `card date
lane cves kev engine kind product check count count_7d_ago counted_at query url affected`; columns
are only ever added at the end, and a field is never empty (a dash stands in), so
`while IFS=$'\t' read -r …` and `awk -F'\t'` both keep their columns. The page prints a short bash
script that reads the table and asks Shodan's count endpoint for the same queries with the reader's
own scope appended; `test/exposureview.test.js` runs that script as printed against stubs. As on the
cards, the scope half (ranges, org name, domains) is never generated, stored or rendered: the
script takes it from the reader's shell and sends it only to Shodan with the reader's key. A count
is how widespread the software is, not how many of those services are vulnerable.

**Response actions.** `/actions` (`/?view=actions`) gives every active card's Contain list as data,
so the chain card → exposure check → hunt → recommendation can be scripted (`lib/actions.js`). Each
step becomes one or more actions with a kind from a closed list (`block_indicator`, `waf_rule`,
`isolate_host`, `revoke_session`, `rotate_secret`, `patch`, … sixteen in all), the condition the step
states (`always`, `if_exposed`, `on_hit`), the kind of asset, whether it can be undone, and the
indicators it names. From those, **fixed rules in code** give each action an autonomy class and the
checks that gate it: `auto` (safe unattended once its gates pass), `recommend` (prepare it, a person
approves), `manual` (a person does it), `never` (not automatable: rotations, rebuilds, removals).
Gates are `evidence_first`, `exposure_check`, `hit_check`, `usage_check`, `age_check`,
`exact_match_only`, `log_mode_first` and `expiry`. Every block carries `usage_check`; a block is
`auto` only for an indicator whose public context says it is the actor's (C2, exfiltration, payload
host, attack source, malware file), and a shared platform, a legitimate tool, a compromised
legitimate site, an address of unknown role or a range of addresses is `recommend` at most. A
platform's own hosts (an API, a CDN, a file host) are the platform whatever the model read; only a
customer's own name under a tenant platform (a Pages site, a tunnel, a dynamic-DNS name) can be an
actor's, by exact host. A WAF step that names indicators follows the same per-indicator rule.
Nothing that cannot be undone is ever `auto`. Indicators no step names are listed once per card as an unstated block candidate
(`<card>:x.1`, `stated: no`). The class is computed when the feed is read, so a rule change applies
to every card at once. Where a record comes from: hand-written cards have a hand-written one
(`lib/handactions.js`; a test holds each step to the text the card prints); for a generated card one
small low-effort model call classifies the steps and the role of each indicator, and code checks the
answer against the card (a step number, indicator or pattern the card does not have is dropped, a
word outside a list falls to the cautious value, a victim's asset is never a block target). The
model only classifies; it never chooses a class. The record is stored on the card's row in place:
no new version, no re-issue, no mail, and it is left out of the prior draft a revision shows the
model. The coverage sweep does it (`lib/hype.js`): the watch tick fills in published cards that have
no record; the daily sweep also re-checks a card whose Contain list or indicators changed (a
revision that leaves the Contain list alone carries the record over). One call per card per 20 hours
at most, 24 per sweep; three answers that cannot be used (one that does not check out, a refusal, a
cut-off answer: all billed) or five calls that never come back end it until the card changes, and a
failed re-check leaves the card the record it had. Nothing is called once the month is over
`MAX_MONTHLY_USD` or when the spend cannot be read. The cost (about 2–4¢ a card) is added to the
card's row; the monthly sum counts rows created in the month, so a call for an older card is on its
row but outside that sum. `CARD_ACTIONS=0` turns the calls off; stored records keep being served, as
long as they still restate the Contain list the card prints. Machine forms: `/actions.json` (grouped by card, with the
vocabulary, the totals by kind and class, and `pending[]`, the cards not classified yet) and
`/actions.tsv`, one line per action and target with a header, columns `card date action step kind
autonomy gates when asset reversible stated target_type target role direction pattern url text`;
columns are only ever added at the end and a field is never empty (a dash stands in). Both take
`?card=SLUG`. `/?view=cards&format=json` carries a per-card count by class and the URL. The page
prints a short bash script that lists the automatic block candidates with their gates;
`test/actions.test.js` runs it as printed against a stub. A role is a reading of public reporting,
not a verdict on the reader's network, which is why every block waits on the reader's own usage
check, and why the feed describes and never acts.

**Agent JSON.** `/?view=agent&format=json` (per day), `/?view=iocs&format=json`, `/?q=TERM&format=json`,
`/?view=cards&format=json`, `/?view=actors&format=json`, `/exposure.json`, `/exposure.tsv`,
`/actions.json` and `/actions.tsv`. Behaviors, guidance and evidence carry `log_source_keys[]`, a closed
vocabulary advertised in `vocab`, so a consumer can map telemetry families to its own data.

## Cost and safety rails

A monthly spend cap (`MAX_MONTHLY_USD`) stops emailing when exceeded and says so; `PAUSED=1` halts
everything without a deploy. Secrets live only in the host's environment variables — never in files.
Every endpoint that mutates state requires a bearer secret. The site is `noindex` and has no login.

## Local work

```bash
npm test                                   # offline: memory store, fake network, replayed LLM responses
node scripts/run-local.js --eml fixtures/briefs/2026-10-20-pipeline.eml   # real sources + real API → out/latest.html
npm run update-attack                      # refresh the ATT&CK mirror when MITRE ships a release
npm run update-worldmap                    # re-project the Actors map (pinned world-atlas@2.0.2); rarely needed
CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node -e "import('./lib/pdfrender.js').then(async (m) => process.stdout.write(await m.renderPdf('https://cutsign.vercel.app/cards/<slug>')))" > card.pdf   # a card PDF with desktop Chrome
```

`.env.example` lists every variable (names only). `LLM_MODE=replay` loads recorded model responses
from `fixtures/llm/`; CI runs the suite in replay mode with no keys. Fixture emails use `example.test`
addresses.

## Database

`supabase/migrations/` — paste into the Supabase SQL editor. RLS on for every table, no policies; only
the service-role key (server-side) can touch data.

## Companion: bluesign

A blue-team detection-validation tool that consumes Cutsign's agent JSON: constructs synthetic log
events from a story's signal fields, runs them through the SIEM vendors' own public ingestion
pipelines in a local Docker lab, asserts the detection fires on signal and stays silent on noise,
and measures telemetry coverage ("today's brief needed six log sources; you can see four").
Adversary emulation is out of scope and never initiated by the system.

**Proposal handoff.** bluesign's `lib/cutsign.js` reads `proposed_queries[]` from the agent JSON;
a proposal becomes a lab candidate; one that passes the lab and is admitted by a person
(`bluesign admit <id>`) is copied into bluesign's template library with `tier: constructed`.
Cutsign never learns the outcome: the flow is one-way, and nothing about the consumer's
environment ever comes back.
