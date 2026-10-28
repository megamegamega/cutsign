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
new advisories, KEV listings, vendor fixes, confirmed exploitation — surface the same day, and for
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
hourly ──────────────────────────  /api/watch  (story watches: page diffs, KEV, feeds, NVD, GitHub)
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
| extracted → normalized | IoCs refanged and canonicalized, placeholders and private ranges dropped, upserted on `(type, value)`; stories matched to the trailing 14 days and linked as updates |
| normalized → … → sent | email, site, Discord. The `validated` / `queried` stages are seams for the detection-validation companion (see below) |

**Watches.** Each day's deep-read stories become watches (14 days, extended by material changes,
capped at 30). Hourly checks are free; models run only on a change, reading just the added text. A
development that falsifies a title's outcome claim ("no confirmed compromises") retitles the story and
its watch in place. HIGH events alert immediately; everything appears in the next morning's email under
"Developments on tracked stories".

**Verdict cards** come two ways. Hand-written ones live in `public/cards/` (manifest in
`lib/cards.js`): one per campaign, re-issued in place (the as-of date and the manifest date move
together — a test enforces it), with a lifecycle of `active → archived → superseded`. Every card
ends with inferred, tool-neutral detections and a runnable Splunk block over `index=*`; every bare
identifier printed is labeled. The pipeline's own cards are published automatically from the draft
loop below at `/cards/<slug>` and carry an "AI-generated, published automatically" banner. Both
kinds carry an **automated detection-coverage check** (next section) and both are kept current
without a hand: a hand-written card's page links the AI re-issue draft the pipeline writes when
something develops after its as-of date, and corrects its KEV row from the live catalog.

**AI drafts, the card loop** (`lib/hype.js`, `lib/carddraft.js`): after each brief is sent, and
again from the hourly watch tick when something developed, every story thread is scored on what the
pipeline already knows — priority, deep read, a CISA KEV listing within three days, how many briefs
the story has run, distinct publishers, a primary source, stated internet-facing exposure, a named
actor, and 48 h of watch developments. Over `HYPE_NOMINATE` (6) the thread is nominated to Discord
with the signals that fired. A nominated thread with something actionable (published guidance, a
vendor-stated behavior, a fix version, a fresh KEV listing, evidence samples or IoCs) gets an
AI-generated draft from one Opus call, shaped on the DAIR model (Detect, Verify and Triage, the
Scope / Contain / Eradicate / Recover loop, Debrief; Joshua Wright, *Dynamic Incident Response*).
Each draft records the evidence fingerprint it was built from; when the evidence changes, the draft
is revised from the prior version as a new row with a change list, the old one marked superseded.
A draft never invents hunts when its thread has proposer hunts (below): its Detect section is those,
lint-clean and in both dialects, and the model writes only what a hit means.
Over `HYPE_SURFACE` (9) the draft is **published** (`CARD_AUTOPUBLISH`, default on): it becomes
an AI verdict card at `/cards/<slug>`, with a "Verdict card" chip on its story in the CISO view,
`verdict_card` in the agent JSON, a place on the Cards tab, and a "published" email. Revisions
re-issue it in place (same URL, old version superseded); dismissing the draft unpublishes it. No
person is in the loop: the banner says what it is. Drafts live in `card_drafts` (migrations 0004,
0005), render at `/?view=draft&id=…` behind an "AI-generated, unreviewed" banner until published,
and are scrubbed with the repo's hygiene rules.

**Detection coverage, checked automatically** (`lib/coverage.js`). The model never claims product
coverage; the pipeline asks the public sources instead and prints what each one said. Every draft
and every published card carries a table built from: the impacted vendor's own page (a primary
source among the thread's sources), CISA KEV, NVD (CVSS), Rapid7's vulnerability database (its
own InsightVM coverage flag), Qualys ThreatPROTECT posts (QIDs when printed), Red Hat security data
(errata), the Debian tracker, the Nuclei template tree, Emerging Threats open rules (Suricata
sids), and the feeds and changelogs of CrowdStrike, Microsoft Security, SentinelOne, Cloudflare's
WAF managed ruleset, Akamai, Wiz, Talos, Elastic Security Labs, Unit 42, Huntress, Sophos, Arctic
Wolf and Rapid7. Each lane ends in one of four statuses — `published` (with the link), `nothing
found` (the source answered and had nothing; itself a finding), `not checkable` (Tenable's plugin
list renders only in a browser; the SigmaHQ, Elastic and Splunk rule repositories need
`GITHUB_TOKEN` for GitHub code search) or `check failed` — so a dead feed never reads as "nothing
published". Feeds match on CVE id, or on stated names only when a campaign has no CVE. The check is
re-asked daily for every published card and every hand-written card (stored on the card's manifest
story row, rendered under the hand-written table by the card page's script), and a lane that moved
is posted to Discord.

A thread that already has a hand-written card is not scored, but it is kept honest: each sweep
compares the card's as-of date with what happened after it (a CISA KEV listing of a CVE the card
names, a HIGH watch development). Each development is raised once on Discord and folded into an AI
re-issue draft, which the card page links at the top until the card is re-issued. Two things need
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
its own model tier (`LLM_MODEL_PROPOSE`, Claude Fable 5.1) and falls back to the deep tier once
month-to-date spend passes 80% of `MAX_MONTHLY_USD`, marking the proposal `model_tier: deep`.
Proposals appear in the agent JSON as `proposed_queries[]` (tier `proposed`), collapsed in the web
analyst view, and by name in search results; never in the email or the CISO view. Nothing here runs
against any SIEM.

**Agent JSON.** `/?view=agent&format=json` (per day), `/?view=iocs&format=json`, `/?q=TERM&format=json`,
`/?view=cards&format=json`. Behaviors, guidance and evidence carry `log_source_keys[]`, a closed
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
