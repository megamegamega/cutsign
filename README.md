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

**Verdict cards** (`public/cards/`, manifest in `lib/cards.js`): one per campaign, re-issued in place
(the as-of date and the manifest date move together — a test enforces it), with a lifecycle of
`active → archived → superseded`. Every card ends with inferred, tool-neutral detections and a
runnable Splunk block over `index=*`; every bare identifier printed is labeled.

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
Over `HYPE_SURFACE` (9) a draft is surfaced: an "AI draft" chip on its story in the CISO view, an
`ai_draft` link in the agent JSON, first place on the Cards tab, and a "ready for review" email.
Drafts live in `card_drafts` (migrations 0004, 0005), render at `/?view=draft&id=…` behind an
"AI-generated, unreviewed" banner, never claim product coverage, and are scrubbed with the repo's
hygiene rules. Publishing one is a human edit to `public/cards/` and the manifest, where the analyst
fills the coverage table; a dismissed or promoted draft stops the loop for its thread, and threads
that already have a card are skipped.

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

## Companion: bluesign (planned)

A blue-team detection-validation tool that consumes Cutsign's agent JSON: constructs synthetic log
events from a story's signal fields, runs them through the SIEM vendors' own public ingestion
pipelines in a local Docker lab, asserts the detection fires on signal and stays silent on noise,
and measures telemetry coverage ("today's brief needed six log sources; you can see four").
Adversary emulation is out of scope and never initiated by the system.
