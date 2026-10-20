# Cutsign

Personal, cron-driven pipeline: the sender's daily threat brief → the primary sources behind it →
the adversary's **behaviors** first, then printed evidence, published detection guidance, and
atomic IoCs → one email to me. Named for the tracker's "cutting for sign": reading the sign an
adversary can't avoid leaving.

**Current version: v0 — the read, as an email.** No pack page, no Sigma, no validation yet. v0 exists
to tune `prompts/extract.system.md` against real briefs for 1–2 weeks. v0 is done when, for five
consecutive briefs, the extracted behaviors match what I'd have written by hand.

## The one rule: zero employer data

This system never receives, stores, or references anything from my employer — no internal
hostnames, index names, sourcetypes, usernames, ticket numbers, or results. Inputs are public OSINT
only (the brief + public URLs); outputs are generic. There is no table column that could hold an
internal value, and there must never be one. Every email says so in its banner. A test
(`test/hygiene.test.js`) greps the repo for internal-looking tokens.

## How it runs

```
Vercel cron 13:00 UTC ─┐                     ┌─ chain: POST /api/advance (202, works under waitUntil)
Vercel cron 17:00 UTC ─┴─ /api/cron ─ intake ─┴─ driveRuns ─ stages… ─ email + Discord ✔/✖
```

Email goes to `EMAIL_TO` (default dispatch@liberto.us).

**Inbound (stage `received`).** A Gmail filter forwards the sender's brief (from
`brief@example.test OR briefs@example.test`, subject "Threat Brief") to `BRIEF_INBOUND_ADDRESS`, a
Resend Receiving address. Resend stores it; the cron lists received mail via Resend's API (same
`EMAIL_API_KEY`, full access) and downloads the raw message — no webhook, so a failed run loses nothing.
Received mail counts toward the Resend account's quota (~1–2/day). The `Message-ID` is checked against
`briefs` **before** the body is downloaded; re-delivery is a no-op. Then:

- Resend reports the message's DKIM result; anything without a DKIM pass is `rejected` with a Discord ⚠
  (the public inbound address is otherwise spoofable);
- sender not on `BRIEF_SENDER_ALLOWLIST` → stored as `rejected` (no body), Discord ⚠, nothing else;
- subject contains `[TEST]` → `ignored`;
- a brief for the same date was already accepted (the sender sometimes sends both formats) → `ignored`;
- otherwise `accepted` + a new `runs` row.

**Stages.** `runs.stage` is always the last stage that *completed*:

| from → to | what happens |
|---|---|
| received → parsed | MIME → clean text; brief split into one story per item (deterministic — the brief is a structured list) |
| parsed → fetched | each story's first link, ≤ `MAX_SOURCES` (40) per brief; 10 s timeout, 1 MB cap, ≤ 3 redirects, robots.txt honored; one hop from a news page to a linked vendor/CERT page; 7-day cache; prompt-injection screen flags `suspicious` sources, which are excluded from extraction and shown in the email |
| fetched → extracted | **light read** of every story (`claude-haiku-5-5`, first source, 20k chars, 4 at a time) → **score** each on what it found (`lib/select.js`: behaviors, evidence, guidance, IoCs, KEV, primary source, financial relevance; unconfirmed/roundup penalized) → top ≤ `MAX_STORIES` (6) scoring ≥ `MIN_DEEP_SCORE` (6) get their second link + one hop to a vendor/CERT page and a **deep read** (`claude-opus-5-5`, 50k chars). Stories the light read rated P3 never get a deep read, and two write-ups of the same campaign (shared CVE, or same actor + malware) never take two deep slots. A failed deep read falls back to the light result. (Structured output validated by zod; ATT&CK IDs checked against `lib/attack-ids.json`; one corrective retry). Exploited + behaviors, or KEV, floors priority at P1 |
| extracted → normalized | IoCs refanged, canonicalized, placeholders/private ranges dropped, upserted on `(type, value_norm)`; `seen_count` +1 once per run. Each story is then matched to the trailing 14 days (shared CVE, same specific malware family, or same actor + a shared IoC) and linked via `updates_story_id` |
| normalized → validated → queried → rendered | **v1/v2 seams — pass-through in v0** |
| rendered → sent | email to `EMAIL_TO` (skipped for dry runs or when over the monthly cap) and a Discord ✔ line |

Any thrown error → `stage='failed'`, `failed_stage`, `error`, a Discord ✖ line, and a retry from that
stage on the next tick (3 attempts max). Long stages check the clock and yield; what they finished is
persisted, so the next invocation resumes. A short lease on the run row stops two invocations working one run.

**Schedule and DST.** Vercel Hobby crons run once a day each and may fire anywhere in the scheduled
hour, in **fixed UTC**. The brief lands ~11:10–12:10 UTC. `0 13 * * *` therefore fires 13:00–13:59 UTC
= 9–10 AM EDT in summer, 8–9 AM EST in winter (DST shifts *local* time by an hour; the brief, also
UTC-scheduled on the sender's side, shifts with it or not — either way 13:00 UTC is after it). `0 17 * * *`
is the catch-up for late or re-sent briefs and for resuming a stuck run; it's normally a no-op.

**Cost.** First live run (Opus 5.5, 5 stories) cost $0.48. Sonnet for the deep tier was tried on
2026-10-19 and judged weaker, so: 6 deep reads on Opus 5.5 + ~25 light reads on Haiku 5.5 → estimated
$0.55–0.70 per brief, ~$17–21/month. `LLM_MODEL_DEEP=claude-sonnet-5-5` roughly halves the deep-tier cost. `MAX_MONTHLY_USD` (25): above it the pipeline still extracts but stops emailing and says
so on Discord. `PAUSED=1` stops everything without a deploy.

## Day-over-day diffing (`lib/diff.js`)

- **Delta line** at the top of every email: new IoCs and never-seen behaviors vs. restated IoCs and story updates.
- **Story updates:** a story continuing one from the last 14 days is titled "update to <date>'s story"; only
  what's new is shown, restated IoCs and already-reported behaviors fold into collapsed sections.
- **Behavior novelty:** a behavior is "seen before" if any behavior in the last 90 days has the same
  `pattern_kind`, same parent, and ≥ 50 % overlapping children. New ones get a ★.

**Email size.** Gmail clips bodies over ~102 KB. Styles are one `<style>` block, and if a heavy day still
runs long the renderer trims quick-read stories (then lists them as one-liners) until it fits 95 KB; deep
stories are never trimmed.

## Endpoints

- `GET /api/cron` (`?dry=1` → new runs don't email) — Bearer `CRON_SECRET` (Vercel cron sends it).
- `POST /api/advance` — internal self-chain, same secret.
- `POST /api/inbound` (`?dry=1`) — feed a raw `.eml` brief by hand; same dedupe + allowlist as the poll.
- `GET /api/health` — liveness + list of *missing* env var names (never values). `noindex` everywhere.

## Env vars

See `.env.example` (names only). Required: `CRON_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`,
`ANTHROPIC_API_KEY`, `EMAIL_API_KEY` (full access), `DISCORD_WEBHOOK_URL`, `BRIEF_INBOUND_ADDRESS`. Gmail
polling is still available as a fallback (`INBOUND_SOURCE=gmail` + the three `GMAIL_*` vars).

## Local work

```bash
npm test                                   # offline: memory store, fake network, fake/replayed LLM
node scripts/run-local.js --eml fixtures/briefs/2026-10-20-pipeline.eml   # real sources + real API → out/latest.html
node scripts/run-local.js --gmail --save-fixture                          # newest real brief from Gmail
node scripts/run-local.js --eml … --record                                # also save LLM responses to fixtures/llm/
npm run gmail-auth                         # one-time, in your own Terminal: read-only Gmail token → Vercel (no files)
npm run update-attack                      # refresh the ATT&CK mirror when MITRE ships a release
```

`LLM_MODE=replay` loads `fixtures/llm/<hash>.json`; the hash covers the prompt, so editing the prompt
means re-recording. CI runs `npm test` in replay mode with no keys.

## Database

`supabase/migrations/0001_v0.sql` — paste into the Supabase SQL editor. RLS on for every table, no
policies, revoked from `anon`/`authenticated`: only the service-role key (Vercel env, server-side) can
touch data. Retention jobs (raw MIME 30 d, source text 90 d) and backups arrive with v1.

## Roadmap seams (present, deliberately unbuilt)

`lib/validate.js`, `lib/feeds.js`, `lib/queries.js`, `lib/lint.js`, `lib/backends/{splunk,elastic}.js`,
`templates/`, `logsources/`, `stories.fingerprint` / `updates_story_id`, `lib/tokens.js` (signed links).
v1 = the pack; v2 = prove it. Open v1 decision: pySigma is Python — compile in a Python function or in
an Actions job.
