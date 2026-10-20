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

**Inbound (stage `received`).** Gmail API polling with a read-only token (`gmail.readonly`, nothing
else; the token refresh *fails* if any other scope appears). Query (env `GMAIL_QUERY`):
`from:(brief@example.test OR briefs@example.test) subject:"Threat Brief" newer_than:3d` —
no Gmail filter or label needed. For each message, the `Message-ID` is checked against `briefs`
**before** the body is even downloaded; re-delivery is a no-op. Then:

- sender not on `BRIEF_SENDER_ALLOWLIST` → stored as `rejected` (no body), Discord ⚠, nothing else;
- subject contains `[TEST]` → `ignored`;
- a brief for the same date was already accepted (the sender sometimes sends both formats) → `ignored`;
- otherwise `accepted` + a new `runs` row.

**Stages.** `runs.stage` is always the last stage that *completed*:

| from → to | what happens |
|---|---|
| received → parsed | MIME → clean text; brief split into one story per item (deterministic — the brief is a structured list); top ≤ `MAX_STORIES` (5) exploited/TTP items selected, the rest stored as `skipped` |
| parsed → fetched | ≤ 2 links per story, round-robin, ≤ `MAX_SOURCES` (12) per brief; 10 s timeout, 1 MB cap, ≤ 3 redirects, robots.txt honored; one hop from a news page to a linked vendor/CERT page; 7-day cache; prompt-injection screen flags `suspicious` sources, which are excluded from extraction and shown in the email |
| fetched → extracted | one Claude call per story (`claude-opus-5-5`, structured output validated by zod; ATT&CK IDs checked against `lib/attack-ids.json`; one corrective retry). Exploited + behaviors, or KEV, floors priority at P1 |
| extracted → normalized | IoCs refanged, canonicalized, placeholders/private ranges dropped, upserted on `(type, value_norm)`; `seen_count` +1 once per run |
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

**Cost.** ~5 extraction calls per brief at Opus 5.5 rates, system prompt cached → roughly $0.30–0.80
per brief. `MAX_MONTHLY_USD` (25): above it the pipeline still extracts but stops emailing and says
so on Discord. `PAUSED=1` stops everything without a deploy.

## Endpoints

- `GET /api/cron` (`?dry=1` → new runs don't email) — Bearer `CRON_SECRET` (Vercel cron sends it).
- `POST /api/advance` — internal self-chain, same secret.
- `GET /api/health` — liveness + list of *missing* env var names (never values). `noindex` everywhere.

## Env vars

See `.env.example` (names only). Required: `CRON_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`,
`ANTHROPIC_API_KEY`, `EMAIL_API_KEY`, `DISCORD_WEBHOOK_URL`, `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`,
`GMAIL_REFRESH_TOKEN`.

## Local work

```bash
npm test                                   # offline: memory store, fake network, fake/replayed LLM
node scripts/run-local.js --eml fixtures/briefs/2026-10-20-pipeline.eml   # real sources + real API → out/latest.html
node scripts/run-local.js --gmail --save-fixture                          # newest real brief from Gmail
node scripts/run-local.js --eml … --record                                # also save LLM responses to fixtures/llm/
npm run gmail-auth                         # one-time: read-only Gmail refresh token → .env
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
