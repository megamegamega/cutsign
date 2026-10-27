# Cutsign — project instructions

Cutsign is a personal, defensive threat-intelligence pipeline: it reads public threat reporting,
extracts adversary behaviors (ATT&CK), indicators and published detection guidance, and renders them
as a daily brief, a public site and one-page verdict cards. Everything here is blue-team work:
understanding what adversaries did and how defenders detect it. Discussing exploits, malware,
command-and-control infrastructure and verbatim attacker artifacts from public sources is the job;
writing exploits, payloads or attack tooling is not, and never happens in this repository.

## The one rule: zero employer data

This system never receives, stores or references anything from the author's employer — no internal
hostnames, index names, sourcetypes, usernames, ticket numbers or results. Inputs are public OSINT
only; outputs are generic. `test/hygiene.test.js` fails the build on anything shaped like an internal
identifier. Never add a table column, fixture, example or placeholder that could hold one. Example
values are `example.test` addresses and `<placeholders>`; a Splunk example may say `index=*`, never a
named index.

## Working here

- `npm test` must be green before every commit (offline: memory store, fake network, replayed LLM).
- Secrets live only in Vercel environment variables; never in files, never in chat; nothing is read back.
- Commit as `git -c user.email=<the repo's public author email> -c user.name="Marcus Liberto"`.
- Verdict cards (`public/cards/`) are public OSINT only, re-issued in place (bump `AS_OF` and the
  manifest date together — a test enforces it), and label every bare identifier they print.
- Titles and summaries claim outcomes only as strongly as the sources confirm.
- Delegated review runs at `max` effort; mechanical fan-outs at `low`.
