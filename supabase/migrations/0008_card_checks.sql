-- Stale-card checks. Paste into the Supabase SQL editor once (after 0007).
-- One row per hand-written card (lib/cardchecks.js): when it was last checked, the flags that are
-- open against it, the KEV listings and advisory fingerprints it was compared with, and which flags
-- were already said on Discord, so a flag is raised once and then carried in the daily digest. A
-- hand-written card with no brief story has no story row to carry this (the coverage check rides on
-- one), which is why it gets a table of its own. The row named '_digest' holds the day the digest
-- was last posted. The state holds flag text (which can quote one line, at most 160 characters, of a
-- public advisory), CVE ids, public URLs and line hashes of public pages. With this table missing
-- the checks do not run and the tick says which migration to apply, so the code can deploy before
-- it. Same lockdown as 0001: RLS on, no policies, service role only.

create table if not exists card_checks (
  slug        text primary key,
  state       jsonb not null default '{}',
  updated_at  timestamptz not null default now()
);

do $$
declare t text;
begin
  foreach t in array array['card_checks'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
