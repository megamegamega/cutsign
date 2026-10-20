-- Cutsign story watches. Paste into the Supabase SQL editor once (after 0001).
-- Each day's deep-read stories become watches; an hourly cron re-checks their pages, KEV, NVD, GitHub and
-- feeds, and records what changed. Same lockdown as 0001: RLS on, no policies, service role only.

create table if not exists watches (
  id               uuid primary key default gen_random_uuid(),
  story_id         uuid references stories (id) on delete set null,   -- latest story in the campaign
  title            text not null,
  cves             text[] not null default '{}',
  actor            text,
  malware          text,
  urls             text[] not null default '{}',                      -- pages to re-check (deep-read sources)
  status           text not null default 'active' check (status in ('active', 'expired')),
  created_at       timestamptz not null default now(),
  expires_at       timestamptz not null,
  last_checked_at  timestamptz,
  last_change_at   timestamptz,
  state            jsonb not null default '{}'                         -- page line-hashes, seen KEV/repos/news/NVD keys
);
create index if not exists watches_status_idx on watches (status, expires_at);

create table if not exists watch_events (
  id            uuid primary key default gen_random_uuid(),
  watch_id      uuid not null references watches (id) on delete cascade,
  created_at    timestamptz not null default now(),
  kind          text not null check (kind in ('page_changed', 'new_source', 'kev_added', 'poc_repo', 'nvd_status')),
  level         text not null check (level in ('HIGH', 'LOW')),
  url           text,
  summary       text not null,
  assessment    jsonb,             -- Haiku verdict on the new text; Opus re-read result when escalated
  cost_usd      numeric(10, 4) not null default 0,
  notified_at   timestamptz,       -- HIGH events: when the immediate alert went out
  digested_at   timestamptz        -- when it appeared in a morning email
);
create index if not exists watch_events_digest_idx on watch_events (digested_at);

do $$
declare t text;
begin
  foreach t in array array['watches','watch_events'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
