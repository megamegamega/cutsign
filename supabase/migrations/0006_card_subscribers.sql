-- Cutsign card card_subscribers. Paste into the Supabase SQL editor once (after 0005).
-- lib/subscribe.js: an address signs up on the site, confirms by link, and gets one mail per new
-- verdict card (AI-published or hand-written) with an unsubscribe link. The address is stored for
-- this and nothing else, never rendered on a page or written to a log. Same lockdown as 0001: RLS
-- on, no policies, service role only.

create table if not exists card_subscribers (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  requested_at    timestamptz not null default now(),   -- latest sign-up request (a re-subscribe refreshes it)
  email           text not null unique,
  token           text not null unique,                 -- confirm / unsubscribe link token, rotated on every request
  status          text not null default 'pending' check (status in ('pending', 'confirmed', 'unsubscribed')),
  confirmed_at    timestamptz,
  unsubscribed_at timestamptz
);
create index if not exists subscribers_status_idx on card_subscribers (status);

do $$
declare t text;
begin
  foreach t in array array['card_subscribers'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
