-- Cutsign card drafts. Paste into the Supabase SQL editor once (after 0002).
-- lib/hype.js scores every brief's stories for "will the CISO ask about this"; over the draft bar
-- it has Opus assemble a verdict-card draft from the stored story, guidance and IoCs. A draft is
-- private-by-obscurity (uuid URL, noindex), carries an "unreviewed" banner, and is never in the
-- manifest: promoting one to public/cards/ is a human edit. Same lockdown as 0001: RLS on, no
-- policies, service role only.

create table if not exists card_drafts (
  id             uuid primary key default gen_random_uuid(),
  created_at     timestamptz not null default now(),
  story_id       uuid references stories (id) on delete set null,   -- newest story in the thread
  thread_ids     uuid[] not null default '{}',                      -- every story row in the update chain
  title          text not null,
  score          int not null,
  reasons        text[] not null default '{}',
  draft          jsonb not null,                                     -- lib/carddraft.js DraftSchema
  model          text,
  cost_usd       numeric(8,4) not null default 0,
  status         text not null default 'draft' check (status in ('draft', 'promoted', 'dismissed')),
  promoted_slug  text
);
create index if not exists card_drafts_status_idx on card_drafts (status, created_at desc);
create index if not exists card_drafts_thread_idx on card_drafts using gin (thread_ids);

do $$
declare t text;
begin
  foreach t in array array['card_drafts'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
