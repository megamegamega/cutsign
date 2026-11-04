-- Batched model calls. Paste into the Supabase SQL editor once (after 0006).
-- Work that can wait an hour — the hunt proposals of the queried stage (lib/queries.js) and the card
-- drafts, revisions and re-issue drafts of the card loop (lib/hype.js) — goes through the Batches API
-- at half price. A row here is one request in flight: what was asked, where its answer goes, and what
-- became of it; lib/jobs.js collects on the hourly tick. The payload holds ids, fact keys and change
-- lines, never source text. With this table missing the pipeline makes the same calls live, so the
-- code can deploy before the migration and switches over on its own once it is applied. Same lockdown
-- as 0001: RLS on, no policies, service role only.

create table if not exists llm_jobs (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  kind         text not null check (kind in ('proposal', 'card_draft')),
  status       text not null default 'pending' check (status in ('pending', 'done', 'failed', 'abandoned')),
  batch_id     text not null,
  custom_id    text not null,
  model        text,
  run_id       uuid references runs (id) on delete cascade,
  story_id     uuid references stories (id) on delete cascade,
  payload      jsonb not null default '{}',
  outcome      text,                                   -- why it failed or was abandoned; "live: …" when a live call finished it
  cost_usd     numeric(8,4) not null default 0,
  finished_at  timestamptz
);
create index if not exists llm_jobs_status_idx on llm_jobs (status, created_at);

do $$
declare t text;
begin
  foreach t in array array['llm_jobs'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
