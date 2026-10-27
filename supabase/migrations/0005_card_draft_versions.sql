-- Card drafts become a loop. A draft is regenerated when the thread's evidence changes (a new day
-- of the story, new published guidance, new IoCs, a KEV listing, a material watch development);
-- each regeneration is a new row that supersedes the previous one, carrying the evidence
-- fingerprint it was built from. surfaced_at marks the moment a draft crossed the high bar and
-- was shown on the CISO view. Paste into the Supabase SQL editor once (after 0004).

alter table card_drafts add column if not exists version     int not null default 1;
alter table card_drafts add column if not exists supersedes  uuid references card_drafts (id) on delete set null;
alter table card_drafts add column if not exists fingerprint text;
alter table card_drafts add column if not exists surfaced_at timestamptz;
alter table card_drafts drop constraint if exists card_drafts_status_check;
alter table card_drafts add constraint card_drafts_status_check
  check (status in ('draft', 'superseded', 'promoted', 'dismissed'));
