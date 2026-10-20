-- Cutsign v0 schema. Paste into the Supabase SQL editor (or psql) once.
-- Every table has RLS ON with NO policies and is revoked from anon/authenticated:
-- only the service-role key (server-side, Vercel env) can read or write.
--
-- No-employer-data rule: there is deliberately no column anywhere for internal hostnames,
-- usernames, index names, ticket numbers, or query results. Do not add one.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- briefs: one row per inbound Gmail message, keyed by RFC 822 Message-ID.
create table if not exists briefs (
  id            uuid primary key default gen_random_uuid(),
  message_id    text not null unique,
  gmail_id      text,
  received_at   timestamptz,
  from_addr     text,
  subject       text,
  brief_date    date,                         -- date in the subject line, used for one-brief-per-day
  status        text not null default 'accepted'
                check (status in ('accepted', 'rejected', 'ignored')),
  status_reason text,
  raw_mime      text,                         -- retention: 30 days (cleanup job, later)
  clean_text    text,
  urls          text[] not null default '{}',
  created_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- runs: one per accepted brief. `stage` is the last stage that COMPLETED.
create table if not exists runs (
  id            uuid primary key default gen_random_uuid(),
  brief_id      uuid not null unique references briefs (id) on delete cascade,
  stage         text not null default 'received'
                check (stage in ('received', 'parsed', 'fetched', 'extracted', 'normalized',
                                 'validated', 'queried', 'rendered', 'sent', 'failed')),
  failed_stage  text,                         -- stage that was being attempted when it failed
  attempts      int not null default 0,       -- failures so far; gives up at 3
  dry           boolean not null default false,
  lease_until   timestamptz,                  -- simple lock so two invocations never run one run
  started_at    timestamptz not null default now(),
  finished_at   timestamptz,
  updated_at    timestamptz not null default now(),
  counts        jsonb not null default '{}',
  error         text,
  model         text,
  tokens_in     int not null default 0,
  tokens_out    int not null default 0,
  cost_usd      numeric(10, 4) not null default 0
);
create index if not exists runs_stage_idx on runs (stage);
create index if not exists runs_started_idx on runs (started_at);

-- ---------------------------------------------------------------------------
-- stories: one per brief item (deterministically split at parse time).
create table if not exists stories (
  id                 uuid primary key default gen_random_uuid(),
  run_id             uuid not null references runs (id) on delete cascade,
  ordinal            int not null,
  section            text,                    -- brief section heading
  severity           text,                    -- brief's own [Critical]/[High]/... tag
  brief_text         text,                    -- the brief's text for this item
  selected           boolean not null default false,  -- chosen for extraction
  status             text not null default 'pending'
                     check (status in ('pending', 'extracted', 'skipped', 'failed')),
  extract_error      text,
  title              text,
  summary            text,
  threat_actor       text,
  malware_family     text,
  cves               text[] not null default '{}',
  attack_techniques  text[] not null default '{}',
  sector_relevance   text[] not null default '{}',
  priority           smallint check (priority between 1 and 3),
  priority_reason    text,
  source_urls        text[] not null default '{}',
  suspicious_sources text[] not null default '{}',
  first_published_at date,
  raw_iocs           jsonb,                   -- extraction output, consumed by the normalize stage
  fingerprint        text,                    -- v2 seam: story fingerprinting
  updates_story_id   uuid references stories (id) on delete set null,  -- v2 seam
  created_at         timestamptz not null default now(),
  unique (run_id, ordinal)
);

-- ---------------------------------------------------------------------------
-- sources: fetched pages, cached by URL.
create table if not exists sources (
  id            uuid primary key default gen_random_uuid(),
  url           text not null unique,
  final_url     text,
  fetched_at    timestamptz,
  status        int,                          -- HTTP status; 0 = network error/timeout
  outcome       text,                         -- ok | http_error | timeout | too_large | robots | unsupported | error
  error         text,
  content_hash  text,
  clean_text    text,                         -- capped; retention 90 days (later)
  publisher     text,
  published_at  date,
  suspicious    boolean not null default false,
  suspicious_reason text,
  links         text[] not null default '{}'  -- outbound links (for the one-hop-to-vendor rule)
);

-- ---------------------------------------------------------------------------
create table if not exists behaviors (
  id                uuid primary key default gen_random_uuid(),
  story_id          uuid not null references stories (id) on delete cascade,
  attack_technique  text,
  pattern_kind      text not null
                    check (pattern_kind in ('shell_from_server_process', 'discovery_burst', 'download_cradle',
                                            'persistence_artifact', 'credential_access', 'lateral_auth',
                                            'defense_evasion', 'exfil_channel', 'other')),
  parent            text,
  children          text[] not null default '{}',
  log_source        text,
  time_window       text,
  vendor_stated     boolean not null default false,
  source_quote_ref  text
);
create index if not exists behaviors_story_idx on behaviors (story_id);

-- ---------------------------------------------------------------------------
-- evidence: published detection guidance AND printed evidence samples, split by kind.
create table if not exists evidence (
  id                uuid primary key default gen_random_uuid(),
  story_id          uuid not null references stories (id) on delete cascade,
  kind              text not null
                    check (kind in ('guidance', 'log_line', 'command_line', 'http_request',
                                    'process_tree', 'file_path', 'registry', 'other')),
  raw               text not null check (char_length(raw) <= 2048),
  log_source        text,
  attack_technique  text,
  url               text,
  publisher_tier    char(1) check (publisher_tier in ('A', 'B', 'C', 'D', 'E', 'F')),
  source_quote_ref  text
);
create index if not exists evidence_story_idx on evidence (story_id);

-- ---------------------------------------------------------------------------
create table if not exists iocs (
  id                 uuid primary key default gen_random_uuid(),
  type               text not null
                     check (type in ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email',
                                     'filename', 'filepath', 'registry', 'mutex', 'ja3', 'ja4',
                                     'useragent', 'cve', 'yara_name', 'cert_sha1')),
  value              text not null,
  value_norm         text not null,
  first_seen_run_id  uuid references runs (id) on delete set null,
  last_seen_run_id   uuid references runs (id) on delete set null,
  first_seen_at      timestamptz not null default now(),
  seen_count         int not null default 1,
  confidence         text check (confidence in ('vendor_stated', 'inferred')),
  context            text,
  tlp                text not null default 'CLEAR',
  unique (type, value_norm)
);

create table if not exists story_iocs (
  story_id  uuid not null references stories (id) on delete cascade,
  ioc_id    uuid not null references iocs (id) on delete cascade,
  role      text not null default 'unknown',
  primary key (story_id, ioc_id, role)
);

-- ---------------------------------------------------------------------------
-- Lock everything down: RLS on, no policies, no grants to the public API roles.
do $$
declare t text;
begin
  foreach t in array array['briefs','runs','stories','sources','behaviors','evidence','iocs','story_iocs'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
