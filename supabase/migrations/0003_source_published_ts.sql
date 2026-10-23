-- sources.published_at: date → timestamptz, so the hour/minute from article
-- metadata (article:published_time etc.) survives. Existing rows become
-- midnight UTC; the UI shows a time only when it is not exactly 00:00,
-- so old rows keep reading as date-only.
alter table sources alter column published_at type timestamptz using published_at::timestamptz;
