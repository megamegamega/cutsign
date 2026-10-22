// Data layer. SERVER-ONLY: uses SUPABASE_SERVICE_KEY (bypasses RLS; the anon key can read nothing).
//
// Every pipeline stage talks to a `store` with the small interface below, never to Supabase
// directly — so tests run the whole pipeline against the in-memory store (lib/store-memory.js)
// with no network and no keys.

import { createClient } from '@supabase/supabase-js';

let _client;
function sb() {
  if (_client) return _client;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY; // service role — server only
  if (!url || !key) throw new Error('SUPABASE_URL / SUPABASE_SERVICE_KEY not set');
  _client = createClient(url, key, { auth: { persistSession: false } });
  return _client;
}

const must = ({ data, error }) => { if (error) throw new Error('db: ' + error.message); return data; };
// `.in()` lists go in the URL; keep each request well under PostgREST's limits.
async function inChunks(ids, fn, size = 100) {
  const out = [];
  for (let i = 0; i < ids.length; i += size) out.push(...must(await fn(ids.slice(i, i + size))));
  return out;
}
const nowIso = () => new Date().toISOString();

export function supabaseStore() {
  return {
    // ---- briefs ----
    async briefExists(messageId) {
      const d = must(await sb().from('briefs').select('id').eq('message_id', messageId).maybeSingle());
      return !!d;
    },
    async acceptedBriefForDate(date) {
      return must(await sb().from('briefs').select('id,message_id').eq('brief_date', date).eq('status', 'accepted').limit(1).maybeSingle());
    },
    async insertBrief(row) {
      // ignoreDuplicates: a concurrent poll that raced us on the same Message-ID is a no-op
      const d = must(await sb().from('briefs').upsert(row, { onConflict: 'message_id', ignoreDuplicates: true }).select('*'));
      return d?.[0] || null;
    },
    async getBrief(id) { return must(await sb().from('briefs').select('*').eq('id', id).single()); },
    async updateBrief(id, patch) { must(await sb().from('briefs').update(patch).eq('id', id)); },

    // ---- runs ----
    async insertRun(row) { return must(await sb().from('runs').insert(row).select('*').single()); },
    async getRun(id) { return must(await sb().from('runs').select('*').eq('id', id).single()); },
    async updateRun(id, patch) { must(await sb().from('runs').update({ ...patch, updated_at: nowIso() }).eq('id', id)); },
    /** Runs with work left: not sent, and not permanently failed. Oldest first. */
    async listOpenRuns() {
      return must(await sb().from('runs').select('*')
        .or('stage.not.in.(sent,failed),and(stage.eq.failed,attempts.lt.3)')
        .gte('started_at', new Date(Date.now() - 3 * 86400000).toISOString())
        .order('started_at', { ascending: true }));
    },
    /** Take a lease on a run; returns the run if we got it, null if another invocation holds it. */
    async claimRun(id, seconds) {
      const until = new Date(Date.now() + seconds * 1000).toISOString();
      const d = must(await sb().from('runs').update({ lease_until: until })
        .eq('id', id).or(`lease_until.is.null,lease_until.lt.${nowIso()}`).select('*'));
      return d?.[0] || null;
    },
    async releaseRun(id) { must(await sb().from('runs').update({ lease_until: null }).eq('id', id)); },
    async monthCostUsd() {
      const start = new Date(); start.setUTCDate(1); start.setUTCHours(0, 0, 0, 0);
      const d = must(await sb().from('runs').select('cost_usd').gte('started_at', start.toISOString()));
      // watch events (Haiku/Opus on changes) count toward the same cap; table may not exist before 0002
      const { data: ev } = await sb().from('watch_events').select('cost_usd').gte('created_at', start.toISOString());
      return [...(d || []), ...(ev || [])].reduce((s, r) => s + Number(r.cost_usd || 0), 0);
    },

    async listRecentSentRuns(days) {
      return must(await sb().from('runs').select('*').eq('stage', 'sent').eq('dry', false)
        .gte('started_at', new Date(Date.now() - days * 86400000).toISOString()).order('started_at'));
    },
    // ---- web search (api/page.js) ----
    async searchStories(q, limit = 30) {
      const pat = '%' + q.replace(/[%_,()]/g, ' ').trim() + '%';
      const ors = [`title.ilike.${pat}`, `summary.ilike.${pat}`, `threat_actor.ilike.${pat}`, `malware_family.ilike.${pat}`];
      if (/^cve-\d{4}-\d{4,}$/i.test(q.trim())) ors.push(`cves.cs.{${q.trim().toUpperCase()}}`);
      const rows = must(await sb().from('stories')
        .select('id,run_id,title,summary,section,severity,priority,selected,cves,threat_actor,malware_family,created_at')
        .eq('status', 'extracted').or(ors.join(','))
        .order('created_at', { ascending: false }).limit(limit));
      const runIds = [...new Set(rows.map((r) => r.run_id))];
      if (!runIds.length) return rows;
      const runs = must(await sb().from('runs').select('id,brief_id').in('id', runIds));
      const briefs = must(await sb().from('briefs').select('id,brief_date,received_at').in('id', runs.map((r) => r.brief_id)));
      const dateByRun = new Map(runs.map((r) => {
        const b = briefs.find((x) => x.id === r.brief_id) || {};
        return [r.id, b.brief_date || String(b.received_at || '').slice(0, 10)];
      }));
      return rows.map((r) => ({ ...r, brief_date: dateByRun.get(r.run_id) || '' }));
    },
    async searchIocs(q, limit = 30) {
      const pat = '%' + q.replace(/[%_,()]/g, ' ').trim() + '%';
      return must(await sb().from('iocs').select('type,value_norm,seen_count,first_seen_at,context,confidence')
        .ilike('value_norm', pat).order('first_seen_at', { ascending: false }).limit(limit));
    },
    // ---- watches ----
    async listActiveWatches() { return must(await sb().from('watches').select('*').eq('status', 'active')); },
    async insertWatch(row) { return must(await sb().from('watches').insert(row).select('*').single()); },
    async updateWatch(id, patch) { must(await sb().from('watches').update(patch).eq('id', id)); },
    async insertWatchEvents(rows) { if (rows.length) must(await sb().from('watch_events').insert(rows)); },
    /** { pendingAlert: HIGH not yet notified } | { undigested: not yet in a morning email } — with watch title */
    async listWatchEvents({ pendingAlert = false, undigested = false } = {}) {
      let q = sb().from('watch_events').select('*,watches(title,story_id)').order('created_at');
      if (pendingAlert) q = q.eq('level', 'HIGH').is('notified_at', null);
      if (undigested) q = q.is('digested_at', null);
      const rows = must(await q);
      return rows.map(({ watches, ...e }) => ({ ...e, watch_title: watches?.title || '(watch)', watch_story_id: watches?.story_id || null }));
    },
    async markWatchEvents(ids, patch) { if (ids.length) must(await sb().from('watch_events').update(patch).in('id', ids)); },
    async watchDeepCountSince(iso) {
      const { count, error } = await sb().from('watch_events').select('id', { count: 'exact', head: true })
        .gte('created_at', iso).not('assessment->deep', 'is', null);
      if (error) throw new Error('db: ' + error.message);
      return count || 0;
    },
    async getStory(id) { return must(await sb().from('stories').select('*').eq('id', id).maybeSingle()); },

    // ---- stories ----
    async upsertStories(rows) {
      if (!rows.length) return;
      must(await sb().from('stories').upsert(rows, { onConflict: 'run_id,ordinal', ignoreDuplicates: true }));
    },
    async listStories(runId) {
      return must(await sb().from('stories').select('*').eq('run_id', runId).order('ordinal'));
    },
    async updateStory(id, patch) { must(await sb().from('stories').update(patch).eq('id', id)); },
    /** Replace a story's behaviors + evidence atomically enough for a single writer (delete then insert). */
    async replaceStoryChildren(storyId, { behaviors, evidence }) {
      must(await sb().from('behaviors').delete().eq('story_id', storyId));
      must(await sb().from('evidence').delete().eq('story_id', storyId));
      if (behaviors.length) must(await sb().from('behaviors').insert(behaviors.map((b) => ({ ...b, story_id: storyId }))));
      if (evidence.length) must(await sb().from('evidence').insert(evidence.map((e) => ({ ...e, story_id: storyId }))));
    },
    async listBehaviors(storyIds) {
      return inChunks(storyIds, (ids) => sb().from('behaviors').select('*').in('story_id', ids));
    },
    async listEvidence(storyIds) {
      return inChunks(storyIds, (ids) => sb().from('evidence').select('*').in('story_id', ids));
    },
    /** Deep-read stories from OTHER runs in the last `days` days, full rows + their brief date (for reuse). */
    async listRecentDeepStories(runId, days) {
      const rows = must(await sb().from('stories').select('*,runs(briefs(brief_date))')
        .neq('run_id', runId).eq('status', 'extracted').eq('selected', true)
        .gte('created_at', new Date(Date.now() - days * 86400000).toISOString()));
      return rows.map(({ runs, ...s }) => ({ ...s, brief_date: runs?.briefs?.brief_date || null }));
    },
    /** Extracted stories from OTHER runs created in the last `days` days (for update matching / novelty). */
    async listPriorStories(runId, days) {
      const rows = must(await sb().from('stories').select('id,run_id,title,cves,threat_actor,malware_family,created_at,runs(briefs(brief_date))')
        .neq('run_id', runId).eq('status', 'extracted')
        .gte('created_at', new Date(Date.now() - days * 86400000).toISOString()));
      return rows.map(({ runs, ...s }) => ({ ...s, brief_date: runs?.briefs?.brief_date || null }));
    },

    // ---- sources ----
    async getSource(url) { return must(await sb().from('sources').select('*').eq('url', url).maybeSingle()); },
    async upsertSource(row) { must(await sb().from('sources').upsert(row, { onConflict: 'url' })); },
    async getSources(urls) {
      if (!urls.length) return [];
      return must(await sb().from('sources').select('*').in('url', urls));
    },

    // ---- iocs ----
    async getIoc(type, valueNorm) {
      return must(await sb().from('iocs').select('*').eq('type', type).eq('value_norm', valueNorm).maybeSingle());
    },
    async insertIoc(row) { return must(await sb().from('iocs').insert(row).select('*').single()); },
    async updateIoc(id, patch) { must(await sb().from('iocs').update(patch).eq('id', id)); },
    async linkStoryIoc(storyId, iocId, role) {
      must(await sb().from('story_iocs').upsert({ story_id: storyId, ioc_id: iocId, role }, { onConflict: 'story_id,ioc_id,role', ignoreDuplicates: true }));
    },
    /** Story↔IoC links with the IoC row joined, for rendering. */
    async listStoryIocs(storyIds) {
      return (await inChunks(storyIds, (ids) => sb().from('story_iocs').select('story_id,role,iocs(*)').in('story_id', ids)))
        .map((r) => ({ story_id: r.story_id, role: r.role, ioc: r.iocs }));
    },
  };
}
