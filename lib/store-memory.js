// In-memory store with the same interface as supabaseStore() — for tests and offline dry runs.

import { randomUUID } from 'node:crypto';

export function memoryStore() {
  const t = { briefs: [], runs: [], stories: [], sources: [], behaviors: [], evidence: [], iocs: [], story_iocs: [], watches: [], watch_events: [], card_drafts: [], subscribers: [] };
  const clone = (x) => (x == null ? x : structuredClone(x));
  const nowIso = () => new Date().toISOString();

  return {
    _tables: t,

    async briefExists(messageId) { return t.briefs.some((b) => b.message_id === messageId); },
    async acceptedBriefForDate(date) { return clone(t.briefs.find((b) => b.brief_date === date && b.status === 'accepted')) || null; },
    async insertBrief(row) {
      if (t.briefs.some((b) => b.message_id === row.message_id)) return null;
      const r = { id: randomUUID(), status: 'accepted', urls: [], created_at: nowIso(), ...row };
      t.briefs.push(r); return clone(r);
    },
    async getBrief(id) { return clone(t.briefs.find((b) => b.id === id)); },
    async updateBrief(id, patch) { Object.assign(t.briefs.find((b) => b.id === id), patch); },

    async insertRun(row) {
      const r = { id: randomUUID(), stage: 'received', attempts: 0, dry: false, lease_until: null, started_at: nowIso(),
        counts: {}, tokens_in: 0, tokens_out: 0, cost_usd: 0, ...row };
      t.runs.push(r); return clone(r);
    },
    async getRun(id) { return clone(t.runs.find((r) => r.id === id)); },
    async updateRun(id, patch) { Object.assign(t.runs.find((r) => r.id === id), patch, { updated_at: nowIso() }); },
    async listOpenRuns() {
      return clone(t.runs.filter((r) => (r.stage !== 'sent' && r.stage !== 'failed') || (r.stage === 'failed' && r.attempts < 3)));
    },
    async claimRun(id, seconds) {
      const r = t.runs.find((x) => x.id === id);
      if (r.lease_until && new Date(r.lease_until) > new Date()) return null;
      r.lease_until = new Date(Date.now() + seconds * 1000).toISOString();
      return clone(r);
    },
    async releaseRun(id) { t.runs.find((r) => r.id === id).lease_until = null; },
    async monthCostUsd() { return [...t.runs, ...t.watch_events, ...t.card_drafts].reduce((s, r) => s + Number(r.cost_usd || 0), 0); },

    async insertCardDraft(row) { const r = { id: randomUUID(), created_at: nowIso(), status: 'draft', promoted_slug: null, ...clone(row) }; t.card_drafts.push(r); return clone(r); },
    async getCardDraft(id) { return clone(t.card_drafts.find((d) => d.id === id)) || null; },
    async listCardDrafts({ storyIds = null, status = null, limit = 20 } = {}) {
      return clone(t.card_drafts.filter((d) => (!status || d.status === status) && (!storyIds || d.thread_ids.some((i) => storyIds.includes(i))))
        .sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, limit));
    },
    async updateCardDraft(id, patch) { Object.assign(t.card_drafts.find((d) => d.id === id), clone(patch)); },

    async getSubscriberByEmail(email) { return clone(t.subscribers.find((s) => s.email === email)) || null; },
    async getSubscriberByToken(token) { return clone(t.subscribers.find((s) => s.token === token)) || null; },
    async insertSubscriber(row) {
      if (t.subscribers.some((s) => s.email === row.email || s.token === row.token)) throw new Error('duplicate key value violates unique constraint');
      const r = { id: randomUUID(), created_at: nowIso(), requested_at: nowIso(), status: 'pending', confirmed_at: null, unsubscribed_at: null, ...clone(row) };
      t.subscribers.push(r); return clone(r);
    },
    async updateSubscriber(id, patch) { Object.assign(t.subscribers.find((s) => s.id === id), clone(patch)); },
    async listSubscribers({ status = 'confirmed', limit = 1000 } = {}) { return clone(t.subscribers.filter((s) => s.status === status).slice(0, limit)); },
    async countSubscribersSince(iso) { return t.subscribers.filter((s) => s.requested_at >= iso).length; },

    async listRecentSentRuns() { return clone(t.runs.filter((r) => r.stage === 'sent' && !r.dry)); },
    async listActiveWatches() { return clone(t.watches.filter((w) => w.status === 'active')); },
    async insertWatch(row) { const r = { id: randomUUID(), created_at: nowIso(), status: 'active', state: {}, ...row }; t.watches.push(r); return clone(r); },
    async updateWatch(id, patch) { Object.assign(t.watches.find((w) => w.id === id), clone(patch)); },
    async watchFacts(storyIds) { return clone(t.watches.filter((w) => storyIds.includes(w.story_id)).map(({ story_id, status, expires_at, last_change_at }) => ({ story_id, status, expires_at, last_change_at }))); },
    async insertWatchEvents(rows) { for (const r of rows) t.watch_events.push({ id: randomUUID(), created_at: nowIso(), notified_at: null, digested_at: null, ...clone(r) }); },
    async listWatchEvents({ pendingAlert = false, undigested = false, since = null } = {}) {
      return clone(t.watch_events
        .filter((e) => (!pendingAlert || (e.level === 'HIGH' && !e.notified_at)) && (!undigested || !e.digested_at) && (!since || e.created_at >= since))
        .map((e) => { const w = t.watches.find((x) => x.id === e.watch_id); return { ...e, watch_title: w?.title || '(watch)', watch_story_id: w?.story_id || null }; }));
    },
    async markWatchEvents(ids, patch) { for (const e of t.watch_events) if (ids.includes(e.id)) Object.assign(e, patch); },
    async listWatchDevelopments(watchId, sinceIso) {
      return clone(t.watch_events.filter((e) => e.watch_id === watchId && e.created_at > sinceIso && (e.level === 'HIGH' || e.assessment?.material)));
    },
    async watchDeepCountSince(iso) { return t.watch_events.filter((e) => e.created_at >= iso && e.assessment?.deep).length; },
    async getStory(id) { return clone(t.stories.find((s) => s.id === id)) || null; },
    async getStories(ids) { return clone(t.stories.filter((s) => ids.includes(s.id))); },

    async upsertStories(rows) {
      for (const row of rows) {
        if (t.stories.some((s) => s.run_id === row.run_id && s.ordinal === row.ordinal)) continue;
        t.stories.push({ id: randomUUID(), created_at: nowIso(), status: 'pending', selected: false, cves: [], attack_techniques: [],
          sector_relevance: [], source_urls: [], suspicious_sources: [], ...row });
      }
    },
    async listStories(runId) { return clone(t.stories.filter((s) => s.run_id === runId).sort((a, b) => a.ordinal - b.ordinal)); },
    async listStoriesByCves(cves, limit = 10) {
      const want = new Set(cves.map((c) => c.toUpperCase()));
      return clone(t.stories.filter((s) => s.status === 'extracted' && (s.cves || []).some((c) => want.has(c.toUpperCase()))).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, limit));
    },
    async updateStory(id, patch) { Object.assign(t.stories.find((s) => s.id === id), patch); },
    async replaceStoryChildren(storyId, { behaviors, evidence }) {
      t.behaviors = t.behaviors.filter((b) => b.story_id !== storyId);
      t.evidence = t.evidence.filter((e) => e.story_id !== storyId);
      for (const b of behaviors) t.behaviors.push({ id: randomUUID(), ...b, story_id: storyId });
      for (const e of evidence) {
        if (e.raw.length > 2048) throw new Error('evidence.raw exceeds 2048 (CHECK)');
        t.evidence.push({ id: randomUUID(), ...e, story_id: storyId });
      }
    },
    async listBehaviors(ids) { return clone(t.behaviors.filter((b) => ids.includes(b.story_id))); },
    async listEvidence(ids) { return clone(t.evidence.filter((e) => ids.includes(e.story_id))); },
    async listRecentDeepStories(runId, days) {
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();
      const briefDate = (s) => t.briefs.find((b) => b.id === t.runs.find((r) => r.id === s.run_id)?.brief_id)?.brief_date || null;
      return clone(t.stories.filter((s) => s.run_id !== runId && s.status === 'extracted' && s.selected && s.created_at >= cutoff)
        .map((s) => ({ ...s, brief_date: briefDate(s) })));
    },
    async listPriorStories(runId, days) {
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();
      const briefDate = (s) => t.briefs.find((b) => b.id === t.runs.find((r) => r.id === s.run_id)?.brief_id)?.brief_date || null;
      return clone(t.stories.filter((s) => s.run_id !== runId && s.status === 'extracted' && s.created_at >= cutoff)
        .map((s) => ({ ...s, brief_date: briefDate(s) })));
    },

    async getSource(url) { return clone(t.sources.find((s) => s.url === url)) || null; },
    async upsertSource(row) {
      const i = t.sources.findIndex((s) => s.url === row.url);
      if (i >= 0) t.sources[i] = { ...t.sources[i], ...row }; else t.sources.push({ id: randomUUID(), ...row });
    },
    async getSources(urls) { return clone(t.sources.filter((s) => urls.includes(s.url))); },

    async getIoc(type, valueNorm) { return clone(t.iocs.find((i) => i.type === type && i.value_norm === valueNorm)) || null; },
    async insertIoc(row) {
      const r = { id: randomUUID(), seen_count: 1, tlp: 'CLEAR', first_seen_at: nowIso(), ...row };
      t.iocs.push(r); return clone(r);
    },
    async updateIoc(id, patch) { Object.assign(t.iocs.find((i) => i.id === id), patch); },
    async linkStoryIoc(storyId, iocId, role) {
      if (!t.story_iocs.some((l) => l.story_id === storyId && l.ioc_id === iocId && l.role === role)) {
        t.story_iocs.push({ story_id: storyId, ioc_id: iocId, role });
      }
    },
    async listStoryIocs(ids) {
      return t.story_iocs.filter((l) => ids.includes(l.story_id))
        .map((l) => ({ story_id: l.story_id, role: l.role, ioc: clone(t.iocs.find((i) => i.id === l.ioc_id)) }));
    },
  };
}
