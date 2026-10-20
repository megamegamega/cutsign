// In-memory store with the same interface as supabaseStore() — for tests and offline dry runs.

import { randomUUID } from 'node:crypto';

export function memoryStore() {
  const t = { briefs: [], runs: [], stories: [], sources: [], behaviors: [], evidence: [], iocs: [], story_iocs: [] };
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
    async monthCostUsd() { return t.runs.reduce((s, r) => s + Number(r.cost_usd || 0), 0); },

    async upsertStories(rows) {
      for (const row of rows) {
        if (t.stories.some((s) => s.run_id === row.run_id && s.ordinal === row.ordinal)) continue;
        t.stories.push({ id: randomUUID(), created_at: nowIso(), status: 'pending', selected: false, cves: [], attack_techniques: [],
          sector_relevance: [], source_urls: [], suspicious_sources: [], ...row });
      }
    },
    async listStories(runId) { return clone(t.stories.filter((s) => s.run_id === runId).sort((a, b) => a.ordinal - b.ordinal)); },
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
    async listPriorStories(runId, days) {
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();
      return clone(t.stories.filter((s) => s.run_id !== runId && s.status === 'extracted' && s.created_at >= cutoff));
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
