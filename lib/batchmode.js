// Whether model calls that can wait go through the Batches API (half price, answered within a day,
// collected by lib/jobs.js on the watch tick): LLM_BATCH is not 0 and the llm_jobs table exists
// (supabase/migrations/0007_llm_jobs.sql). The table is probed once every five minutes, so a deploy
// ahead of the migration makes the same calls live and switches over on its own once it is applied.

const PROBE_MS = 300_000;
let probe = { at: 0, ok: false };

export async function batchMode(store) {
  if (process.env.LLM_BATCH === '0') return false;
  if (Date.now() - probe.at < PROBE_MS) return probe.ok;
  let ok = false;
  try { await store.listJobs({ limit: 1 }); ok = true; } catch { ok = false; }
  probe = { at: Date.now(), ok };
  return ok;
}

/** Tests: forget the probe (a store swapped under the module). */
export function _resetBatchMode() { probe = { at: 0, ok: false }; }
