// The hunt-query proposer: shape proposals from one story record, lint-gated, placeholders only,
// published as candidates; the `queried` stage resumes without duplicates and skips stories whose
// telemetry is `other` only; past 80% of the monthly cap the deep tier stands in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns, advanceRun } from '../lib/pipeline.js';
import { buildDigestData, renderHtml } from '../lib/render.js';
import { generateQueries, finishProposals, storyTelemetryKeys, buildProposeInput, queryLiterals, eligible } from '../lib/queries.js';
import { lintSpl, lintEsql } from '../lib/lint.js';
import { fixtureMessage, fakeFetch, installFakeLLM, installFakeBatch, defaultResponder, captureOutputs, NETSCALER_EXTRACTION } from './helpers.js';
import { collectJobs } from '../lib/jobs.js';
import { _resetBatchMode } from '../lib/batchmode.js';

const J = (...a) => a.join('');
const HYGIENE = [/\bindex\s*=\s*(?!\*)[a-z_]/i, /\b[a-z0-9-]+\.(corp|internal|intranet|lan)\.[a-z]{2,}\b/i, /\b(sourcetype)\s*=\s*"?[a-z]+:[a-z]/i];

// A ConnectWise-shaped record: service-principal sign-ins then mailbox access, seven appIds
const APPIDS = Array.from({ length: 7 }, (_, i) => `${String(i + 1).repeat(8)}-${String(i + 1).repeat(4)}-4${String(i + 1).repeat(3)}-8${String(i + 1).repeat(3)}-${String(i + 1).repeat(12)}`);
const CW = {
  story: {
    id: 'cw000000-0000-4000-8000-000000000001', title: 'Storm-0940 abuses a cloud backup app credential in M365 tenants',
    summary: `Seven application IDs (${APPIDS.join(', ')}) were used to obtain service-principal tokens and read mail.`,
    priority: 1, selected: true, status: 'extracted', cves: [], threat_actor: 'Storm-0940', malware_family: null,
    raw_iocs: { exposure: { only_if: ['tenant has the backup app consented'], affected: [], not_affected_if: [], fixed_in: null } },
  },
  behaviors: [
    { attack_technique: 'T1528', pattern_kind: 'credential_access', parent: null, children: [], log_source: 'Entra ID service-principal sign-in logs', vendor_stated: true, source_quote_ref: 'S1' },
    { attack_technique: 'T1114.002', pattern_kind: 'exfil_channel', parent: null, children: [], log_source: 'Microsoft 365 Unified Audit Log (MailItemsAccessed)', vendor_stated: true, source_quote_ref: 'S1' },
  ],
  guidance: [{ kind: 'guidance', raw: 'Hunt SP sign-ins by the listed appIds, then MailItemsAccessed by the same ClientAppId within the hour', log_source: 'Entra sign-in logs, UAL', publisher_tier: 'B', url: 'https://vendor.example.test/g' }],
  samples: [], iocs: [],
};

const PROPOSAL = (over = {}) => ({ proposed_queries: [{
  shape: 'correlation', name: 'sp_token_then_mail_access',
  hypothesis: 'A listed appId obtains a service-principal token and then reads mail within an hour.',
  stages: [
    { log_source_key: 'entra_signin', predicate: 'service-principal sign-in by a listed appId', fields: ['appId', 'resourceDisplayName'] },
    { log_source_key: 'm365_ual', predicate: 'MailItemsAccessed by the same ClientAppId', fields: ['ClientAppId (Splunk: ClientAppId; ECS: o365.audit.ClientAppId)', 'Operation'] },
  ],
  join: { on: 'appId', window: '1h' },
  splunk: `index=<entra_signin> appId="${APPIDS[0]}" | join type=inner appId [ search index=<m365_ual> Operation=MailItemsAccessed | rename ClientAppId as appId | fields appId ] | table _time appId`,
  elastic: `FROM <entra_signin> | WHERE appId == "${APPIDS[0]}" | LOOKUP JOIN <m365_ual> ON appId | KEEP appId`,
  params: [{ name: 'app_id', value: APPIDS[0] }],
  noise_hint: 'the backup job itself reads mail on a schedule; exclude the tenant-approved appId and its known IP ranges',
  from: ['behaviors[0]', 'behaviors[1]', 'detection_guidance[0]'], confidence: 'derived', ...over,
}] });

test('a ConnectWise-shaped story yields a lint-clean correlation with two stages, a join, and every literal in params', async () => {
  assert.deepEqual(storyTelemetryKeys(CW).sort(), ['entra_signin', 'm365_ual']);
  const input = buildProposeInput(CW);
  assert.match(input, /\[behaviors\[1\]\]/); assert.match(input, /<vocabulary>/); assert.match(input, /<story_telemetry>entra_signin, m365_ual<\/story_telemetry>/);
  const calls = installFakeLLM(() => PROPOSAL());
  const r = await generateQueries({ ...CW, spent: 1, cap: 25 });
  assert.equal(calls.length, 1); assert.equal(calls[0].tier, 'propose'); assert.equal(calls[0].schemaName, 'proposal'); assert.equal(calls[0].model, 'claude-sonnet-5-5', 'the proposer runs on Sonnet 5.5 since 2026-11-12 (Opus 5.5 or Fable 5.1 by LLM_MODEL_PROPOSE)');
  assert.equal(r.model_tier, 'propose'); assert.equal(r.dropped.length, 0, JSON.stringify(r.dropped));
  const corr = r.proposals.filter((p) => p.shape === 'correlation');
  assert.equal(corr.length, 1); assert.equal(corr[0].stages.length, 2); assert.deepEqual(corr[0].join, { on: 'appId', window: '1h' });
  for (const p of r.proposals) {
    assert.equal(p.tier, 'proposed'); assert.ok(p.id); assert.equal(p.model_tier, 'propose'); assert.ok(p.cost_usd > 0);
    assert.ok(lintSpl(p.splunk, { allowed: () => true }).ok); assert.ok(lintEsql(p.elastic, { allowed: () => true }).ok);
    const have = new Set(Object.values(p.params));
    for (const lit of queryLiterals(p.splunk, p.elastic)) assert.ok(have.has(lit), `literal ${lit} missing from params`);
    for (const re of HYGIENE) assert.ok(!re.test(JSON.stringify(p)), `hygiene ${re}`);
  }
  assert.deepEqual(r.proposals[0].params, { app_id: APPIDS[0] });
});

test('finishProposals drops what the rules forbid and lists the reason', () => {
  const record = { story: CW.story, behaviors: CW.behaviors, guidance: CW.guidance };
  const run = (over) => finishProposals(PROPOSAL(over), { record, model: 'm', model_tier: 'propose', cost: 0.1 });
  const bad = (over, re) => { const r = run(over); assert.equal(r.proposals.length, 0); assert.ok(r.dropped[0].reasons.some((x) => re.test(x)), r.dropped[0].reasons.join('; ')); };
  bad({ splunk: J('index', '=main | stats count') }, /literal index name/);
  bad({ elastic: 'FROM logs-* | STATS COUNT(*)' }, /FROM must use/);
  bad({ noise_hint: ' ' }, /noise_hint required/);
  bad({ from: [] }, /from citations required/);
  bad({ stages: [{ log_source_key: 'other', predicate: 'x', fields: [] }, { log_source_key: 'm365_ual', predicate: 'y', fields: [] }] }, /not in vocabulary/);
  bad({ shape: 'single_source' }, /single_source needs exactly one stage/);
  bad({ join: null }, /needs two or more stages and a join/);
  bad({ splunk: 'index=<entra_signin> appId="99999999-9999-4999-8999-999999999999" | stats count' }, /literal not in the story record/);
  // a literal the model used but forgot to list is added to params rather than dropped
  const r = run({ params: [] });
  assert.equal(r.proposals.length, 1); assert.deepEqual(r.proposals[0].params, { p1: APPIDS[0] });
  assert.equal(r.proposals[0].cost_usd, 0.1);
});

test('at or past 80% of the monthly cap the proposer runs on the deep tier and says so', async () => {
  const calls = installFakeLLM(() => PROPOSAL());
  const r = await generateQueries({ ...CW, spent: 8, cap: 10 });
  assert.equal(calls[0].tier, 'deep'); assert.equal(calls[0].model, 'claude-sonnet-5-5');
  assert.equal(r.model_tier, 'deep'); assert.equal(r.proposals[0].model_tier, 'deep');
  const r2 = await generateQueries({ ...CW, spent: 7.9, cap: 10 });
  assert.equal(r2.model_tier, 'propose');
});

test('a story whose telemetry is other only, or one family only, gets no call and an empty list', async () => {
  const calls = installFakeLLM(() => PROPOSAL());
  const r = await generateQueries({ ...CW, behaviors: CW.behaviors.map((b) => ({ ...b, log_source: 'unspecified' })), guidance: [], samples: [] });
  assert.equal(calls.length, 0); assert.deepEqual(r.proposals, []); assert.match(r.skipped, /other only/);
  // one family: template territory, the proposer stays out
  const one = await generateQueries({ ...CW, behaviors: CW.behaviors.map((b) => ({ ...b, log_source: 'Entra ID sign-in logs' })), guidance: [], samples: [] });
  assert.equal(calls.length, 0); assert.match(one.skipped, /one telemetry family \(entra_signin\)/);
  assert.ok(eligible({ selected: true, status: 'extracted', priority: 2 }));
  assert.ok(!eligible({ selected: true, status: 'extracted', priority: 3 }));
  assert.ok(!eligible({ selected: false, status: 'extracted', priority: 1 }));
});

const NS_PROPOSAL = { proposed_queries: [{
  shape: 'correlation', name: 'nsppe_shell_then_download', hypothesis: 'The packet engine spawns a shell that then fetches a payload.',
  stages: [{ log_source_key: 'appliance_logs', predicate: 'child of nsppe is a shell or interpreter', fields: ['parent', 'child'] },
    { log_source_key: 'endpoint_process', predicate: 'that shell runs curl or wget', fields: ['process.parent.name', 'process.name'] }], join: { on: 'host', window: '5m' },
  splunk: 'index=<appliance_logs> parent=nsppe | join type=inner host [ search index=<endpoint_process> process.name=curl | fields host ] | stats count by child',
  elastic: 'FROM <appliance_logs> | WHERE process.parent.name == "nsppe" | LOOKUP JOIN <endpoint_process> ON host | STATS c = COUNT(*) BY process.name',
  params: [], noise_hint: 'vendor maintenance scripts run as root from the same parent; exclude the documented script paths', from: ['behaviors[0]', 'behaviors[1]'], confidence: 'derived',
}] };
// the NetScaler fixture names one telemetry family; give its guidance a second so the proposer has a correlation to make
const NS_TWO = { ...NETSCALER_EXTRACTION, detection_guidance: NETSCALER_EXTRACTION.detection_guidance.map((g, i) => (i ? g : { ...g, log_source: 'EDR process events and appliance logs' })) };
const nsTwoResponder = (user, n, req) => (req.schemaName === 'proposal' ? NS_PROPOSAL : /nsppe|NetScaler ADC post-exploitation/.test(user) ? NS_TWO : defaultResponder(user, n, req));

test('stage queried: proposals for the deep P1 story, the ✔ line counts them, the email omits them, a resumed stage does not propose twice', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  const calls = installFakeLLM(nsTwoResponder);
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const run = store._tables.runs[0];
  assert.equal(run.stage, 'sent');
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.equal(ns.raw_iocs.proposed_queries.length, 1);
  assert.equal(ns.raw_iocs.proposed_queries[0].tier, 'proposed'); assert.equal(ns.raw_iocs.proposals.model_tier, 'propose');
  assert.equal(run.counts.proposals, 1); assert.equal(run.counts.calls_propose, 1); assert.ok(run.counts.cost_propose > 0);
  assert.ok(out.discord.at(-1).includes('proposals +1'), out.discord.at(-1));
  assert.ok(out.discord.at(-1).includes('proposer $'), out.discord.at(-1));
  assert.doesNotMatch(out.emails[0].html, /Proposed hunts/, 'candidates never reach the brief');
  const d = await buildDigestData(store, run);
  assert.match(renderHtml(d, 0, { proposals: true }), /Proposed hunts \(1\) · candidates, not detections/);
  assert.doesNotMatch(renderHtml(d, 0), /Proposed hunts/);
  // the quiet stories were never proposed on (not deep, or P3)
  assert.ok(store._tables.stories.filter((s) => s.id !== ns.id).every((s) => !s.raw_iocs?.proposals));
  // resume: the stage runs again (a later stage failed and was retried) and finds its work done
  const before = calls.filter((c) => c.schemaName === 'proposal').length;
  await store.updateRun(run.id, { stage: 'validated' });
  assert.equal(await advanceRun(store, run.id, { fetchImpl: fakeFetch() }), 'sent');
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, before, 'no second proposal call');
  assert.equal(store._tables.stories.find((s) => s.id === ns.id).raw_iocs.proposed_queries.length, 1, 'no duplicate proposals');
});

test('stage queried: a deep story with one telemetry family is skipped without a call (template territory)', async () => {
  captureOutputs();
  const store = memoryStore();
  const calls = installFakeLLM((user, n, req) => (req.schemaName === 'proposal' ? NS_PROPOSAL : defaultResponder(user, n, req)));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.ok(ns.selected);
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, 0);
  assert.deepEqual(ns.raw_iocs.proposed_queries, []); assert.match(ns.raw_iocs.proposals.skipped, /one telemetry family \(appliance_logs\)/);
});

test('stage queried: a deep story with other-only telemetry yields an empty list and no model call', async () => {
  captureOutputs();
  const store = memoryStore();
  const blind = structuredClone(NETSCALER_EXTRACTION);
  for (const b of blind.behaviors) b.log_source = 'unspecified';
  for (const g of blind.detection_guidance) g.log_source = null;
  for (const e of blind.evidence_samples) e.log_source_guess = null;
  const calls = installFakeLLM((user, n, req) => (req.schemaName === 'proposal' ? NS_PROPOSAL : /nsppe|NetScaler ADC post-exploitation/.test(user) ? blind : defaultResponder(user, n, req)));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.ok(ns.selected);
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, 0);
  assert.deepEqual(ns.raw_iocs.proposed_queries, []); assert.match(ns.raw_iocs.proposals.skipped, /other only/);
  assert.equal(store._tables.runs[0].counts.proposals, 0);
});

test('stage queried: a proposal that fails validation twice is recorded on the story and never fails the run', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  installFakeLLM((user, n, req) => (req.schemaName === 'proposal' ? { nonsense: true } : nsTwoResponder(user, n, req)));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const run = store._tables.runs[0];
  assert.equal(run.stage, 'sent');
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.match(ns.raw_iocs.proposals.error, /failed validation twice/);
  assert.ok(out.discord.at(-1).includes('⚠ 1 failed'));
});

// ---- the queried stage through the Batches API (lib/jobs.js collects on the hourly tick) ----------

const batchedStage = async (t) => {
  // batched proposals only: the card loop is kept out of these runs (no day-one card, a bar nothing reaches)
  process.env.LLM_BATCH = '1'; process.env.CARD_P1_DAY_ONE = '0'; process.env.HYPE_SURFACE = '99'; _resetBatchMode();
  t.after(() => { process.env.LLM_BATCH = '0'; delete process.env.CARD_P1_DAY_ONE; delete process.env.HYPE_SURFACE; _resetBatchMode(); });
  const out = captureOutputs(); const store = memoryStore();
  const calls = installFakeLLM(nsTwoResponder);
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  return { out, store, calls };
};
const nsOf = (store) => store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
const proposalJobs = (store) => store._tables.llm_jobs.filter((j) => j.kind === 'proposal');

test('stage queried, batched: the proposal is submitted at half price, the brief goes out without waiting, and the collector lints the answer onto the story and counts it on the run', async (t) => {
  const { out, store, calls } = await batchedStage(t);
  const fake = installFakeBatch(() => NS_PROPOSAL); fake.ready = false;
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const run = store._tables.runs[0];
  assert.equal(run.stage, 'sent', 'the brief did not wait');
  const ns = nsOf(store);
  assert.ok(ns.raw_iocs.proposals.pending); assert.equal(ns.raw_iocs.proposals.batched, true); assert.deepEqual(ns.raw_iocs.proposed_queries, []);
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, 0, 'no live proposer call');
  assert.equal(proposalJobs(store).length, 1); assert.equal(proposalJobs(store)[0].status, 'pending'); assert.equal(proposalJobs(store)[0].run_id, run.id);
  const p = fake.submitted.find((s) => s.custom_id.startsWith('proposal')).params;
  assert.equal(p.model, 'claude-sonnet-5-5'); assert.equal(p.output_config.effort, 'high'); assert.ok(p.output_config.format);
  assert.equal(p.system[0].cache_control.type, 'ephemeral'); assert.ok(!('fallbacks' in p) && !('betas' in p));
  assert.equal(run.counts.proposals_pending, 1); assert.equal(run.counts.proposals, 0);
  const line = out.discord.find((l) => l.startsWith('Cutsign ✔'));
  assert.ok(line.includes('1 proposal pending (batch)'), line); assert.ok(!line.includes('proposer $'), line);
  assert.doesNotMatch(out.emails[0].html, /Proposed hunts/);
  // the first hourly tick: not answered yet
  const c1 = await collectJobs(store, {});
  assert.equal(c1.pending >= 1, true, JSON.stringify(c1)); assert.equal(c1.landed, 0); assert.deepEqual(c1.runs, []);
  // answered: linted onto the story, counted and costed on the run at the batch rate, and the run is named for the card loop
  fake.ready = true;
  const costBefore = Number(run.cost_usd); // the brief's own reads; the proposal adds to it
  const c2 = await collectJobs(store, {});
  assert.equal(c2.landed >= 1, true, JSON.stringify(c2)); assert.deepEqual(c2.runs, [run.id]);
  const ns2 = nsOf(store);
  assert.equal(ns2.raw_iocs.proposed_queries.length, 1); assert.equal(ns2.raw_iocs.proposed_queries[0].tier, 'proposed'); assert.equal(ns2.raw_iocs.proposed_queries[0].model, 'claude-sonnet-5-5');
  assert.ok(!ns2.raw_iocs.proposals.pending); assert.equal(ns2.raw_iocs.proposals.batched, true); assert.ok(ns2.raw_iocs.proposals.finished_at);
  const run2 = await store.getRun(run.id);
  assert.equal(run2.counts.calls_propose, 1); assert.equal(run2.counts.proposals, 1); assert.equal(run2.counts.proposals_pending, 0);
  assert.ok(Math.abs(run2.counts.cost_propose - 0.0035) < 1e-9, `half of Sonnet's live $0.007, got ${run2.counts.cost_propose}`);
  assert.ok(Math.abs(Number(run2.cost_usd) - costBefore - 0.0035) < 1e-9, `run cost ${costBefore} → ${run2.cost_usd}`);
  assert.equal(proposalJobs(store)[0].status, 'done'); assert.equal(proposalJobs(store)[0].cost_usd, 0.0035);
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, 0, 'still no live call');
  // a resumed stage finds the work done; nothing is collected twice
  await store.updateRun(run.id, { stage: 'validated' });
  assert.equal(await advanceRun(store, run.id, { fetchImpl: fakeFetch() }), 'sent');
  assert.equal(proposalJobs(store).length, 1, 'no second submission');
  assert.equal(store._tables.llm_jobs.length, 1, 'and nothing else in flight');
  assert.equal((await collectJobs(store, {})).checked, 0, 'nothing is collected twice');
});

test('stage queried, batched: an answer the API could not give is made live, once; a batch still running after six hours is cancelled and made live', async (t) => {
  const a = await batchedStage(t);
  const fake = installFakeBatch(() => NS_PROPOSAL); fake.fail = 'invalid_request: The compiled grammar is too large';
  await driveRuns(a.store, { fetchImpl: fakeFetch() });
  const c = await collectJobs(a.store, {});
  assert.equal(c.live >= 1, true, JSON.stringify(c)); assert.equal(a.calls.filter((x) => x.schemaName === 'proposal').length, 1, 'one live proposer call');
  const ns = nsOf(a.store);
  assert.equal(ns.raw_iocs.proposed_queries.length, 1); assert.equal(ns.raw_iocs.proposals.batched, false);
  assert.match(proposalJobs(a.store)[0].outcome, /^live: invalid_request/);
  assert.ok(Math.abs((await a.store.getRun(a.store._tables.runs[0].id)).counts.cost_propose - 0.014) < 1e-9, 'the live call at the list price');
  // six hours and no answer
  const b = await batchedStage(t);
  const fake2 = installFakeBatch(() => NS_PROPOSAL); fake2.ready = false;
  await driveRuns(b.store, { fetchImpl: fakeFetch() });
  const c2 = await collectJobs(b.store, { now: Date.now() + 7 * 3600_000 });
  assert.equal(c2.live >= 1, true, JSON.stringify(c2)); assert.ok(fake2.cancelled.length >= 1); assert.equal(b.calls.filter((x) => x.schemaName === 'proposal').length, 1);
  assert.match(proposalJobs(b.store)[0].outcome, /not answered in 6 h/);
  assert.equal(nsOf(b.store).raw_iocs.proposed_queries.length, 1);
});

test('stage queried, batched: a submission the API refuses is proposed live in the same step', async (t) => {
  const { out, store, calls } = await batchedStage(t);
  installFakeBatch(() => NS_PROPOSAL);
  const { _setBatchAPI } = await import('../lib/llm.js');
  _setBatchAPI({ async create() { throw new Error('400 output_config.format: unsupported'); } });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const ns = nsOf(store);
  assert.equal(ns.raw_iocs.proposed_queries.length, 1); assert.ok(!ns.raw_iocs.proposals.pending); assert.ok(!ns.raw_iocs.proposals.batched);
  assert.equal(calls.filter((c) => c.schemaName === 'proposal').length, 1, 'the live call');
  assert.equal(store._tables.llm_jobs.length, 0);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ⚠ batch submission failed, proposing live')), out.discord.join('\n'));
  assert.ok(out.discord.find((l) => l.startsWith('Cutsign ✔')).includes('proposals +1'));
});
