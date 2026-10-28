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
import { fixtureMessage, fakeFetch, installFakeLLM, defaultResponder, captureOutputs, NETSCALER_EXTRACTION } from './helpers.js';

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
  assert.equal(calls.length, 1); assert.equal(calls[0].tier, 'propose'); assert.equal(calls[0].schemaName, 'proposal'); assert.equal(calls[0].model, 'claude-fable-5-1');
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
  assert.equal(calls[0].tier, 'deep'); assert.equal(calls[0].model, 'claude-opus-5-5');
  assert.equal(r.model_tier, 'deep'); assert.equal(r.proposals[0].model_tier, 'deep');
  const r2 = await generateQueries({ ...CW, spent: 7.9, cap: 10 });
  assert.equal(r2.model_tier, 'propose');
});

test('a story whose telemetry is other only gets no call and an empty list', async () => {
  const calls = installFakeLLM(() => PROPOSAL());
  const r = await generateQueries({ ...CW, behaviors: CW.behaviors.map((b) => ({ ...b, log_source: 'unspecified' })), guidance: [], samples: [] });
  assert.equal(calls.length, 0); assert.deepEqual(r.proposals, []); assert.match(r.skipped, /other only/);
  assert.ok(eligible({ selected: true, status: 'extracted', priority: 2 }));
  assert.ok(!eligible({ selected: true, status: 'extracted', priority: 3 }));
  assert.ok(!eligible({ selected: false, status: 'extracted', priority: 1 }));
});

const NS_PROPOSAL = { proposed_queries: [{
  shape: 'single_source', name: 'nsppe_spawns_shell', hypothesis: 'The packet engine spawns an interactive shell.',
  stages: [{ log_source_key: 'appliance_logs', predicate: 'child of nsppe is a shell or interpreter', fields: ['parent', 'child'] }], join: null,
  splunk: 'index=<appliance_logs> parent=nsppe | stats count by child', elastic: 'FROM <appliance_logs> | WHERE process.parent.name == "nsppe" | STATS c = COUNT(*) BY process.name',
  params: [], noise_hint: 'vendor maintenance scripts run as root from the same parent; exclude the documented script paths', from: ['behaviors[0]'], confidence: 'stated',
}] };

test('stage queried: proposals for the deep P1 story, the ✔ line counts them, the email omits them, a resumed stage does not propose twice', async () => {
  const out = captureOutputs();
  const store = memoryStore();
  const calls = installFakeLLM((user, n, req) => (req.schemaName === 'proposal' ? NS_PROPOSAL : defaultResponder(user, n, req)));
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
  installFakeLLM((user, n, req) => (req.schemaName === 'proposal' ? { nonsense: true } : defaultResponder(user, n, req)));
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const run = store._tables.runs[0];
  assert.equal(run.stage, 'sent');
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.match(ns.raw_iocs.proposals.error, /failed validation twice/);
  assert.ok(out.discord.at(-1).includes('⚠ 1 failed'));
});
