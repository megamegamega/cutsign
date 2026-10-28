// The query linter: the only index form is a placeholder, only read-only commands, and no
// identifier that the story record does not print. Strings the repo's hygiene test must never see
// verbatim are assembled at runtime with J().
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lintSpl, lintEsql } from '../lib/lint.js';

const J = (...a) => a.join('');

test('SPL: placeholder index and wildcard pass; a literal index name fails', () => {
  assert.ok(lintSpl('index=<entra_signin> appId="x" | stats count by appId').ok);
  assert.ok(lintSpl('index=* | stats count').ok);
  const r = lintSpl(J('index', '=main | stats count'));
  assert.ok(!r.ok); assert.match(r.reasons[0], /literal index name/);
  assert.ok(!lintSpl(J('index', '="prod_web" | stats count')).ok);
  assert.ok(!lintSpl(J('index IN (', 'a, b) | stats count')).ok);
  assert.ok(!lintSpl('').ok);
});

test('SPL: denylisted and non-allowlisted commands fail, inside subsearches too', () => {
  for (const cmd of ['delete', 'outputlookup', 'sendemail', 'script', 'run', 'lookup', 'inputlookup', 'collect', 'outputcsv', 'rest', 'map', 'sendalert', 'savedsearch', 'makeresults', 'streamstats', 'eventstats']) {
    const r = lintSpl(`index=<web_access> | ${cmd} x`);
    assert.ok(!r.ok, cmd); assert.ok(r.reasons.some((x) => /command not allowed/.test(x)), cmd);
  }
  assert.ok(!lintSpl('index=<a> | append [ search index=<b> | outputlookup t ]').ok);
  assert.ok(lintSpl('index=<entra_signin> | join type=inner appId [ search index=<m365_ual> Operation=MailItemsAccessed | fields appId ] | table appId').ok);
  assert.ok(lintSpl('| tstats count from datamodel=Authentication where index=<auth_log> by Authentication.user | sort - count | head 20').ok);
  // a denylisted word inside a quoted string is still refused — no clever escapes
  assert.ok(!lintSpl('index=<a> | eval x="| delete"').ok);
});

test('SPL: literal sourcetype, hostname, email, IP and username fail unless the story carries them', () => {
  assert.ok(!lintSpl(J('index=<a> sourcetype', '="x:y" | stats count')).ok);
  assert.ok(lintSpl('index=<a> sourcetype=<a> | stats count').ok);
  assert.ok(!lintSpl(J('index=<a> dest=srv01.', 'corp.example.com | stats count')).ok);
  assert.ok(!lintSpl('index=<a> sender="alice@example.test" | stats count').ok);
  assert.ok(lintSpl('index=<a> sender="alice@example.test" | stats count', { allowed: (l) => l === 'alice@example.test' }).ok);
  assert.ok(!lintSpl('index=<a> src=203.0.113.5 | stats count').ok);
  assert.ok(lintSpl('index=<a> src=203.0.113.5 | stats count', { allowed: (l) => l === '203.0.113.5' }).ok);
  assert.ok(!lintSpl('index=<a> user=jsmith | stats count').ok);
  assert.ok(!lintSpl('index=<a> src_user="j.smith" | stats count').ok);
  assert.ok(lintSpl('index=<a> user=* | stats count').ok);
  assert.ok(lintSpl('index=<a> user=<user> | stats count').ok);
  assert.ok(!lintSpl('index=<a> host=webprod01 | stats count').ok);
  // ECS-style dotted field names are field names, not hostnames
  assert.ok(lintSpl('index=<endpoint_process> process.parent.name=httpd | stats count by process.name, user.name').ok);
  // a story-printed domain is allowed, an invented one is not
  assert.ok(lintSpl('index=<dns> query="update-check.net" | stats count', { allowed: (l) => l === 'update-check.net' }).ok);
  assert.ok(!lintSpl('index=<dns> query="update-check.net" | stats count').ok);
});

test('ES|QL: FROM placeholder only, read-only commands, same literal rules', () => {
  assert.ok(lintEsql('FROM <entra_signin> | WHERE appId == "x" | STATS c = COUNT(*) BY appId | LIMIT 100').ok);
  assert.ok(lintEsql('FROM <a>, <b> METADATA _index | KEEP appId').ok);
  assert.ok(!lintEsql('FROM logs-azure.signinlogs-* | STATS COUNT(*)').ok);
  assert.ok(!lintEsql('FROM <a> | ENRICH policy').ok);
  assert.ok(!lintEsql('ROW a = 1').ok);
  assert.ok(!lintEsql(J('FROM <a> | WHERE data_stream.dataset', ' == "azure.signinlogs"')).ok);
  assert.ok(!lintEsql('FROM <a> | WHERE user.name == "jsmith"').ok);
  assert.ok(!lintEsql('FROM <a> | WHERE host.name == "web01"').ok);
  assert.ok(!lintEsql('FROM <a> | WHERE source.ip == "203.0.113.5"').ok);
  assert.ok(lintEsql('FROM <a> | WHERE source.ip == "203.0.113.5"', { allowed: (l) => l === '203.0.113.5' }).ok);
  assert.ok(lintEsql('FROM <a> | LOOKUP JOIN <b> ON appId | KEEP appId').ok);
  assert.ok(!lintEsql('FROM <a> | LOOKUP x').ok);
  assert.ok(!lintEsql('').ok);
});
