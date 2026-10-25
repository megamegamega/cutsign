// Canonical log-source keys: closed vocabulary, multi-label, retroactive over the free text the
// extractor writes. Strings below are real phrasings from stored briefs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LOG_SOURCE_KEYS, logSourceKeys } from '../lib/logsources.js';

test('every key the classifier can emit is in the published vocabulary', () => {
  const cases = ['EDR process events / Sysmon EID 1 / Windows 4688', 'proxy / DNS / network logs', 'Entra ID sign-in logs',
    'BeyondTrust appliance syslog', 'M365 Unified Audit Log / Defender for Cloud Apps', 'GitHub Actions workflow run logs',
    'Android device telemetry / MDM application inventory', 'memory forensics', 'wat', ''];
  for (const c of cases) for (const k of logSourceKeys(c)) assert.ok(LOG_SOURCE_KEYS.includes(k), `${k} from "${c}"`);
});

test('multi-label phrasings split into their families', () => {
  assert.deepEqual(logSourceKeys('EDR process events / Sysmon EID 1 / Windows 4688'), ['endpoint_process']);
  assert.deepEqual(logSourceKeys('proxy / DNS / network logs'), ['network', 'proxy', 'dns']);
  assert.deepEqual(logSourceKeys('Entra ID sign-in logs (authentication protocol deviceCode)'), ['entra_signin']);
  assert.deepEqual(logSourceKeys('Entra audit log'), ['entra_audit']);
  assert.deepEqual(logSourceKeys('M365 Unified Audit Log'), ['m365_ual']);
  assert.deepEqual(logSourceKeys('web server access log; EDR process events'), ['web_access', 'endpoint_process']);
  assert.deepEqual(logSourceKeys('Sysmon EID 7 image load'), ['endpoint_memory']);
  assert.deepEqual(logSourceKeys('shell/bash history, .bashrc file'), ['shell_history']);
  assert.deepEqual(logSourceKeys('auth log (sshd password login)'), ['auth_log']);
  assert.deepEqual(logSourceKeys('FortiGate VPN event logs / authentication logs'), ['appliance_logs', 'auth_log']);
  assert.deepEqual(logSourceKeys('AWS CloudTrail'), ['cloud_audit']);
  assert.deepEqual(logSourceKeys('GitLab application logs'), ['app_logs']);
  assert.deepEqual(logSourceKeys('Okta system log / Entra ID audit log'), ['entra_audit', 'identity_idp']);
  assert.deepEqual(logSourceKeys('Email gateway / mail flow telemetry'), ['email_gateway']);
  assert.deepEqual(logSourceKeys('appliance syslog and session events'), ['appliance_logs']);
});

test('unknown or empty text is other, never a guess', () => {
  assert.deepEqual(logSourceKeys(''), ['other']);
  assert.deepEqual(logSourceKeys(null), ['other']);
  assert.deepEqual(logSourceKeys('host performance metrics'), ['other']);
});
