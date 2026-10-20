// Repo hygiene: secrets untracked, no employer-shaped tokens, Gmail scope read-only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { GMAIL_SCOPE } from '../lib/gmail.js';

const root = new URL('..', import.meta.url).pathname;
const git = (...a) => { try { return execFileSync('git', a, { cwd: root, encoding: 'utf8' }); } catch { return null; } };

test('.env is gitignored and untracked', () => {
  const ignore = readFileSync(new URL('../.gitignore', import.meta.url), 'utf8');
  assert.match(ignore, /^\.env$/m);
  const tracked = git('ls-files');
  if (tracked !== null) assert.ok(!tracked.split('\n').some((f) => /(^|\/)\.env($|\.(?!example))/.test(f)), '.env must not be tracked');
});

test('Gmail scope is gmail.readonly only', () => {
  assert.equal(GMAIL_SCOPE, 'https://www.googleapis.com/auth/gmail.readonly');
  const auth = readFileSync(new URL('../scripts/gmail-auth.js', import.meta.url), 'utf8');
  assert.ok(!/gmail\.(modify|send|compose|insert|labels|settings)|mail\.google\.com\/"/.test(auth), 'no write scope requested');
});

test('no internal-looking hostnames, index names, or usernames in tracked code', () => {
  const files = (git('ls-files') || '').split('\n').filter((f) => /\.(js|json|md|yml|yaml|sql)$/.test(f))
    .filter((f) => !f.startsWith('fixtures/') && f !== 'test/hygiene.test.js' && f !== 'lib/attack-ids.json');
  const bad = [
    /\bindex\s*=\s*(?!\*)[a-z_]/i,                          // literal index=<name> (index=* allowed)
    /\b[a-z0-9-]+\.(corp|internal|intranet|lan)\.[a-z]{2,}\b/i, // host.corp.example.com style
    /\b(sourcetype)\s*=\s*"?[a-z]+:[a-z]/i,                  // concrete internal sourcetypes
  ];
  for (const f of files) {
    const text = readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
    for (const re of bad) assert.ok(!re.test(text), `${f} matches ${re}`);
  }
});
