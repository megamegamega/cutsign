import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refang, normalizeIoc } from '../lib/normalize.js';

test('refangs common defang styles', () => {
  assert.equal(refang('hxxps://evil[.]com/x'), 'https://evil.com/x');
  assert.equal(refang('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(refang('evil(dot)com'), 'evil.com');
  assert.equal(refang('evil[dot]com'), 'evil.com');
  assert.equal(refang('bad[@]evil[.]com'), 'bad@evil.com');
  assert.equal(refang('hXXp://x{.}y[.]org'), 'http://x.y.org');
});

test('canonicalizes defanged inputs', () => {
  assert.deepEqual(normalizeIoc('url', 'hxxps://Evil[.]COM/x'), { type: 'url', value_norm: 'https://evil.com/x' });
  assert.deepEqual(normalizeIoc('domain', 'evil(dot)com'), { type: 'domain', value_norm: 'evil.com' });
  assert.deepEqual(normalizeIoc('domain', 'Evil.Com.'), { type: 'domain', value_norm: 'evil.com' });
  assert.deepEqual(normalizeIoc('ipv4', '45[.]61[.]139[.]12:8443'), { type: 'ipv4', value_norm: '45.61.139.12' });
  // 1[.]2[.]3[.]4 refangs to 1.2.3.4 — which is then dropped as a placeholder
  assert.equal(refang('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.ok(normalizeIoc('ipv4', '1[.]2[.]3[.]4').drop);
});

test('drops placeholders, private ranges, and junk hashes', () => {
  for (const [t, v] of [['domain', 'example.com'], ['url', 'http://example.com/a'], ['ipv4', '127.0.0.1'], ['ipv4', '10.0.0.1'],
    ['ipv4', '192.168.1.5'], ['ipv4', '203.0.113.50'], ['ipv6', '::1'], ['ipv6', '2001:db8::1'],
    ['sha256', '0'.repeat(64)], ['md5', '0'.repeat(32)], ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['domain', 'not a domain'], ['email', 'x@example.com']]) {
    assert.ok(normalizeIoc(t, v).drop, `${t} ${v} should drop`);
  }
});

test('reclassifies by shape', () => {
  assert.equal(normalizeIoc('sha256', 'D41D8CD98F00B204E9800998ECF8427F').type, 'md5');
  assert.equal(normalizeIoc('domain', 'update.exe').type, 'filename');
  assert.equal(normalizeIoc('domain', 'hxxp://bad[.]site/path').type, 'url');
  assert.equal(normalizeIoc('filepath', 'C:\\Windows\\Temp\\X.EXE').value_norm, 'c:\\windows\\temp\\x.exe');
  assert.equal(normalizeIoc('filepath', '/var/tmp/.X11').value_norm, '/var/tmp/.X11');
  assert.equal(normalizeIoc('cve', 'cve-2026-88779').value_norm, 'CVE-2026-88779');
});
