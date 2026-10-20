// One-time Gmail OAuth, straight into Vercel. Run it in your own Terminal (not through Claude), so the
// client secret never lands in a transcript:
//
//   cd ~/cutsign && npm run gmail-auth
//
// It asks for the OAuth client ID + secret (Desktop app) with hidden input, opens Google's consent page,
// catches the redirect on 127.0.0.1, verifies the ONLY granted scope is gmail.readonly, then pipes
// GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN into the cutsign Vercel project
// (production). Nothing is written to disk. Redeploy afterwards so the function picks them up.

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { execFile, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { rmSync } from 'node:fs';
import { GMAIL_SCOPE } from '../lib/gmail.js';

const CUTSIGN = new URL('..', import.meta.url).pathname;

function ask(prompt, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = (s) => { if (s.includes(prompt)) process.stdout.write(s); };
    rl.question(prompt, (a) => { rl.close(); if (hidden) process.stdout.write('\n'); resolve(a.trim()); });
  });
}

function toVercel(name, value) {
  spawnSync('npx', ['-y', 'vercel@latest', 'env', 'rm', name, 'production', '--yes'], { cwd: CUTSIGN, stdio: 'ignore' });
  const r = spawnSync('npx', ['-y', 'vercel@latest', 'env', 'add', name, 'production'], { cwd: CUTSIGN, input: value, stdio: ['pipe', 'ignore', 'pipe'], encoding: 'utf8' });
  rmSync(new URL('../.env.local', import.meta.url), { force: true }); // the CLI sometimes drops one; never keep it
  if (r.status !== 0) throw new Error(`vercel env add ${name} failed: ${(r.stderr || '').split('\n').filter(Boolean).slice(-2).join(' | ')}`);
  console.log(`✔ ${name} → Vercel (production)`);
}

const clientId = await ask('OAuth client ID: ');
const clientSecret = await ask('OAuth client secret (hidden): ', { hidden: true });
if (!clientId || !clientSecret) { console.error('Both are required.'); process.exit(1); }

const state = randomBytes(16).toString('hex');
const server = createServer(async (req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  if (u.pathname !== '/callback') { res.writeHead(404).end(); return; }
  if (u.searchParams.get('state') !== state) { res.writeHead(400).end('state mismatch'); return; }
  if (u.searchParams.get('error')) { res.end('Consent was not granted.'); console.error('Google returned:', u.searchParams.get('error')); server.close(); return; }
  const redirect = `http://127.0.0.1:${server.address().port}/callback`;
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: u.searchParams.get('code'), client_id: clientId, client_secret: clientSecret, redirect_uri: redirect, grant_type: 'authorization_code' }),
    });
    const j = await r.json();
    const granted = (j.scope || '').split(' ').filter(Boolean);
    if (!j.refresh_token) throw new Error(`no refresh token returned (${j.error || r.status}: ${j.error_description || ''})`);
    if (granted.length !== 1 || granted[0] !== GMAIL_SCOPE) throw new Error(`unexpected scopes ${JSON.stringify(granted)} — refusing; only gmail.readonly is allowed`);
    res.end('Done — Cutsign has read-only Gmail access. You can close this tab and go back to the Terminal.');
    console.log(`✔ Granted scope: ${granted[0]} (read-only)`);
    toVercel('GMAIL_CLIENT_ID', clientId);
    toVercel('GMAIL_CLIENT_SECRET', clientSecret);
    toVercel('GMAIL_REFRESH_TOKEN', j.refresh_token);
    console.log('\nAll set. Tell Claude "gmail done" — it will redeploy and run a test poll.');
  } catch (e) {
    res.end('Something went wrong — see the Terminal.');
    console.error('✖', e.message);
    process.exitCode = 1;
  } finally {
    server.close();
  }
});
server.listen(0, '127.0.0.1', () => {
  const redirect = `http://127.0.0.1:${server.address().port}/callback`;
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: clientId, redirect_uri: redirect, response_type: 'code', scope: GMAIL_SCOPE,
    access_type: 'offline', prompt: 'consent', state,
  });
  console.log('\nOpening your browser — sign in as dispatch@liberto.us (the inbox that receives the brief).');
  execFile('open', [url]);
});
