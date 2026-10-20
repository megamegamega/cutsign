// One-time Gmail OAuth: opens Google's consent page, catches the redirect on 127.0.0.1, exchanges the
// code for a refresh token, verifies the ONLY granted scope is gmail.readonly, and writes
// GMAIL_REFRESH_TOKEN into .env. Needs GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET in .env (Desktop client).
//   npm run gmail-auth

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { GMAIL_SCOPE } from '../lib/gmail.js';

const ENV = new URL('../.env', import.meta.url);
const env = Object.fromEntries((existsSync(ENV) ? readFileSync(ENV, 'utf8') : '').split('\n')
  .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.split('=')[0], l.slice(l.indexOf('=') + 1)]));
const clientId = process.env.GMAIL_CLIENT_ID || env.GMAIL_CLIENT_ID;
const clientSecret = process.env.GMAIL_CLIENT_SECRET || env.GMAIL_CLIENT_SECRET;
if (!clientId || !clientSecret) { console.error('Put GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET in .env first.'); process.exit(1); }

const state = randomBytes(16).toString('hex');
const server = createServer(async (req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  if (u.pathname !== '/callback') { res.writeHead(404).end(); return; }
  if (u.searchParams.get('state') !== state) { res.writeHead(400).end('state mismatch'); return; }
  const code = u.searchParams.get('code');
  const redirect = `http://127.0.0.1:${server.address().port}/callback`;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirect, grant_type: 'authorization_code' }),
  });
  const j = await r.json();
  const granted = (j.scope || '').split(' ').filter(Boolean);
  if (!j.refresh_token) {
    res.end('No refresh token returned — see terminal.'); console.error('Token response:', { ...j, access_token: j.access_token ? '[redacted]' : undefined });
  } else if (granted.length !== 1 || granted[0] !== GMAIL_SCOPE) {
    res.end('Unexpected scopes — refused. See terminal.'); console.error('Granted scopes were', granted, '— expected only', GMAIL_SCOPE, '. Not saving.');
  } else {
    let text = existsSync(ENV) ? readFileSync(ENV, 'utf8') : '';
    text = /^GMAIL_REFRESH_TOKEN=.*$/m.test(text) ? text.replace(/^GMAIL_REFRESH_TOKEN=.*$/m, `GMAIL_REFRESH_TOKEN=${j.refresh_token}`) : text + `\nGMAIL_REFRESH_TOKEN=${j.refresh_token}\n`;
    writeFileSync(ENV, text);
    res.end('Done — Cutsign has read-only Gmail access. You can close this tab.');
    console.log(`✔ Granted scope: ${granted[0]} (read-only). GMAIL_REFRESH_TOKEN written to .env.`);
  }
  server.close();
});
server.listen(0, '127.0.0.1', () => {
  const redirect = `http://127.0.0.1:${server.address().port}/callback`;
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: clientId, redirect_uri: redirect, response_type: 'code', scope: GMAIL_SCOPE,
    access_type: 'offline', prompt: 'consent', state, include_granted_scopes: 'false',
  });
  console.log('Opening your browser for Google consent (sign in as the inbox that receives the brief)…\n' + url);
  execFile('open', [url]);
});
