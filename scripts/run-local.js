// Run the whole pipeline locally against an in-memory store (no Supabase), writing the email to a
// file instead of sending it. This is the prompt-tuning loop for v0.
//
//   node scripts/run-local.js --eml fixtures/briefs/2026-10-20-pipeline.eml   # a saved brief
//   node scripts/run-local.js --gmail                                         # latest real brief (needs GMAIL_* in .env)
//   options: --out <file.html>  (default ./out/latest.html)   --record (save LLM responses as fixtures)
//
// Reads .env. Uses the real network for sources and the real API for extraction (LLM_MODE=live) unless
// LLM_MODE=replay is set.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';

const ENV = new URL('../.env', import.meta.url);
if (existsSync(ENV)) for (const l of readFileSync(ENV, 'utf8').split('\n')) {
  const m = l.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
  if (m && m[2] !== '' && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/\s+#.*$/, '');
}
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
if (args.includes('--record')) process.env.LLM_MODE = 'record';

const { memoryStore } = await import('../lib/store-memory.js');
const { intake } = await import('../lib/intake.js');
const { driveRuns } = await import('../lib/pipeline.js');
const { _setEmailSink } = await import('../lib/email.js');
const { _setDiscordSink } = await import('../lib/discord.js');

const outFile = opt('--out') || 'out/latest.html';
let email = null;
_setEmailSink((m) => { email = m; });
_setDiscordSink((l) => console.log('[discord]', l));

let messages;
if (opt('--eml')) {
  const raw = readFileSync(opt('--eml'), 'utf8');
  messages = [{ getRaw: async () => raw }];
} else if (args.includes('--gmail')) {
  const { listBriefMessages } = await import('../lib/gmail.js');
  const q = process.env.GMAIL_QUERY || 'subject:"Threat Brief" -subject:TEST newer_than:7d';
  messages = (await listBriefMessages(q)).slice(0, 1);
  if (args.includes('--save-fixture') && messages[0]) {
    const raw = await messages[0].getRaw();
    const f = `fixtures/briefs/${new Date(messages[0].receivedAt).toISOString().slice(0, 10)}-gmail.eml`;
    writeFileSync(f, raw); console.log('saved', f);
  }
} else {
  console.error('usage: run-local.js --eml <file> | --gmail [--save-fixture]'); process.exit(1);
}

const store = memoryStore();
const t0 = Date.now();
console.log('intake:', await intake(store, { messages }));
await driveRuns(store, {});
const run = store._tables.runs[0];
console.log(`run: stage=${run?.stage} cost=$${Number(run?.cost_usd || 0).toFixed(3)} tokens=${run?.tokens_in}/${run?.tokens_out} ${Math.round((Date.now() - t0) / 1000)}s`);
if (run?.error) console.log('error:', run.error);
for (const s of store._tables.stories.filter((x) => x.selected)) console.log(` - [${s.status}] P${s.priority ?? '-'} ${s.title}${s.extract_error ? ' — ' + s.extract_error : ''}`);
if (email) {
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, email.html);
  writeFileSync(outFile.replace(/\.html$/, '.json'), JSON.stringify({ subject: email.subject, ...store._tables, briefs: undefined }, null, 2));
  console.log(`\n${email.subject}\n→ ${outFile} (and .json with every extracted row)`);
}
