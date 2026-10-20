// One-line Discord notifier (ported from Daybreak). NEVER throws: a reporting failure must never
// break a run. Discord caps messages at 2000 chars, so long text is chunked on line boundaries.

const LIMIT = 1900;

function chunk(text) {
  const out = [];
  let buf = '';
  for (const line of String(text).split('\n')) {
    if (buf.length + line.length + 1 > LIMIT) { if (buf) out.push(buf); buf = ''; }
    buf += (buf ? '\n' : '') + line.slice(0, LIMIT);
  }
  if (buf) out.push(buf);
  return out.length ? out : [''];
}

// Tests swap this to capture lines instead of posting.
let sink = null;
export function _setDiscordSink(fn) { sink = fn; }

/** Post to DISCORD_WEBHOOK_URL. Returns true if every chunk posted. */
export async function postDiscord(content) {
  if (sink) { sink(String(content)); return true; }
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) { console.error('discord: DISCORD_WEBHOOK_URL not set —', content); return false; }
  let ok = true;
  for (const part of chunk(content)) {
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: part, allowed_mentions: { parse: [] } }),
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) { console.error(`discord: ${r.status}`); ok = false; }
    } catch (e) { console.error('discord post failed:', e?.message); ok = false; }
  }
  return ok;
}
