// Gmail polling (read-only). OAuth refresh token for the inbox that receives the brief,
// scope gmail.readonly ONLY — obtained once with `npm run gmail-auth`.

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const API = 'https://gmail.googleapis.com/gmail/v1/users/me';
export const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';

export const DEFAULT_QUERY =
  'from:(brief@example.test OR briefs@example.test) subject:"Threat Brief" newer_than:3d';

async function accessToken() {
  const { GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN } = process.env;
  if (!GMAIL_CLIENT_ID || !GMAIL_CLIENT_SECRET || !GMAIL_REFRESH_TOKEN) {
    throw new Error('GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN not set');
  }
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GMAIL_CLIENT_ID, client_secret: GMAIL_CLIENT_SECRET,
      refresh_token: GMAIL_REFRESH_TOKEN, grant_type: 'refresh_token',
    }),
    signal: AbortSignal.timeout(10000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    // invalid_grant here almost always means the refresh token was revoked or expired
    // (e.g. consent screen left in "Testing" → 7-day expiry). Re-run `npm run gmail-auth`.
    throw new Error(`gmail token refresh failed: ${r.status} ${j.error || ''} ${j.error_description || ''}`.trim());
  }
  if (j.scope && j.scope.split(' ').some((s) => s !== GMAIL_SCOPE)) {
    throw new Error(`gmail token carries unexpected scopes: ${j.scope} — only gmail.readonly is allowed`);
  }
  return j.access_token;
}

async function api(token, path) {
  const r = await fetch(`${API}${path}`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`gmail ${path.split('?')[0]}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

/**
 * List candidate brief messages. Returns [{ gmailId, messageId, from, subject, date, getRaw() }].
 * Message-ID comes from a cheap metadata fetch, so callers can dedupe before pulling the full MIME.
 */
export async function listBriefMessages(query = process.env.GMAIL_QUERY || DEFAULT_QUERY) {
  const token = await accessToken();
  const list = await api(token, `/messages?maxResults=20&q=${encodeURIComponent(query)}`);
  const out = [];
  for (const { id } of list.messages || []) {
    const m = await api(token, `/messages/${id}?format=metadata&metadataHeaders=Message-ID&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`);
    const h = Object.fromEntries((m.payload?.headers || []).map((x) => [x.name.toLowerCase(), x.value]));
    out.push({
      gmailId: id,
      messageId: (h['message-id'] || `<gmail-${id}>`).trim(),
      from: h.from || '',
      subject: h.subject || '',
      receivedAt: new Date(Number(m.internalDate)).toISOString(),
      getRaw: async () => {
        const full = await api(token, `/messages/${id}?format=raw`);
        return Buffer.from(full.raw, 'base64url').toString('utf8');
      },
    });
  }
  return out;
}
