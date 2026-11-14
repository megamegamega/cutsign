// Facts about an indicator that public reporting does not carry: who owns an address, when a domain
// was registered, whether a domain is one of the most visited on the internet.
//
// Reporting says what part an indicator played. It does not say that the address belongs to a cloud
// thousands of customers share, or that the domain is fifteen years old and ranked in the top ten
// thousand. Those facts decide what a block would cost, so the rules in lib/actions.js read them
// before calling a block automatic. They flag collateral, they do not validate the reporting: an
// address in a big cloud can still be the actor's rented server.
//
// All of it is free and none of it is a model:
//   address owner       Team Cymru's IP-to-ASN mapping (TXT records, asked over DNS-over-HTTPS) and
//                       PeeringDB's self-declared network type (access provider, enterprise, ...)
//   registration date   RDAP, through the rdap.org bootstrap redirect
//   most visited        the Tranco list (https://tranco-list.eu), a committed snapshot of its top
//                       domains in lib/topsites.json (`npm run update-enrich` refreshes it)
// Lookups are stored beside the card's record (draft.enrich on an AI card, lib/handenrich.json for
// the hand-written ones) and read back at render time; nothing is looked up when a page is served.

import { readFileSync } from 'node:fs';

// each file named in place, as a literal: the deploy's file tracing only bundles what it can read off the source
let TOP = { domains: [] }; let HAND = { facts: {} };
try { TOP = JSON.parse(readFileSync(new URL('./topsites.json', import.meta.url), 'utf8')); } catch { /* no snapshot: nothing is ranked */ }
try { HAND = JSON.parse(readFileSync(new URL('./handenrich.json', import.meta.url), 'utf8')); } catch { /* no file: the hand cards carry no facts */ }
const RANK = new Map((TOP.domains || []).map((d, i) => [d, i + 1]));
/** How many domains the committed top-sites snapshot holds. */
export const TOP_N = RANK.size;
/** Facts for the hand-written cards' indicators (they have no draft row to hold them). */
export const HAND_FACTS = HAND.facts || {};

const bare = (h) => String(h || '').toLowerCase().replace(/\.+$/, '');
const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const SECOND = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go']);
/** The name a registry holds for a host: its last two labels, three under a country's second level (co.uk). No suffix list: a rare miss costs one failed lookup. */
export function registrable(host) {
  const l = bare(host).split('.').filter(Boolean);
  if (l.length < 2 || V4.test(bare(host))) return null;
  return l.slice(-(l.length >= 3 && l.at(-1).length === 2 && SECOND.has(l.at(-2)) ? 3 : 2)).join('.');
}
/** The best rank among a host and the names above it, from the committed snapshot: { domain, rank } or null. */
export function topRank(host) {
  const l = bare(host).split('.').filter(Boolean); let best = null;
  for (let i = 0; i <= l.length - 2; i++) { const d = l.slice(i).join('.'); const rank = RANK.get(d); if (rank && (!best || rank < best.rank)) best = { domain: d, rank }; }
  return best;
}

const hostOfUrl = (v) => { try { return bare(new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `http://${v}`).hostname.replace(/^\[|\]$/g, '')); } catch { return ''; } };
/** What an indicator is looked up as: { key, host } with key `ip|<address>` or `dom|<registrable name>`, or null where there is nothing to ask (a hash, a .onion name). */
export function enrichKey(t) {
  const v = String(t?.value || '').trim().toLowerCase();
  if (t?.type === 'ipv4' || t?.type === 'ipv6') return { key: `ip|${v.replace(/\/\d+$/, '')}`, host: null };
  const host = t?.type === 'domain' ? bare(v) : t?.type === 'url' ? hostOfUrl(v) : '';
  if (!host || host.endsWith('.onion')) return null;
  if (V4.test(host) || host.includes(':')) return { key: `ip|${host}`, host: null };
  const reg = registrable(host);
  return reg ? { key: `dom|${reg}`, host } : null;
}

// Networks whose addresses are shared by design. Fixed lists, by AS number: the names a lookup
// returns are free text and change. Edge networks front many unrelated sites and users behind one
// address (a CDN, a relay or secure-web gateway: Cloudflare's includes WARP egress); the big clouds
// rent addresses by the hour, so one is an actor's server today and another customer's tomorrow.
const EDGE = new Set([13335, 209242, 20940, 16625, 54113, 22616, 62044, 55256]);
const CLOUD = new Set([16509, 14618, 8987, 8075, 8068, 8069, 15169, 396982, 19527, 31898, 45102, 37963, 45090, 132203, 36351]);
const ACCESS = new Set(['Cable/DSL/ISP']);
const ORG = new Set(['Enterprise', 'Educational/Research', 'Government', 'Non-Profit']);
/** The sort of network an address sits in: 'edge', 'cloud', 'access' (home and office connections), 'org' (an organization's own network), or null (rented hosting, transit, unknown). */
export function netClass(e) {
  if (!e || !e.asn) return null;
  if (EDGE.has(e.asn)) return 'edge';
  if (CLOUD.has(e.asn)) return 'cloud';
  if (ACCESS.has(e.kind)) return 'access';
  if (ORG.has(e.kind)) return 'org';
  return null;
}

const OLD_DAYS = 730;
/**
 * What is known about one indicator, from the stored lookups: owner ("AS13335 Cloudflare, Inc., US"),
 * net (netClass), registered (YYYY-MM-DD), old (registered more than two years before it was looked
 * up), reg_domain, rank and top_domain. Every field null when nothing is known.
 */
export function factsFor(t, enrich) {
  const out = { owner: null, net: null, registered: null, old: false, reg_domain: null, rank: null, top_domain: null };
  const k = enrichKey(t);
  if (!k) return out;
  const e = enrich?.[k.key] || null;
  if (k.key.startsWith('ip|')) {
    if (e?.asn) { out.owner = `AS${e.asn}${e.owner ? ` ${e.owner}` : ''}`; out.net = netClass(e); }
    return out;
  }
  const top = topRank(k.host);
  if (top) { out.rank = top.rank; out.top_domain = top.domain; }
  out.reg_domain = k.key.slice(4);
  if (e?.registered) {
    out.registered = e.registered;
    out.old = Date.parse(e.at) - Date.parse(e.registered) > OLD_DAYS * 86_400_000;
  }
  return out;
}

// ---- lookups ----------------------------------------------------------------------------------------

const TIMEOUT_MS = 5000;
// rdap.org refuses a request with no client name, and a named client is the polite thing anyway
const UA = 'cutsign-enrich/1 (+https://cutsign.vercel.app)';
const RETRY_FAILED_MS = 20 * 3_600_000; const MAX_FAILS = 3; const REFRESH_MS = 90 * 86_400_000; const KIND_SOON_MS = 30 * 60_000;
/** Is this stored lookup missing, a failure old enough to retry, or stale? */
export function enrichDue(e, now = Date.now()) {
  if (!e) return true;
  const age = now - (Date.parse(e.at) || 0);
  if (e.fail) return e.fail < MAX_FAILS ? age > RETRY_FAILED_MS : age > REFRESH_MS;
  // the owner is known and its network type is not: asked again soon when it was never asked (the sweep's allowance ran out), a day later when asking failed
  if (e.asn && e.kind == null && (e.kt || 0) < MAX_FAILS) return age > (e.kt ? RETRY_FAILED_MS : KIND_SOON_MS);
  return age > REFRESH_MS;
}

async function txt(name, fetchImpl) {
  const r = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, { headers: { accept: 'application/dns-json', 'user-agent': UA }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!r.ok) throw new Error(`dns ${r.status}`);
  const j = await r.json();
  if (j.Status !== 0 && j.Status !== 3) throw new Error(`dns status ${j.Status}`);
  return (j.Answer || []).filter((a) => a.type === 16).map((a) => String(a.data).replace(/^"|"$/g, '').replace(/"\s+"/g, ''));
}
function reverseName(ip) {
  const m = V4.exec(ip);
  if (m) return `${m[4]}.${m[3]}.${m[2]}.${m[1]}.origin.asn.cymru.com`;
  if (!/^[0-9a-f:]+$/.test(ip) || !ip.includes(':')) return null;
  const [head, tail] = ip.split('::');
  const a = head ? head.split(':') : []; const b = tail ? tail.split(':') : [];
  const full = ip.includes('::') ? [...a, ...Array(Math.max(0, 8 - a.length - b.length)).fill('0'), ...b] : a;
  if (full.length !== 8 || full.some((x) => x.length > 4)) return null;
  return `${full.map((x) => x.padStart(4, '0')).join('').split('').reverse().join('.')}.origin6.asn.cymru.com`;
}
const cells = (s) => String(s || '').split('|').map((x) => x.trim());

/**
 * One network's name and declared type, by AS number. `asns` caches across a sweep. PeeringDB allows
 * an anonymous caller only a few questions a minute, so a sweep has an allowance (`budget.peeringdb`)
 * and stops asking at the first refusal: the type is then null (`asked` says whether it was tried)
 * and the owner is stored without it, to be completed by a later sweep.
 */
async function asInfo(asn, { fetchImpl, asns, budget }) {
  if (asns.has(asn)) return asns.get(asn);
  const [line] = await txt(`AS${asn}.asn.cymru.com`, fetchImpl);
  const name = cells(line)[4] || '';
  // "M247 - M247 Europe SRL, RO": the handle, then the name a person recognises
  const owner = (name.includes(' - ') ? name.slice(name.indexOf(' - ') + 3) : name).slice(0, 80) || null;
  let kind = ''; let asked = true;
  if (!EDGE.has(asn) && !CLOUD.has(asn)) {
    if (budget.peeringdb > 0) {
      budget.peeringdb--;
      if (budget.paceMs) await new Promise((r) => setTimeout(r, budget.paceMs));
      try {
        const r = await fetchImpl(`https://www.peeringdb.com/api/net?asn=${asn}&fields=asn,info_type`, { headers: { accept: 'application/json', 'user-agent': UA }, signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (r.ok) kind = String((await r.json())?.data?.[0]?.info_type || '');
        else if (r.status !== 404) { kind = null; if (r.status === 429) budget.peeringdb = 0; }
      } catch { kind = null; }
    } else { kind = null; asked = false; }
  }
  const info = { owner, kind, asked };
  asns.set(asn, info);
  return info;
}

/**
 * Look one key up. Resolves to the record to store ({ at, asn, owner, cc, kind } for an address, kind null while the network type is still to be asked,
 * { at, registered } for a domain; asn or registered null where the source has no answer) and
 * throws where the source could not be asked, so the caller counts a failure and asks again later.
 */
export async function lookup(key, { fetchImpl = fetch, now = Date.now(), asns = new Map(), budget = { peeringdb: 8 }, prev = null } = {}) {
  const at = new Date(now).toISOString(); const v = key.slice(key.indexOf('|') + 1);
  if (key.startsWith('ip|')) {
    const name = reverseName(v);
    if (!name) return { at, asn: null };
    const [line] = await txt(name, fetchImpl);
    const c = cells(line); const asn = Number(String(c[0] || '').split(/\s+/)[0]) || null;
    if (!asn) return { at, asn: null };
    const info = await asInfo(asn, { fetchImpl, asns, budget });
    const rec = { at, asn, owner: info.owner, cc: /^[A-Z]{2}$/.test(c[2] || '') ? c[2] : null, kind: info.kind };
    if (info.kind == null) rec.kt = (prev?.asn === asn ? prev.kt || 0 : 0) + (info.asked ? 1 : 0);
    return rec;
  }
  const r = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(v)}`, { headers: { accept: 'application/rdap+json', 'user-agent': UA }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (r.status === 404) return { at, registered: null };
  if (!r.ok) throw new Error(`rdap ${r.status}`);
  const ev = ((await r.json())?.events || []).find((e) => e?.eventAction === 'registration');
  const d = /^\d{4}-\d{2}-\d{2}/.exec(String(ev?.eventDate || ''));
  return { at, registered: d ? d[0] : null };
}

/** Every key a card's stored record needs facts for (its steps' targets and the indicators beside them). `skipHost(host)` leaves out names whose age means nothing (a shared platform). */
export function wantedKeys(stored, { skipHost = () => false } = {}) {
  const keys = new Set();
  for (const t of [...(stored?.items || []).flatMap((a) => a.targets || []), ...(stored?.indicators || [])]) {
    const k = enrichKey(t);
    if (k && !(k.host && skipHost(k.host))) keys.add(k.key);
  }
  return keys;
}
