// Banner spellings for the exposure queries. NVD names a product the way its vendor's catalogue
// does today ("Catalyst SD-WAN Manager", "VeloCloud Orchestrator" under Arista); Shodan's banners
// and page titles carry the names the devices themselves print, often the former or marketing name
// ("Cisco vManage", "VeloCloud Orchestrator"). One small model call per card version asks for those
// strings from the NVD names and the card's own text; every suggestion is validated here (a Shodan
// filter from a fixed list, a specific value, never a vendor name alone, never scope) and then
// counted against Shodan by lib/shodan.js, which shows only the ones that match something. The
// result is cached on the card's exposure block by a key over the inputs, so the model is asked
// again only when the products or the card text change.

import { createHash } from 'node:crypto';
import { z } from 'zod';
import { callStructured } from './llm.js';
import { productName, VENDORS } from './exposure.js';

export const FILTERS = ['http.title', 'product', 'http.component', 'http.html', 'ssl'];
export const NamesSchema = z.object({
  names: z.array(z.object({
    for: z.string().describe('the vendor:product key the string belongs to, or "card" for a product the card names that NVD does not'),
    filter: z.enum(FILTERS).describe('the Shodan filter the string is for: http.title for a web console\'s page title, product for a banner product field, http.component for a web application behind a server, http.html for text on the page, ssl for certificate text'),
    value: z.string().describe('the exact string as it appears in banners, 3-60 characters, no quotes'),
    why: z.string().describe('one short clause: where the string comes from (former name, UI title, marketing name)'),
  })).max(10),
});

export const MAX_ALIASES = 8;
const GENERIC = new Set(['server', 'manager', 'management', 'orchestrator', 'controller', 'director', 'appliance', 'gateway', 'console', 'portal', 'login', 'admin',
  'administration', 'administrator', 'dashboard', 'web', 'http', 'https', 'system', 'systems', 'service', 'services', 'platform', 'enterprise', 'edition', 'software',
  'cloud', 'secure', 'security', 'network', 'networks', 'device', 'devices', 'firewall', 'router', 'vpn', 'api', 'the', 'and', 'for', 'virtual', 'edge', 'core',
  'sign', 'welcome', 'home', 'index', 'default', 'page', 'interface', 'manager.', 'control', 'center', 'centre', 'suite', 'client', 'agent', 'monitor', 'monitoring']);
const VALUE_RE = /^[A-Za-z0-9][A-Za-z0-9 .\-_/+]{1,58}$/;
const words = (s) => String(s).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const camel = (t) => /^[a-z0-9]+[A-Z]/.test(t) || /^[A-Z][a-z0-9]+[A-Z]/.test(t);

/** The cache key over everything the model sees. */
export const aliasKey = ({ products = [], affected = [], title = '' } = {}) =>
  createHash('sha1').update(JSON.stringify([products.map((p) => `${p.vendor}:${p.product}`).sort(), affected.map((a) => String(a).trim()).sort(), String(title).trim()])).digest('hex').slice(0, 16);

/**
 * The model's suggestions, kept only when specific and safe: a filter from the list, a value that is
 * a plain string (no quotes, colons or operators), not a vendor name or a generic word on its own,
 * not already a query on the card. Returns [{ query, for, note }], at most MAX_ALIASES.
 */
export function cleanNames(names = [], { keys = [], vendors = [], existing = [] } = {}) {
  const seen = new Set(existing.map((q) => String(q).toLowerCase()));
  const vend = new Set([...VENDORS, ...vendors.map((v) => String(v).toLowerCase())]);
  const out = [];
  for (const n of names) {
    if (!n || !FILTERS.includes(n.filter)) continue;
    const value = String(n.value || '').trim().replace(/\s+/g, ' ');
    if (!VALUE_RE.test(value)) continue;
    const toks = value.split(' ');
    const w = words(value);
    if (!w.length || w.every((t) => GENERIC.has(t))) continue;                             // "Orchestrator", "Management Console"
    if (toks.length === 1 && (vend.has(w[0]) || (!camel(toks[0]) && toks[0].length < 6))) continue; // "Cisco" alone, a short plain word
    // vendor + generic ("Versa Director") is how some products are really named; Shodan's count decides
    const query = `${n.filter}:"${value}"`;
    if (seen.has(query.toLowerCase())) continue;
    seen.add(query.toLowerCase());
    const why = String(n.why || '').replace(/\s+/g, ' ').trim().slice(0, 120);
    out.push({ query, for: keys.includes(n.for) ? n.for : 'card', note: `Banner spelling suggested by the model from the card text${why ? ` (${why})` : ''}; counted against Shodan before it was shown.` });
    if (out.length >= MAX_ALIASES) break;
  }
  return out;
}

const SYSTEM = `You name software the way internet scanners see it. You are given the products NVD names for a vulnerability (vendor:product keys and their catalogue names) and a verdict card's own text about the same campaign. Return the strings Shodan would show for these products in banners: the page title of the product's web console (http.title), the product field of its banner (product), its name as a web application behind a server (http.component), distinctive text on its login page (http.html) or in its certificate (ssl). Former names and marketing names matter most, because NVD uses today's catalogue name while devices print the name they shipped with: for example Cisco Catalyst SD-WAN Manager appears as "vManage", VMware/Arista VeloCloud Orchestrator as "VeloCloud Orchestrator", Palo Alto Panorama's console title is "Panorama". Rules: every value must be specific to the product (never a vendor name alone, never a generic word such as Manager or Orchestrator alone); values are plain strings of 3-60 characters with no quotes, colons or wildcards; never an IP, range, organisation or hostname; at most ten entries, best first; nothing you are not reasonably confident a scanner would show. If nothing is worth adding, return an empty list.`;

/**
 * The banner spellings for a card's products. Returns { aliases, cost, model, key, cached }; never
 * throws for the model's sake (a failed call returns no aliases and the cost spent).
 * @param products  nvdCpes() output kept on the card (part a), for the keys and catalogue names
 * @param affected  the card's own affected-product lines (draft scope, or a hand card's summary)
 * @param prev      the previous exposure block: its aliases are reused while the key matches
 */
export async function scannerNames({ products = [], affected = [], title = '', summary = '', prev = null, existing = [] } = {}) {
  if (!products.length && !affected.length) return { aliases: [], cost: 0, model: null, key: null, cached: false };
  const key = aliasKey({ products, affected, title });
  if (prev && prev.aliases_key === key && Array.isArray(prev.aliases)) return { aliases: prev.aliases, cost: 0, model: prev.aliases_model || null, key, cached: true };
  const keys = products.map((p) => `${p.vendor}:${p.product}`);
  const text = `<title>${title}</title>\n<nvd_products>\n${products.map((p) => `${p.vendor}:${p.product} — ${productName(p.product)}${p.ranges?.length ? ` (affected ${p.ranges.join('; ')})` : ''}`).join('\n') || '(none: NVD has no CPE for these CVEs yet)'}\n</nvd_products>\n<card_affected>\n${affected.map((a) => String(a).slice(0, 200)).join('\n')}\n</card_affected>\n<card_summary>${String(summary || '').slice(0, 600)}</card_summary>`;
  let r;
  try {
    r = await callStructured({ tier: 'light', effort: 'low', system: SYSTEM, messages: [{ role: 'user', content: text }], schema: NamesSchema, schemaName: 'scanner_names', maxTokens: 1500 });
  } catch (e) { return { aliases: [], cost: 0, model: null, key, cached: false, error: String(e?.message || e).slice(0, 160) }; }
  const parsed = NamesSchema.safeParse(r.data);
  const aliases = parsed.success ? cleanNames(parsed.data.names, { keys, vendors: products.map((p) => p.vendor), existing }) : [];
  return { aliases, cost: r.cost || 0, model: r.model || null, key, cached: false };
}
