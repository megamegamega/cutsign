// Adversary attribution for the Actors tab (api/page.js ?view=actors): which country, if any, each
// stored story's adversary is attributed to, and what kind of adversary it is. Read
// deterministically from fields extraction already stores (threat_actor, title, summary,
// malware_family), with no model call. Every attribution keeps the basis it was read from (a known
// group, a vendor naming convention, or the sources' own words such as "China-nexus"), so a wrong
// one is visible on the page and fixable here. The attribution is the sources', never Cutsign's.

// ISO 3166 alpha-2 → name, ISO numeric (the world map's ids) and the words that name it in text.
// Acronyms are matched case-sensitively, like every word here, so "US" never matches "us".
export const COUNTRIES = {
  CN: { name: 'China', num: '156', words: ['China', 'Chinese', 'PRC', 'MSS'] },
  RU: { name: 'Russia', num: '643', words: ['Russia', 'Russian', 'GRU', 'SVR', 'FSB'] },
  KP: { name: 'North Korea', num: '408', words: ['North Korea', 'North Korean', 'DPRK'] },
  IR: { name: 'Iran', num: '364', words: ['Iran', 'Iranian', 'IRGC', 'MOIS'] },
  KR: { name: 'South Korea', num: '410', words: ['South Korea', 'South Korean'] },
  VN: { name: 'Vietnam', num: '704', words: ['Vietnam', 'Vietnamese'] },
  IN: { name: 'India', num: '356', words: ['India', 'Indian'] },
  PK: { name: 'Pakistan', num: '586', words: ['Pakistan', 'Pakistani'] },
  TR: { name: 'Turkey', num: '792', words: ['Turkey', 'Türkiye', 'Turkish'] },
  BY: { name: 'Belarus', num: '112', words: ['Belarus', 'Belarusian'] },
  KZ: { name: 'Kazakhstan', num: '398', words: ['Kazakhstan', 'Kazakh'] },
  LB: { name: 'Lebanon', num: '422', words: ['Lebanon', 'Lebanese', 'Hezbollah'] },
  SY: { name: 'Syria', num: '760', words: ['Syria', 'Syrian'] },
  IL: { name: 'Israel', num: '376', words: ['Israel', 'Israeli'] },
  PS: { name: 'Palestine', num: '275', words: ['Hamas', 'Palestinian'] },
  RS: { name: 'Serbia', num: '688', words: ['Serbia', 'Serbian'] },
  UA: { name: 'Ukraine', num: '804', words: ['Ukraine', 'Ukrainian'] },
  BR: { name: 'Brazil', num: '076', words: ['Brazil', 'Brazilian'] },
  NG: { name: 'Nigeria', num: '566', words: ['Nigeria', 'Nigerian'] },
  RO: { name: 'Romania', num: '642', words: ['Romania', 'Romanian'] },
  US: { name: 'United States', num: '840', words: ['United States', 'U.S.', 'US', 'NSA'] },
  GB: { name: 'United Kingdom', num: '826', words: ['United Kingdom', 'UK', 'British', 'GCHQ'] },
  AE: { name: 'United Arab Emirates', num: '784', words: ['UAE', 'Emirati'] },
  SA: { name: 'Saudi Arabia', num: '682', words: ['Saudi Arabia', 'Saudi'] },
  EG: { name: 'Egypt', num: '818', words: ['Egypt', 'Egyptian'] },
  ES: { name: 'Spain', num: '724', words: ['Spain'] },
  IT: { name: 'Italy', num: '380', words: ['Italy', 'Italian'] },
};

export const CATEGORIES = {
  state: 'Nation-state',
  crime: 'Criminal',
  hacktivist: 'Hacktivist',
  spyware: 'Commercial spyware',
  unknown: 'Motive not stated',
};

// Vendor naming conventions: the last word of a name places the actor. [suffix, country, category, vendor]
const SUFFIXES = [
  ['Panda', 'CN', 'state', 'CrowdStrike'], ['Bear', 'RU', 'state', 'CrowdStrike'], ['Kitten', 'IR', 'state', 'CrowdStrike'],
  ['Chollima', 'KP', 'state', 'CrowdStrike'], ['Buffalo', 'VN', 'state', 'CrowdStrike'], ['Tiger', 'IN', 'state', 'CrowdStrike'],
  ['Leopard', 'PK', 'state', 'CrowdStrike'], ['Wolf', 'TR', 'state', 'CrowdStrike'], ['Spider', null, 'crime', 'CrowdStrike'],
  ['Jackal', null, 'hacktivist', 'CrowdStrike'],
  ['Typhoon', 'CN', 'state', 'Microsoft'], ['Blizzard', 'RU', 'state', 'Microsoft'], ['Sandstorm', 'IR', 'state', 'Microsoft'],
  ['Sleet', 'KP', 'state', 'Microsoft'], ['Cyclone', 'VN', 'state', 'Microsoft'], ['Rain', 'LB', 'state', 'Microsoft'],
  ['Hail', 'KR', 'state', 'Microsoft'], ['Dust', 'TR', 'state', 'Microsoft'], ['Tempest', null, 'crime', 'Microsoft'],
  ['Tsunami', null, 'spyware', 'Microsoft'],
  ['Taurus', 'CN', 'state', 'Unit 42'], ['Ursa', 'RU', 'state', 'Unit 42'], ['Serpens', 'IR', 'state', 'Unit 42'],
  ['Pisces', 'KP', 'state', 'Unit 42'], ['Libra', null, 'crime', 'Unit 42'], ['Scorpius', null, 'crime', 'Unit 42'],
];
// Secureworks names lead with a metal
const PREFIXES = [['Bronze', 'CN', 'state'], ['Iron', 'RU', 'state'], ['Cobalt', 'IR', 'state'], ['Nickel', 'KP', 'state'], ['Gold', null, 'crime']];
// Suffixes distinctive enough to find in running text in Title Case ("Volt Typhoon"); the rest are
// common words ("Arctic Wolf" is a vendor) and count in text only in CrowdStrike's ALL CAPS
const TEXT_SUFFIXES = new Set(['Panda', 'Kitten', 'Chollima', 'Spider', 'Jackal', 'Typhoon', 'Blizzard', 'Sandstorm', 'Sleet', 'Cyclone', 'Tempest', 'Ursa', 'Serpens', 'Scorpius']);

// Groups whose attribution is settled in public reporting, by name as written. [names, country, category]
const KNOWN = [
  [['APT1', 'APT3', 'APT10', 'APT15', 'APT27', 'APT31', 'APT40', 'APT41', 'Winnti', 'Hafnium', 'Gallium', 'Earth Lusca', 'Earth Preta',
    'Earth Estries', 'GhostEmperor', 'FamousSparrow', 'Velvet Ant', 'BlackTech', 'UNC3886', 'UNC5221', 'UNC4841', 'UNC5174',
    'Storm-0558', 'Storm-0940', 'Storm-2603', 'Mustang Panda'], 'CN', 'state'],
  [['APT28', 'APT29', 'APT44', 'Sandworm', 'Turla', 'Gamaredon', 'COLDRIVER', 'Callisto', 'Sofacy', 'NOBELIUM', 'Sednit'], 'RU', 'state'],
  [['Lazarus', 'APT37', 'APT38', 'APT43', 'Kimsuky', 'Andariel', 'BlueNoroff', 'TraderTraitor', 'ScarCruft', 'Konni', 'UNC4899'], 'KP', 'state'],
  [['APT33', 'APT34', 'APT35', 'APT42', 'OilRig', 'MuddyWater', 'CyberAv3ngers', 'Agrius', 'Infy', 'Prince of Persia', 'Handala',
    'Homeland Justice'], 'IR', 'state'],
  [['APT32', 'OceanLotus'], 'VN', 'state'],
  [['Patchwork', 'SideWinder'], 'IN', 'state'],
  [['APT36', 'Transparent Tribe', 'SideCopy'], 'PK', 'state'],
  [['Sea Turtle'], 'TR', 'state'],
  [['Ghostwriter', 'UNC1151'], 'BY', 'state'],
  [['Cyber Partisans'], 'BY', 'hacktivist'],
  [['POLONIUM', 'Dark Caracal'], 'LB', 'state'],
  [['Syrian Electronic Army'], 'SY', 'hacktivist'],
  [['Candiru', 'NSO Group', 'Paragon'], 'IL', 'spyware'],
  [['Scattered Spider', 'ShinyHunters', 'LAPSUS$', 'LockBit', 'ALPHV', 'BlackCat', 'Cl0p', 'Clop', 'Akira', 'Qilin', 'Rhysida',
    'Black Basta', 'Medusa', 'RansomHub', 'BlackSuit', 'INC Ransom', 'Interlock', 'SafePay', 'DragonForce', 'Nefilim', 'Hive', 'Conti',
    'Evil Corp', 'TA505'], null, 'crime'],
];

// One actor under several vendors' names (the vendors' published alias tables), so a report listing
// "Jade Sleet" and another saying "TraderTraitor" count one adversary, not two
const ALIAS_GROUPS = [
  ['Lazarus', 'Diamond Sleet', 'Labyrinth Chollima', 'Hidden Cobra', 'ZINC'],
  ['APT38', 'BlueNoroff', 'Sapphire Sleet', 'Stardust Chollima'],
  ['TraderTraitor', 'Jade Sleet', 'UNC4899', 'Slow Pisces'],
  ['Andariel', 'Onyx Sleet', 'Silent Chollima', 'APT45'],
  ['Kimsuky', 'Emerald Sleet', 'APT43', 'Velvet Chollima', 'THALLIUM'],
  ['ScarCruft', 'APT37', 'Ricochet Chollima', 'InkySquid'],
  ['Moonstone Sleet', 'Storm-1789'],
  ['APT28', 'Fancy Bear', 'Forest Blizzard', 'Sofacy', 'Sednit', 'STRONTIUM', 'Fighting Ursa', 'BlueDelta'],
  ['APT29', 'Cozy Bear', 'Midnight Blizzard', 'NOBELIUM', 'Cloaked Ursa', 'BlueBravo'],
  ['Sandworm', 'APT44', 'Seashell Blizzard', 'Voodoo Bear', 'IRIDIUM'],
  ['Turla', 'Secret Blizzard', 'Venomous Bear'],
  ['Gamaredon', 'Aqua Blizzard', 'Primitive Bear', 'Shuckworm'],
  ['COLDRIVER', 'Star Blizzard', 'Callisto', 'SEABORGIUM'],
  ['Cadet Blizzard', 'Ember Bear', 'DEV-0586'],
  ['Volt Typhoon', 'Vanguard Panda', 'Bronze Silhouette', 'Insidious Taurus'],
  ['Salt Typhoon', 'Earth Estries', 'GhostEmperor', 'FamousSparrow'],
  ['Silk Typhoon', 'Hafnium'],
  ['Flax Typhoon', 'Ethereal Panda'],
  ['APT41', 'Brass Typhoon', 'Wicked Panda', 'Barium'],
  ['APT40', 'Gingham Typhoon', 'Leviathan', 'Kryptonite Panda'],
  ['APT31', 'Violet Typhoon', 'Judgment Panda', 'Zirconium'],
  ['Mustang Panda', 'Earth Preta', 'Stately Taurus', 'RedDelta', 'TA416', 'Bronze President'],
  ['APT27', 'Linen Typhoon', 'Emissary Panda', 'LuckyMouse'],
  ['APT15', 'Nylon Typhoon', 'Ke3chang', 'Vixen Panda'],
  ['APT33', 'Peach Sandstorm', 'Refined Kitten', 'Elfin'],
  ['APT34', 'OilRig', 'Hazel Sandstorm', 'Helix Kitten'],
  ['APT35', 'Charming Kitten', 'Mint Sandstorm', 'Phosphorus'],
  ['MuddyWater', 'Mango Sandstorm', 'Static Kitten', 'Seedworm', 'Boggy Serpens'],
  ['Pioneer Kitten', 'Fox Kitten', 'Lemon Sandstorm'],
  ['Prince of Persia', 'Infy'],
  ['APT32', 'OceanLotus', 'Canvas Cyclone'],
  ['Sea Turtle', 'Marbled Dust', 'Cosmic Wolf'],
  ['POLONIUM', 'Plaid Rain'],
  ['Ghostwriter', 'UNC1151'],
  ['Transparent Tribe', 'APT36'],
  ['Scattered Spider', 'Octo Tempest', 'UNC3944', 'Muddled Libra'],
  ['Cl0p', 'Clop'],
  ['ALPHV', 'BlackCat'],
];

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const WORDS = Object.entries(COUNTRIES).flatMap(([cc, c]) => c.words.map((w) => [w, cc])).sort((a, b) => b[0].length - a[0].length);
const CC_OF = new Map(WORDS);
// a country word, not inside a longer word and not "pro-Ukrainian" / "anti-Russian" / "non-Chinese"
const LB = '(?<![A-Za-z])(?<!(?:pro|Pro|anti|Anti|non|Non)-)';
const W = `(${WORDS.map(([w]) => esc(w)).join('|')})(?![A-Za-z])`;
const NEXUS = '(?:nexus|linked|aligned|backed|sponsored|affiliated|attributed|connected|tied|origin)';
const DESC = '(?:suspected|alleged|likely|possibly|probable|state[- ]sponsored|state[- ]backed|state[- ]linked|government[- ]backed|'
  + 'nation[- ]state|cyber[- ]?espionage|espionage|threat|APT|cyber|hacking|hacker|hackers|hacktivist|hacktivists|actor|actors|group|'
  + 'cluster|crew|operator|unit|intrusion|set|gang|advanced|persistent|military|intelligence|influence)';
// text right before a name: "China-nexus actor ", "North Korea's ", "Iranian state-sponsored ", "a North Korean ("
const BEFORE = new RegExp(`${LB}${W}(?:[- ](?:${NEXUS}|based)|'s)?(?:\\s+(?:${DESC}|\\([^)]{0,40}\\)))*\\s*\\(?\\s*$`);
// text right after a name: ", a China-aligned espionage cluster" / " (China-nexus)"
const AFTER = new RegExp(`^\\s*(?:\\([^)]{0,60}\\)\\s*)?,\\s*(?:a|an|the)\\s+(?:(?:suspected|likely|alleged)\\s+)?${LB}${W}[- ](?:${NEXUS}|based|state[- ]sponsored)|^\\s*\\([^)]*?${LB}${W}[- ]${NEXUS}(?![A-Za-z])[^)]*\\)`);
// story-level cues with no name attached: "China-nexus", "Russia-linked", "North Korean threat actors"
const NEXUS_CUE = new RegExp(`${LB}${W}[- ]${NEXUS}(?![A-Za-z])`, 'g');
const NOUN_CUE = new RegExp(`${LB}${W}(?:[- ]based)?(?:\\s+(?:state[- ]sponsored|state[- ]backed|government[- ]backed|nation[- ]state|espionage|`
  + 'cyber[- ]?espionage|APT|threat|hacking|military|intelligence|influence|IT|cyber|ransomware))*\\s+(?:actors?|hackers?|hacktivists?|APTs?|'
  + 'spies|operatives|crews?|gangs?|groups?|clusters?|operators?|IT workers?|campaigns?|operations?)(?![A-Za-z])', 'g');
// any country word in the actor field, unless it names a language ("Russian-speaking", "Chinese-language")
const FIELD_CUE = new RegExp(`${LB}${W}(?![- ](?:speaking|language|speakers))`, 'g');
const FIELD_STATE = new RegExp(`${LB}${W}(?:[- ]${NEXUS}|\\s+(?:government|state|military|intelligence))`);

const CATEGORY_CUES = [
  ['hacktivist', /\bhacktivis/i],
  ['spyware', /\b(?:spyware|surveillance vendor|mercenary|commercial surveillance)\b/i],
  ['state', /\b(?:state[- ]sponsored|state[- ]backed|nation[- ]state|espionage|influence operations?|government|intelligence service)\b/i],
  ['crime', /\b(?:ransomware|extortion|financially[- ]motivated|cyber ?crim\w*|fraud\w*|scams?|scammers?|skimm\w*|carding|stealers?|infostealers?|phishing kits?|PhaaS|affiliates?|affiliate program|initial access broker|cryptojack\w*|miners?)\b/i],
];
// in a story's own text, "government" is usually the victim; only the actor field may use it
const TEXT_CATEGORY_CUES = CATEGORY_CUES.map(([c, re]) => [c, c === 'state' ? /\b(?:state[- ]sponsored|state[- ]backed|nation[- ]state|espionage|influence operations?)\b/i : re]);
const categoryIn = (text, cues = CATEGORY_CUES) => (cues.find(([, re]) => re.test(text)) || [])[0] || null;

/** Normalized key: "ARMORY CASTLE" = "Armory Castle", "Lazarus Group" = "Lazarus", "The Gentlemen" = "Gentlemen". */
export function actorKey(name) {
  return String(name).normalize('NFKD').replace(/[̀-ͯ]/g, '').trim()
    .replace(/^the\s+/i, '').replace(/\s+(?:group|team)$/i, '').toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9$]/g, '');
}

const KNOWN_BY_KEY = new Map(KNOWN.flatMap(([names, cc, cat]) => names.map((n) => [actorKey(n), { cc, cat, name: n }])));
// key → the settled group it belongs to: its alias-table row (by the row's first name), else itself if known
const SETTLED = new Map([...KNOWN_BY_KEY.keys()].map((k) => [k, k]));
for (const g of ALIAS_GROUPS) for (const nm of g) SETTLED.set(actorKey(nm), actorKey(g[0]));
// known state groups found by name in running text; names that are also everyday words are not
const TEXT_KNOWN_SKIP = new Set(['Patchwork', 'Callisto', 'Gallium', 'Infy']);
const KNOWN_STATE_RE = new RegExp(`(?<![\\w-])(${KNOWN.filter(([, cc, cat]) => cc && cat === 'state').flatMap(([n]) => n)
  .filter((n) => !TEXT_KNOWN_SKIP.has(n)).sort((a, b) => b.length - a.length).map(esc).join('|')})(?![\\w-])`, 'g');
const TEXT_NAME_RE = new RegExp(`\\b((?:[A-Z][a-z]+|[A-Z]{2,})\\s(?:${SUFFIXES.map(([s]) => `${s}|${s.toUpperCase()}`).join('|')}))\\b`, 'g');

/** What a name alone says, from the known list or the vendor's naming convention. */
export function nameBasis(name) {
  const known = KNOWN_BY_KEY.get(actorKey(name));
  if (known) return { cc: known.cc, cat: known.cat, rank: 0, text: known.cc ? `public reporting attributes ${known.name} to ${COUNTRIES[known.cc].name}` : `${known.name} is a known ${CATEGORIES[known.cat].toLowerCase()} group` };
  const words = String(name).trim().split(/\s+/);
  if (words.length >= 2) {
    const last = words.at(-1).toLowerCase(); const first = words[0].toLowerCase();
    const s = SUFFIXES.find(([x]) => x.toLowerCase() === last);
    if (s) return { cc: s[1], cat: s[2], rank: 1, text: `${s[3]} names ${s[1] ? `${COUNTRIES[s[1]].name}-based` : CATEGORIES[s[2]].toLowerCase()} actors "… ${s[0]}"` };
    const p = PREFIXES.find(([x]) => x.toLowerCase() === first);
    if (p) return { cc: p[1], cat: p[2], rank: 1, text: `Secureworks names ${p[1] ? `${COUNTRIES[p[1]].name}-based` : 'criminal'} actors "${p[0]} …"` };
  }
  if (/^CL-STA-\d/i.test(name)) return { cc: null, cat: 'state', rank: 1, text: 'Unit 42 "CL-STA" marks a state-sponsored cluster' };
  if (/^CL-CRI-\d/i.test(name) || /^FIN\d+$/i.test(name)) return { cc: null, cat: 'crime', rank: 1, text: `"${name.replace(/\d.*$/, '')}" marks a financially motivated cluster` };
  return null;
}

// ---- the actor field ----

const ALIAS_KEYWORD = /^(?:also known as|also tracked as|tracked as|formerly|also|aka|a\.k\.a\.|overlaps(?: with)?|dubbed|now)\s+/i;
const GENERIC_TAIL = /(?:\s+(?:ransomware|actors?|affiliates?|group|gang|operators?|crew|hackers?|hacktivists?|team|cluster|campaign|operation|spyware|phishing kits?))+$/;
const CONNECTOR = /^(?:of|the|de|del|la|el|and|in)$/;

// split at top level (outside parentheses) on any of the separators
function splitTop(s, seps) {
  const out = []; let depth = 0; let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '(') depth++;
    if (ch === ')') depth = Math.max(0, depth - 1);
    const sep = depth === 0 && seps.find((x) => s.startsWith(x, i));
    if (sep) { out.push(cur); cur = ''; i += sep.length - 1; continue; }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

/** A name, not a description: one token, or a few Capitalized / ALL CAPS / numbered words. */
export function nameLike(s) {
  const t = String(s || '').trim();
  if (t.length < 2 || /^(?:unknown|unnamed|unattributed|multiple|various|several|threat actors?|actors?|attackers?|hackers?)$/i.test(t)) return false;
  if (/^(?:suspected|unnamed|unknown|unidentified|possible|possibly|likely|alleged|multiple|various|several|financially|state|nation)\b/i.test(t)) return false;
  // a country word that describes ("Belarus-linked", "Chinese-speaking") is not part of a name
  if (CC_OF.has(t) || new RegExp(`${LB}${W}[- ](?:${NEXUS}|based|speaking|language)`).test(t)) return false;
  const words = t.split(/\s+/);
  if (words.length === 1) return true;
  if (words.length > 6 || CONNECTOR.test(words[0])) return false;
  return words.every((w) => /^[A-Z0-9]/.test(w) || CONNECTOR.test(w));
}

// an alias read from running text: a name, and not a CVE, a technique, a version or a number
const aliasLike = (s) => nameLike(s) && s.length <= 40 && !/^(?:CVE-|T\d{4}|\d)|[.:@]/i.test(s);

/**
 * The extractor's threat_actor field → { names: [[alias, …] per actor], cues: text that is not a
 * name (descriptions, annotations, stripped words) and so speaks about every name in the field }.
 * "Warp Panda (also Armory Castle, UNC5221)" is one actor with three names; "Salt Typhoon; Interlock"
 * is two; "Suspected China-nexus actor (unnamed)" is no name and one cue.
 */
export function parseActorField(raw) {
  const names = []; const cues = [];
  // one "/" segment: its name, then the aliases in its parentheses; other parentheses are cues
  const segment = (seg) => {
    const parens = [];
    const outside = seg.replace(/\(([^()]*)\)/g, (m, inner) => {
      const body = inner.trim();
      const kw = ALIAS_KEYWORD.test(body);
      // not on " and ": "(Hive and Nefilim affiliate)" describes, it does not alias
      const pieces = splitTop(body.replace(ALIAS_KEYWORD, ''), [',', '/', ';']);
      if (kw || (pieces.length && pieces.every(nameLike))) parens.push(...pieces);
      else cues.push(body);
      return ' ';
    }).replace(/\s+/g, ' ').trim();
    const out = [];
    for (const cand of [outside, ...parens].filter(Boolean)) {
      const tail = cand.match(GENERIC_TAIL);
      const core = tail ? cand.slice(0, tail.index).trim() : cand;
      if (tail) cues.push(tail[0].trim());
      if (core && nameLike(core)) out.push(core);
      else cues.push(cand);
    }
    return { outside, names: out };
  };
  const designation = (s) => (String(s).match(/^([A-Za-z]+)[- ]?\d/) || [])[1]?.toLowerCase() || null;
  for (const part of splitTop(String(raw || ''), [';', ',', ' and ', ' & ', ' + '])) {
    const segs = splitTop(part, ['/']).map(segment);
    // "UAT-6275 / TAG-193" aliases; "Storm-2990 / Storm-3119" (one vendor, two numbers) and
    // "UAC-0099 / Sandworm" (a known group beside another) are two actors
    const pre = segs.map((s) => designation(s.outside));
    const separate = segs.length > 1 && ((pre[0] && pre.every((p) => p === pre[0])) || segs.some((s) => nameBasis(s.outside)));
    for (const list of separate ? segs.map((s) => s.names) : [segs.flatMap((s) => s.names)]) {
      const uniq = [...new Map(list.map((a) => [actorKey(a), a])).values()].filter((a) => actorKey(a).length >= 2);
      if (uniq.length) names.push(uniq);
    }
  }
  return { names, cues };
}

// ---- per-story reading ----

const clauseBefore = (text, i) => { const s = text.slice(Math.max(0, i - 90), i); const cut = Math.max(s.lastIndexOf('. '), s.lastIndexOf('; '), s.lastIndexOf('||')); return cut >= 0 ? s.slice(cut + 2) : s; };
const snippet = (text, i, len) => text.slice(Math.max(0, i), Math.min(text.length, i + len)).replace(/\s+/g, ' ').trim();

/** Country cues a story's text attaches to one of its names ("China-nexus Volt Typhoon"). */
function anchoredCues(name, text, where) {
  const out = [];
  const re = new RegExp(`(?<![\\w-])${esc(name)}(?![\\w-])`, 'gi');
  for (const m of text.matchAll(re)) {
    const before = clauseBefore(text, m.index).match(BEFORE);
    if (before) { out.push({ cc: CC_OF.get(before[1]), rank: where === 'title' ? 3 : 4, state: true, text: `the ${where} says "${snippet(text, m.index - before[0].length, before[0].length + name.length)}"` }); continue; }
    const after = text.slice(m.index + m[0].length, m.index + m[0].length + 90).match(AFTER);
    if (after) out.push({ cc: CC_OF.get(after[1] || after[2]), rank: where === 'title' ? 3 : 4, state: true, text: `the ${where} says "${snippet(text, m.index, m[0].length + after[0].length)}"` });
  }
  return out;
}

function storyCues(text, where) {
  const out = [];
  for (const re of [NEXUS_CUE, NOUN_CUE]) {
    for (const m of text.matchAll(re)) {
      // quote the cue with the words that follow it, up to a word boundary ("Iran-linked freezer hacks")
      const more = text.slice(m.index + m[0].length, m.index + m[0].length + 28);
      const tail = /[.;,]/.test(more) ? more.slice(0, more.search(/[.;,]/)) : more.replace(/\s+\S*$/, '');
      out.push({ cc: CC_OF.get(m[1]), rank: where === 'title' ? 5 : 6, state: re === NEXUS_CUE, text: `the ${where} says "${snippet(text, m.index, m[0].length + tail.length)}"` });
    }
  }
  return out;
}

/** Names a story's text mentions that place themselves: "Volt Typhoon", "FANCY BEAR", "APT28". */
function textNames(text) {
  const out = [];
  for (const m of text.matchAll(TEXT_NAME_RE)) {
    const [first, suffix] = m[1].split(/\s/);
    if (/^(?:The|A|An|This|That|Its|Their|Each|Every|Super|Tropical)$/i.test(first)) continue;
    if (suffix === suffix.toUpperCase() ? m[1] === m[1].toUpperCase() : TEXT_SUFFIXES.has(suffix)) out.push(m[1]);
  }
  for (const m of text.matchAll(KNOWN_STATE_RE)) out.push(m[1]);
  return out;
}

/**
 * Read one story: its named actors (each a list of aliases) with every basis found, and the
 * unnamed attribution when the story names none.
 */
export function readStory(s) {
  const title = String(s.title || ''); const summary = String(s.summary || ''); const field = String(s.threat_actor || '');
  const { names, cues } = parseActorField(field);
  const fieldCues = cues.join(' · ');
  const actors = names.map((aliases) => ({ aliases, basis: [], from: 'field' })); // aliases[0]: the name as the field leads with it
  const has = (n) => actors.some((a) => a.aliases.some((x) => actorKey(x) === actorKey(n)));
  // the story's text gives aliases in parentheses after a name: "ARMORY CASTLE (UNC5221/Warp Panda)"
  const expand = (a) => {
    for (const n of [...a.aliases]) {
      const re = new RegExp(`(?<![\\w-])${esc(n)}\\s*\\(([^()]{2,90})\\)`, 'gi');
      for (const text of [title, summary]) for (const m of text.matchAll(re)) {
        const pieces = splitTop(m[1].trim().replace(ALIAS_KEYWORD, ''), [',', '/', ';']);
        if (pieces.length && pieces.every(aliasLike)) for (const p of pieces) if (!has(p)) a.aliases.push(p);
      }
    }
  };
  actors.forEach(expand);
  for (const [text, where] of [[title, 'title'], [summary, 'summary']]) {
    for (const n of textNames(text)) if (!has(n)) { const a = { aliases: [n], basis: [], from: where }; actors.push(a); expand(a); }
  }
  const fieldCountry = [...(field.replace(/\(([^()]*)\)/g, ' ($1) ')).matchAll(FIELD_CUE)].map((m) => m[1]);
  const fieldState = FIELD_STATE.test(field);
  for (const a of actors) {
    // a name's own basis says which name it came from, in case that name turns out to be another actor's
    for (const n of a.aliases) {
      const nb = nameBasis(n);
      if (nb) a.basis.push({ ...nb, alias: n });
      a.basis.push(...[...anchoredCues(n, title, 'title'), ...anchoredCues(n, summary, 'summary')].map((b) => ({ ...b, alias: n })));
    }
    if (a.from === 'field') {
      for (const w of fieldCountry) a.basis.push({ cc: CC_OF.get(w), rank: 2, state: fieldState, text: `the actor field says "${field}"` });
      const cat = categoryIn(fieldCues);
      if (cat) a.basis.push({ cc: null, cat, rank: 2, text: `the actor field says "${field}"` });
    }
  }
  const textCat = categoryIn(`${title} ${summary}`, TEXT_CATEGORY_CUES);
  // no name: the field's own description, else the title's cues, else (only then) the summary's
  let unnamed = null;
  const namedCountries = new Set(actors.flatMap((a) => a.basis.map((b) => b.cc)).filter(Boolean));
  const fieldDesc = !names.length && field ? fieldCountry.map((w) => ({ cc: CC_OF.get(w), rank: 2, state: fieldState, text: `the actor field says "${field}"` })) : [];
  const loose = fieldDesc.length ? fieldDesc : [...storyCues(title, 'title'), ...(actors.length ? [] : storyCues(summary, 'summary'))];
  const looseNew = loose.filter((c) => !namedCountries.has(c.cc));
  // a country-attributed actor takes its kind from the field's own words only: a story about North
  // Korean IT workers mentions fraud, and that does not make the operation a criminal gang's
  if (looseNew.length) unnamed = { basis: looseNew, label: !names.length && field ? field : null, cat: categoryIn(fieldCues || field) };
  else if (!names.length && field && !actors.length) unnamed = { basis: [], label: field, cat: categoryIn(field) || textCat };
  return { actors, unnamed, textCat };
}

// ---- the corpus ----

const dateOf = (s) => String(s.brief_date || s.created_at || '').slice(0, 10);
// one update chain = one story: the root of updates_story_id, as far back as the rows go
function threadRoots(rows) {
  const parent = new Map(rows.map((r) => [r.id, r.updates_story_id || null]));
  const root = (id) => { let x = id; const seen = new Set(); while (parent.get(x) && !seen.has(x)) { seen.add(x); x = parent.get(x); } return x; };
  return new Map(rows.map((r) => [r.id, root(r.id)]));
}

// pick the attribution: the strongest basis wins, then the most frequent country among equals
function decide(basis) {
  const withCc = basis.filter((b) => b.cc);
  let cc = null;
  if (withCc.length) {
    const best = Math.min(...withCc.map((b) => b.rank));
    const tally = new Map();
    for (const b of withCc.filter((x) => x.rank === best)) tally.set(b.cc, (tally.get(b.cc) || 0) + 1);
    cc = [...tally].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
  }
  const explicit = basis.filter((b) => b.cat && b.rank <= 1).sort((a, b) => a.rank - b.rank)[0];
  const fieldCat = basis.find((b) => b.cat && b.rank === 2);
  const stateCue = basis.some((b) => b.cc && b.state);
  const cat = explicit?.cat || (stateCue ? 'state' : null) || fieldCat?.cat || null;
  return { cc, cat };
}

// malware/tool names: the extractor's malware_family values, split and stripped of "ransomware" etc.
function toolNames(field) {
  return splitTop(String(field || '').replace(/\([^)]*\)/g, (m) => `, ${m.slice(1, -1)}`), [';', ',', '/'])
    .map((t) => t.replace(/\s+(?:ransomware|spyware|stealer|backdoor|malware|phishing kits?|variant|loader)$/i, '').replace(/^(?:a|an|the)\s+/i, '').trim())
    .filter((t) => t.length >= 3 && !/^(?:mirai variant|unknown|none|unnamed)$/i.test(t));
}

/**
 * Attribute every story. rows: extracted stories with id, title, summary, threat_actor,
 * malware_family, updates_story_id and brief_date (or created_at). Returns
 * { actors: Map key → actor, stories: [{ id, thread, date, keys }], toolsByStory: Map id → [tool] }.
 */
export function attribute(rows) {
  const roots = threadRoots(rows);
  // union-find over alias keys. Each component remembers which settled groups (a known group or a
  // vendor alias table) it holds, and two components holding different ones never merge: a source
  // writing "TraderTraitor (Lazarus)" for a subgroup does not make TraderTraitor and Lazarus one actor
  const parent = new Map(); const settled = new Map(); // root → Set of settled-group ids
  const find = (k) => { while (parent.has(k) && parent.get(k) !== k) k = parent.get(k); return k; };
  const node = (k) => { if (!parent.has(k)) { parent.set(k, k); if (SETTLED.has(k)) settled.set(k, new Set([SETTLED.get(k)])); } };
  const union = (a, b) => {
    const ra = find(a); const rb = find(b);
    if (ra === rb) return;
    const sa = settled.get(ra); const sb = settled.get(rb);
    if (sa && sb && ![...sa].some((g) => sb.has(g))) return;
    parent.set(rb, ra);
    if (sb) settled.set(ra, new Set([...(sa || []), ...sb]));
    settled.delete(rb);
  };
  const read = rows.map((s) => ({ s, r: readStory(s) }));
  for (const { r } of read) for (const a of r.actors) {
    const keys = a.aliases.map(actorKey);
    for (const k of keys) {
      node(k);
      const g = SETTLED.get(k);
      if (g && g !== k) { node(g); union(g, k); }
    }
    for (const k of keys.slice(1)) union(keys[0], k);
  }
  const actors = new Map();
  const get = (key) => {
    if (!actors.has(key)) actors.set(key, { key, surfaces: new Map(), basis: [], textCats: [], stories: new Set(), threads: new Set(), dates: [] });
    return actors.get(key);
  };
  const stories = [];
  for (const { s, r } of read) {
    const thread = roots.get(s.id); const date = dateOf(s); const keys = [];
    for (const a of r.actors) {
      // a story actor whose names fell into separate components counts for each of them
      const byRoot = new Map();
      a.aliases.forEach((nm, i) => { const k = find(actorKey(nm)); if (!byRoot.has(k)) byRoot.set(k, []); byRoot.get(k).push([nm, i]); });
      for (const [root, list] of byRoot) {
        const x = get(root);
        // the display name: the one fields lead with most, then their aliases, then names in text
        for (const [nm, i] of list) x.surfaces.set(nm, (x.surfaces.get(nm) || 0) + (a.from !== 'field' ? 1 : i ? 2 : 3));
        x.basis.push(...a.basis.filter((b) => !b.alias || find(actorKey(b.alias)) === root).map((b) => ({ ...b, story: s.id })));
        if (r.textCat) x.textCats.push(r.textCat);
        x.stories.add(s.id); x.threads.add(thread); x.dates.push(date); keys.push(x.key);
      }
    }
    if (r.unnamed) {
      const { cc } = decide(r.unnamed.basis);
      const key = `~${cc || r.unnamed.cat || 'unknown'}`;
      const x = get(key); x.unnamed = true;
      if (r.unnamed.label) x.surfaces.set(r.unnamed.label, (x.surfaces.get(r.unnamed.label) || 0) + 1);
      x.basis.push(...r.unnamed.basis.map((b) => ({ ...b, story: s.id })));
      if (r.unnamed.cat) x.basis.push({ cc: null, cat: r.unnamed.cat, rank: 2, text: 'the story describes the actor', story: s.id });
      x.stories.add(s.id); x.threads.add(thread); x.dates.push(date); keys.push(key);
    }
    stories.push({ id: s.id, thread, date, keys: [...new Set(keys)], title: s.title || '' });
  }
  for (const x of actors.values()) {
    const { cc, cat } = decide(x.basis);
    x.country = x.unnamed ? (x.key.length === 3 && COUNTRIES[x.key.slice(1)] ? x.key.slice(1) : null) : cc;
    const textCat = [...new Set(x.textCats)].sort((a, b) => x.textCats.filter((c) => c === b).length - x.textCats.filter((c) => c === a).length)[0] || null;
    x.category = cat || (x.country ? 'state' : textCat || 'unknown');
    x.name = x.unnamed ? `Unnamed ${x.country ? `${COUNTRIES[x.country].name}-attributed actor` : `${CATEGORIES[x.category].toLowerCase()} actor`}` : [...x.surfaces].sort((a, b) => b[1] - a[1] || b[0].length - a[0].length)[0][0];
    // other names, one per key ("STORM-0940" is Storm-0940 again, not an alias), most used first
    x.aliases = x.unnamed ? [] : [...new Map([...x.surfaces].sort((a, b) => a[1] - b[1]).map(([nm]) => [actorKey(nm), nm])).entries()]
      .filter(([k]) => k !== actorKey(x.name)).map(([, nm]) => nm).reverse();
    x.first = x.dates.sort()[0]; x.last = x.dates.at(-1);
    // the bases that decided it, strongest first, one line per distinct reading
    const seen = new Set();
    x.why = x.basis.filter((b) => (x.country ? b.cc === x.country : !b.cc)).sort((a, b) => a.rank - b.rank)
      .filter((b) => !seen.has(b.text) && seen.add(b.text)).slice(0, 4).map((b) => b.text);
  }
  // tools: every malware_family name that is not also an actor's (ransomware brands are both), and
  // found by name in other stories' text only when the name cannot be an ordinary word ("ARTEX",
  // "GhostAction", "cache_base" — not "Phantom" or "Tornado")
  const vocab = new Map();
  for (const s of rows) for (const t of toolNames(s.malware_family)) if (!vocab.has(actorKey(t)) && !parent.has(actorKey(t))) vocab.set(actorKey(t), t);
  const distinct = (t) => t.length >= 4 && ((t.match(/[A-Z]/g) || []).length >= 2 || /[\d_]/.test(t));
  const toolRes = [...vocab.values()].filter(distinct).map((t) => [actorKey(t), new RegExp(`(?<![\\w-])(?:${esc(t)}|${esc(t.toUpperCase())})(?![\\w-])`)]);
  const toolsByStory = new Map(rows.map((s) => {
    const text = `${s.title || ''} ${s.summary || ''}`;
    const keys = new Set(toolNames(s.malware_family).map(actorKey).filter((k) => vocab.has(k)));
    for (const [k, re] of toolRes) if (re.test(text)) keys.add(k);
    return [s.id, [...keys]];
  }));
  return { actors, stories, toolsByStory, toolName: (k) => vocab.get(k) || k };
}

const addDays = (date, n) => new Date(Date.parse(`${date}T00:00:00Z`) + n * 86400000).toISOString().slice(0, 10);
const weekOf = (date) => { const d = new Date(`${date}T00:00:00Z`); return addDays(date, -((d.getUTCDay() + 6) % 7)); }; // Monday

/**
 * The Actors tab's numbers. days: window length (null = everything loaded); category: one of
 * CATEGORIES or null; today: YYYY-MM-DD. Counts are distinct update chains ("stories") and
 * distinct actors; an unnamed attribution counts as one actor per country.
 */
export function actorReport(rows, { days = 30, category = null, today = new Date().toISOString().slice(0, 10), weeks = 12 } = {}) {
  const { actors, stories, toolsByStory, toolName } = attribute(rows);
  const from = days ? addDays(today, -(days - 1)) : (stories.map((s) => s.date).filter(Boolean).sort()[0] || today);
  const inWin = (d) => d >= from && d <= today;
  const keep = (a) => !category || a.category === category;
  const dataFrom = stories.map((s) => s.date).filter(Boolean).sort()[0] || today;
  // up to `weeks` Monday-weeks ending this week, none before the first stored brief
  const back = weekOf(addDays(today, -7 * (weeks - 1))); const firstWeek = weekOf(dataFrom) > back ? weekOf(dataFrom) : back;
  const weekList = []; for (let w = firstWeek; w <= today; w = addDays(w, 7)) weekList.push(w);

  const byCountry = new Map();
  const cRow = (cc) => {
    if (!byCountry.has(cc)) byCountry.set(cc, { cc, name: COUNTRIES[cc].name, num: COUNTRIES[cc].num, actors: new Map(), threads: new Set(), weekly: new Map(), last7: new Set(), prev7: new Set(), cats: new Map(), latest: null });
    return byCountry.get(cc);
  };
  const noCountry = new Map(); // category -> Map key -> { actor, threads }
  const attributedThreads = new Set(); const allThreads = new Set(); const namedNoCountry = new Set();
  for (const st of stories) {
    if (!st.date) continue;
    if (inWin(st.date)) allThreads.add(st.thread);
    for (const key of st.keys) {
      const a = actors.get(key);
      if (!a || !keep(a)) continue;
      if (a.country) {
        const c = cRow(a.country);
        const wk = weekOf(st.date);
        if (wk >= firstWeek) { if (!c.weekly.has(wk)) c.weekly.set(wk, new Set()); c.weekly.get(wk).add(st.thread); }
        if (st.date > addDays(today, -7) && st.date <= today) c.last7.add(st.thread);
        else if (st.date > addDays(today, -14) && st.date <= addDays(today, -7)) c.prev7.add(st.thread);
        if (!inWin(st.date)) continue;
        if (!c.actors.has(key)) c.actors.set(key, { actor: a, threads: new Set(), latest: null });
        const e = c.actors.get(key); e.threads.add(st.thread);
        if (!e.latest || st.date > e.latest.date) e.latest = st;
        c.threads.add(st.thread); attributedThreads.add(st.thread);
        if (!c.latest || st.date > c.latest.date) c.latest = st;
      } else if (inWin(st.date)) {
        if (!noCountry.has(a.category)) noCountry.set(a.category, new Map());
        const m = noCountry.get(a.category);
        if (!m.has(key)) m.set(key, { actor: a, threads: new Set(), latest: null });
        const e = m.get(key); e.threads.add(st.thread);
        if (!e.latest || st.date > e.latest.date) e.latest = st;
        if (!a.unnamed) namedNoCountry.add(st.thread);
      }
    }
  }
  const actorOut = (e) => ({ key: e.actor.key, name: e.actor.name, aliases: e.actor.aliases, category: e.actor.category, unnamed: !!e.actor.unnamed,
    stories: e.threads.size, first_seen: e.actor.first, last_seen: e.actor.last, basis: e.actor.why,
    latest: e.latest ? { id: e.latest.id, date: e.latest.date, title: e.latest.title } : null });
  const countries = [...byCountry.values()].filter((c) => c.actors.size || c.last7.size || c.prev7.size).map((c) => {
    const list = [...c.actors.values()].sort((a, b) => b.threads.size - a.threads.size || a.actor.name.localeCompare(b.actor.name)).map(actorOut);
    const cats = {}; for (const a of list) cats[a.category] = (cats[a.category] || 0) + 1;
    return { cc: c.cc, name: c.name, num: c.num, adversaries: list.length, stories: c.threads.size, categories: cats, actors: list,
      weekly: weekList.map((w) => (w < weekOf(dataFrom) ? null : c.weekly.get(w)?.size || 0)),
      last7: c.last7.size, prev7: dataFrom <= addDays(today, -13) ? c.prev7.size : null,
      latest: c.latest ? { id: c.latest.id, date: c.latest.date, title: c.latest.title } : null };
  }).sort((a, b) => b.stories - a.stories || b.adversaries - a.adversaries || a.name.localeCompare(b.name));

  // tools across actors: which countries' actors the stories naming a tool are attributed to
  const tools = new Map();
  for (const st of stories) {
    if (!st.date || !inWin(st.date)) continue;
    const ccs = [...new Set(st.keys.map((k) => actors.get(k)).filter((a) => a && keep(a)).map((a) => a.country || null))];
    if (category && !ccs.length) continue;
    for (const t of toolsByStory.get(st.id) || []) {
      if (!tools.has(t)) tools.set(t, { name: toolName(t), threads: new Set(), by: new Map(), latest: null });
      const x = tools.get(t);
      if (x.threads.has(st.thread)) continue;
      x.threads.add(st.thread);
      for (const cc of ccs.length ? ccs : [null]) x.by.set(cc, (x.by.get(cc) || 0) + 1);
      if (!x.latest || st.date > x.latest.date) x.latest = st;
    }
  }
  const toolList = [...tools.values()].filter((t) => t.threads.size >= 2)
    .sort((a, b) => b.threads.size - a.threads.size || b.by.size - a.by.size || a.name.localeCompare(b.name)).slice(0, 12)
    .map((t) => ({ name: t.name, stories: t.threads.size,
      by: [...t.by].sort((a, b) => (a[0] ? 0 : 1) - (b[0] ? 0 : 1) || b[1] - a[1]).map(([cc, n]) => ({ cc, name: cc ? COUNTRIES[cc].name : 'not attributed to a country', stories: n })),
      latest: t.latest ? { id: t.latest.id, date: t.latest.date, title: t.latest.title } : null }));

  const nc = Object.fromEntries([...noCountry].map(([cat, m]) => [cat, [...m.values()].sort((a, b) => b.threads.size - a.threads.size || a.actor.name.localeCompare(b.actor.name)).map(actorOut)]));
  const advTotal = countries.reduce((n, c) => n + c.adversaries, 0);
  return {
    window: { days, from, to: today, category, data_from: dataFrom },
    weeks: weekList,
    totals: { countries: countries.filter((c) => c.adversaries).length, adversaries: advTotal, attributed_stories: attributedThreads.size,
      stories: allThreads.size, named_no_country: namedNoCountry.size },
    countries, no_country: nc, tools: toolList,
  };
}
