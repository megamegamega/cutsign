// IoC normalization: refang → canonicalize → validate → classify. Pure functions, no I/O.
// Returns { type, value_norm } or { drop: reason }. Dropped: private/loopback/bogon/documentation
// IPs, placeholder domains (example.com…), known-empty or all-same-digit hashes, malformed values.

import { isIP } from 'node:net';

export function refang(v) {
  return String(v ?? '').trim()
    .replace(/^["'`<\s]+|["'`>\s,;]+$/g, '')
    .replace(/\bh(xx|\*\*|XX)p(s?)/gi, 'http$2')
    .replace(/\bfxp\b/gi, 'ftp')
    .replace(/\[\s*(\.|dot)\s*\]|\(\s*(\.|dot)\s*\)|\{\s*(\.|dot)\s*\}|\s+dot\s+/gi, '.')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*\/\s*\]/g, '/')
    .replace(/\[\s*(@|at)\s*\]|\(\s*(@|at)\s*\)/gi, '@')
    .replace(/\[\s*:\/\/\s*\]/g, '://')
    .trim();
}

const PLACEHOLDER_DOMAINS = /(^|\.)(example\.(com|net|org|edu)|example|test|invalid|localhost|local|lan|internal|corp|home\.arpa|domain\.(com|tld)|yourdomain\.com|contoso\.com|fabrikam\.com)$/i;
const FILE_EXT_TLDS = new Set(['exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'jse', 'hta', 'lnk', 'msi', 'sh', 'py', 'php',
  'jsp', 'aspx', 'asp', 'txt', 'log', 'tmp', 'dat', 'bin', 'so', 'elf', 'jar', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'iso', 'img', 'sys', 'cfg', 'conf', 'ini']);
const EMPTY_HASHES = new Set([
  'd41d8cd98f00b204e9800998ecf8427e',                                 // md5('')
  'da39a3ee5e6b4b0d3255bfef95601890afd80709',                         // sha1('')
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // sha256('')
]);
const HASH_LEN = { 32: 'md5', 40: 'sha1', 64: 'sha256' };

// ---- IPv4 ----
function v4ToInt(ip) { return ip.split('.').reduce((n, o) => n * 256 + Number(o), 0); }
const V4_BOGONS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([b, m]) => [v4ToInt(b), m]);
const V4_PLACEHOLDERS = new Set(['1.2.3.4', '1.1.1.1', '8.8.8.8', '8.8.4.4', '4.3.2.1', '255.255.255.255']);
function isBogonV4(ip) {
  const n = v4ToInt(ip);
  return V4_BOGONS.some(([base, m]) => Math.floor(n / 2 ** (32 - m)) === Math.floor(base / 2 ** (32 - m)));
}

// ---- IPv6 ----
function isBogonV6(ip) {
  const l = ip.toLowerCase();
  return l === '::' || l === '::1' || /^fe[89ab]/.test(l) || /^f[cd]/.test(l) || /^ff/.test(l) || l.startsWith('2001:db8') || l.startsWith('::ffff:');
}

function normDomain(d) {
  d = d.toLowerCase().replace(/\.$/, '').replace(/:\d+$/, '');
  if (d.startsWith('*.')) d = d.slice(2);
  if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(d)) return { drop: 'malformed domain' };
  const tld = d.split('.').pop();
  if (FILE_EXT_TLDS.has(tld)) return { reclassify: 'filename' };
  if (PLACEHOLDER_DOMAINS.test(d)) return { drop: 'placeholder domain' };
  return { value_norm: d };
}

/** Infer a type from the value when the model's label is missing or clearly wrong. */
export function inferType(v) {
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
  if (/^[a-f0-9]+$/i.test(v) && HASH_LEN[v.length]) return HASH_LEN[v.length];
  if (/^https?:\/\//i.test(v)) return 'url';
  const ipNoPort = v.replace(/:\d+$/, '').replace(/\/\d{1,2}$/, '');
  if (isIP(ipNoPort) === 4) return 'ipv4';
  if (isIP(v.replace(/^\[|\](:\d+)?$/g, '')) === 6) return 'ipv6';
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return 'email';
  if (/^(HK(LM|CU|CR|U|CC)|HKEY_)/i.test(v)) return 'registry';
  if (/^([a-z]:\\|\\\\|\/)/i.test(v)) return 'filepath';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return null;
}

/** Normalize one IoC. */
export function normalizeIoc(type, rawValue) {
  const v = refang(rawValue);
  if (!v) return { drop: 'empty' };
  let t = type;
  // trust the value's shape over the label for the unambiguous types
  const inferred = inferType(v);
  if (inferred && ['md5', 'sha1', 'sha256', 'ipv4', 'ipv6', 'url', 'cve', 'email'].includes(inferred)) t = inferred;

  switch (t) {
    case 'ipv4': {
      const ip = v.replace(/:\d+$/, '');
      const [addr, cidr] = ip.split('/');
      if (isIP(addr) !== 4) return { drop: 'malformed ipv4' };
      const canon = addr.split('.').map(Number).join('.');
      if (V4_PLACEHOLDERS.has(canon)) return { drop: 'placeholder ip' };
      if (isBogonV4(canon)) return { drop: 'private/reserved ip' };
      if (cidr != null && !(Number(cidr) >= 8 && Number(cidr) <= 32)) return { drop: 'bad cidr' };
      return { type: 'ipv4', value_norm: cidr != null && cidr !== '32' ? `${canon}/${Number(cidr)}` : canon };
    }
    case 'ipv6': {
      const ip = v.replace(/^\[/, '').replace(/\](:\d+)?$/, '').toLowerCase();
      if (isIP(ip) !== 6) return { drop: 'malformed ipv6' };
      if (isBogonV6(ip)) return { drop: 'private/reserved ip' };
      return { type: 'ipv6', value_norm: ip };
    }
    case 'domain': {
      const r = normDomain(v.replace(/^https?:\/\//i, '').split(/[/?#]/)[0]);
      if (r.reclassify) return normalizeIoc('filename', v);
      return r.drop ? r : { type: 'domain', value_norm: r.value_norm };
    }
    case 'url': {
      let u;
      try { u = new URL(/^[a-z]+:\/\//i.test(v) ? v : `http://${v}`); } catch { return { drop: 'malformed url' }; }
      if (!/^(https?|ftp):$/.test(u.protocol)) return { drop: 'unsupported scheme' };
      const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
      if (isIP(host) === 4 && (isBogonV4(host) || V4_PLACEHOLDERS.has(host))) return { drop: 'private/placeholder host' };
      if (!isIP(host) && PLACEHOLDER_DOMAINS.test(host)) return { drop: 'placeholder domain' };
      u.hash = '';
      return { type: 'url', value_norm: u.toString() };
    }
    case 'md5': case 'sha1': case 'sha256': case 'cert_sha1': {
      const h = v.toLowerCase().replace(/^0x/, '');
      if (!/^[a-f0-9]+$/.test(h)) return { drop: 'non-hex hash' };
      const want = t === 'cert_sha1' ? 40 : { md5: 32, sha1: 40, sha256: 64 }[t];
      if (h.length !== want) {
        if (t !== 'cert_sha1' && HASH_LEN[h.length]) return normalizeIoc(HASH_LEN[h.length], h);
        return { drop: `hash length ${h.length}` };
      }
      if (/^(.)\1+$/.test(h)) return { drop: 'placeholder hash' };
      if (EMPTY_HASHES.has(h)) return { drop: 'empty-file hash' };
      return { type: t, value_norm: h };
    }
    case 'email': {
      const [local, domain] = v.split('@');
      if (!local || !domain) return { drop: 'malformed email' };
      const d = normDomain(domain);
      if (d.drop || d.reclassify) return { drop: d.drop || 'malformed email' };
      return { type: 'email', value_norm: `${local}@${d.value_norm}` };
    }
    case 'cve': {
      const m = v.toUpperCase().match(/^CVE-\d{4}-\d{4,}$/);
      return m ? { type: 'cve', value_norm: m[0] } : { drop: 'malformed cve' };
    }
    case 'filename': case 'filepath': case 'registry': {
      // Windows paths/registry are case-insensitive → lowercase; POSIX paths keep case.
      const win = t === 'registry' || /\\/.test(v) || (t === 'filename' && /\.(exe|dll|ps1|bat|cmd|vbs|lnk|hta|msi|sys)$/i.test(v));
      return { type: t, value_norm: win ? v.toLowerCase() : v };
    }
    case 'ja3': case 'ja4': case 'mutex': case 'useragent': case 'yara_name':
      return { type: t, value_norm: v.replace(/\s+/g, ' ') };
    default:
      return { drop: `unknown type ${t}` };
  }
}
