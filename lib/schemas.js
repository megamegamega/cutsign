// zod schemas for every LLM output. The same schema is sent to the API as a structured-output
// format AND re-validated locally; a mismatch triggers one retry with the validation error appended.

import { z } from 'zod';

export const PATTERN_KINDS = ['shell_from_server_process', 'discovery_burst', 'download_cradle', 'persistence_artifact',
  'credential_access', 'lateral_auth', 'defense_evasion', 'exfil_channel', 'other'];
export const EVIDENCE_KINDS = ['log_line', 'command_line', 'http_request', 'process_tree', 'file_path', 'registry', 'other'];
export const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'filename', 'filepath',
  'registry', 'mutex', 'ja3', 'ja4', 'useragent', 'cve', 'yara_name', 'cert_sha1'];
export const TIERS = ['A', 'B', 'C', 'D', 'E', 'F'];

const nstr = z.string().nullable();

export const ExtractionSchema = z.object({
  story: z.object({
    title: z.string().describe('Short headline, ≤ 90 chars; claim outcomes only as strongly as the sources confirm'),
    summary: z.string().describe('2–4 sentences: what happened, who, how, what to hunt for'),
    threat_actor: nstr,
    malware_family: nstr,
    cves: z.array(z.string()),
    attack_techniques: z.array(z.string()).describe('ATT&CK Enterprise IDs, e.g. T1190, T1059.004'),
    sector_relevance: z.array(z.string()),
    priority: z.number().int().min(1).max(3),
    priority_reason: z.string(),
    earliest_published: nstr.describe('YYYY-MM-DD of the earliest source publication date, if stated'),
  }),
  behaviors: z.array(z.object({
    attack_technique: z.string(),
    pattern_kind: z.enum(PATTERN_KINDS),
    parent: nstr,
    children: z.array(z.string()),
    log_source: z.string(),
    time_window: nstr,
    vendor_stated: z.boolean(),
    source_quote_ref: z.string(),
  })),
  detection_guidance: z.array(z.object({
    description: z.string(),
    log_source: nstr,
    attack_technique: nstr,
    url: nstr,
    verbatim_query: nstr,
    publisher_tier: z.enum(TIERS),
  })),
  evidence_samples: z.array(z.object({
    kind: z.enum(EVIDENCE_KINDS),
    raw: z.string().max(2048),
    log_source_guess: nstr,
    attack_technique: nstr,
    source_quote_ref: z.string(),
  })),
  iocs: z.array(z.object({
    type: z.enum(IOC_TYPES),
    value: z.string(),
    role: z.string(),
    confidence: z.enum(['vendor_stated', 'inferred']),
    context: z.string(),
  })),
  more_sources: z.array(z.string()).describe('URLs the sources point to for IoCs/details not printed inline'),
  exposure: z.object({
    affected: z.array(z.string()).describe('Product/component + affected versions, as stated'),
    only_if: z.array(z.string()).describe('Preconditions for exposure: optional module installed, non-default config, interface exposed, auth required…'),
    not_affected_if: z.array(z.string()).describe('Quick exclusions a defender can check'),
    fixed_in: nstr,
  }),
});
