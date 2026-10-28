// zod schemas for every LLM output. The same schema is sent to the API as a structured-output
// format AND re-validated locally; a mismatch triggers one retry with the validation error appended.

import { z } from 'zod';
import { LOG_SOURCE_KEYS } from './logsources.js';

export const PATTERN_KINDS = ['shell_from_server_process', 'discovery_burst', 'download_cradle', 'persistence_artifact',
  'credential_access', 'lateral_auth', 'defense_evasion', 'exfil_channel', 'other'];
export const EVIDENCE_KINDS = ['log_line', 'command_line', 'http_request', 'process_tree', 'file_path', 'registry', 'other'];
export const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'filename', 'filepath',
  'registry', 'mutex', 'ja3', 'ja4', 'useragent', 'cve', 'yara_name', 'cert_sha1'];
export const TIERS = ['A', 'B', 'C', 'D', 'E', 'F'];

const nstr = z.string().nullable();

// Hunt-query proposals (lib/queries.js). The model proposes the SHAPE of a hunt — stages over the
// closed log-source vocabulary, a join for correlations, one SPL and one ES|QL rendering over
// `index=<key>` / `FROM <key>` placeholders. id, tier, model and cost are added by code, never by
// the model. No length bounds: they inflate the grammar the API compiles (see lib/llm.js).
export const PROPOSAL_SHAPES = ['single_source', 'correlation', 'sequence'];
export const PROPOSAL_CONFIDENCE = ['stated', 'derived', 'speculative'];
export const ProposalSchema = z.object({
  proposed_queries: z.array(z.object({
    shape: z.enum(PROPOSAL_SHAPES),
    name: z.string().describe('Short snake_case slug, e.g. sp_token_then_graph_success'),
    hypothesis: z.string().describe('One sentence: what adversary activity this would surface'),
    stages: z.array(z.object({
      log_source_key: z.enum(LOG_SOURCE_KEYS).describe('Exactly one vocabulary key per stage; never other'),
      predicate: z.string().describe('Human-readable condition for this stage'),
      fields: z.array(z.string()).describe('Generic field names the stage reads; note Splunk-native vs ECS where they differ'),
    })),
    join: z.object({ on: z.string(), window: z.string() }).nullable().describe('null for single_source; the generic join field and time window otherwise'),
    splunk: z.string().describe('SPL over index=<key> placeholders and generic field names; literals only from the story'),
    elastic: z.string().describe('ES|QL over FROM <key> placeholders and ECS field names; literals only from the story'),
    params: z.array(z.object({ name: z.string(), value: z.string() })).describe('Every story-specific literal the queries use, so a consumer can re-parameterise'),
    noise_hint: z.string().describe('What benign activity would also match and how to exclude it; required'),
    from: z.array(z.string()).describe('Citations into the story record: behaviors[i], detection_guidance[j], iocs[k], or inference'),
    confidence: z.enum(PROPOSAL_CONFIDENCE),
  })),
});

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
