// Canonical log-source keys for the free-text `log_source` the extractor writes ("EDR process
// events / Sysmon EID 1 / Windows 4688"). Derived at emission time so every stored story gets
// keys retroactively, and a consumer (a hunt runner) can map a small closed vocabulary to its own
// data instead of 300+ phrasings. Multi-label: "proxy / DNS" → ['proxy', 'dns']. Generic by design —
// keys name telemetry families, never anyone's index or data-stream names.

export const LOG_SOURCE_KEYS = [
  'endpoint_process',   // EDR process events, Sysmon EID 1, Windows 4688, auditd execve, PowerShell 4104
  'endpoint_file',      // EDR file events, Sysmon EID 11, file integrity monitoring, web root / filesystem
  'endpoint_memory',    // image loads (Sysmon EID 7), injection, memory telemetry
  'windows_eventlog',   // Security/System channels: 4624, 4698, 4720, 4732, 4662, 7045, 1102, 104
  'shell_history',      // bash/zsh history, .bashrc, Run-dialog history
  'auth_log',           // SSH / sudo / PAM auth logs on hosts
  'appliance_logs',     // network/security appliance syslog + vendor logs (BeyondTrust, Forti*, NetScaler, GlobalProtect, ESXi/vCenter, VCO)
  'web_access',         // web server / reverse proxy / WAF access + error logs
  'network',            // firewall, NetFlow, IDS/IPS, NGFW, packet capture
  'proxy',              // forward proxy / egress web traffic
  'dns',
  'entra_signin',       // Entra ID (Azure AD) interactive + service-principal sign-in logs
  'entra_audit',        // Entra ID audit log, Entra ID Protection, device registration
  'm365_ual',           // M365 Unified Audit Log, Exchange trace, SharePoint/OneDrive activity, Defender XDR/MDCA
  'identity_idp',       // Okta system log, generic IdP / MFA / OAuth consent telemetry
  'email_gateway',
  'cloud_audit',        // AWS CloudTrail, GCP audit, cloud storage/database auth logs
  'code_platform',      // GitHub/GitLab audit logs, Actions/CI runs, repository history
  'app_logs',           // application-specific server logs (GitLab, Veeam, MSSQL, Langflow, search services, database audit)
  'mobile',             // Android/iOS device telemetry, MDM inventory
  'forensics',          // memory forensics, disk timeline, YARA scans, host forensic review
  'other',
];

// order matters only for readability; every rule that matches contributes its key
const RULES = [
  ['entra_signin', /\b(sign-?in|signin|spn ?sign|AADServicePrincipalSignIn|EntraIdSpnSignInEvents|SigninLogs|Entra ID Protection)\b/i],
  ['entra_audit', /\b(entra( id)? (audit|devices)|azure ad audit|device registration|AuditLogs)\b/i],
  ['m365_ual', /\b(unified audit|UAL|M365|Microsoft 365|Office 365|exchange (message )?trace|sharepoint|onedrive|defender (xdr|for cloud apps)|MDCA|OAuthAppInfo|GraphAPIAuditEvents|MicrosoftGraphActivityLogs|graph activity)\b/i],
  ['identity_idp', /\b(okta|identity provider|idp|mfa (provider|registration)|oauth consent|consent grant|token grant|platform authentication)\b/i],
  ['email_gateway', /\b(e-?mail gateway|mail flow|mail logs?|message inspection)\b/i],
  ['cloud_audit', /\b(cloudtrail|gcp|cloud (audit|admin|storage)|cloud and database auth)/i],
  ['code_platform', /\b(github|gitlab audit|repository (commit )?history|git activity|workflow run|CI or orchestration|commit history)\b/i],
  ['app_logs', /\b(gitlab application|application(\/web server)? (access )?logs?|veeam|mssql|database audit|search service|langflow|ahsay|nextcloud|wordpress (options|users|audit|plugin)|wp-cron|crontab|systemd unit|cron logs?|nginx (running )?config|apache mod_md|torrc)\b/i],
  ['appliance_logs', /\b(appliance|beyondtrust|fortigate|fortimanager|fortios|fortisiem|netscaler|globalprotect|esxi|vcenter|vco\b|hostd|session reports?|messages log|haproxy|ns\/config|NGFW threat|IPS\/virtual patch|edge device|NAS logs)/i],
  ['web_access', /\b(web (server|access|application)|access\/error log|access log|reverse[- ]proxy|waf|http-access|nginx|apache|iis|api gateway)\b/i],
  ['network', /\b(firewall|network (flow|logs?|traffic|telemetry|events?|egress)|netflow|ids\b|ips\b|snort|intrusion|packet|flow logs?|egress|NAT rule|wireless|http\/2 sessions|tcp\s*\d+|\d+\/tcp)\b/i],
  ['proxy', /\bproxy\b/i],
  ['dns', /\bdns\b/i],
  ['windows_eventlog', /\b(windows (security|system|file creation|scheduled task)|4624|4662|4698|4720|4732|7036|7040|7045|1102|security 1102|system 104|scheduled task creation)\b/i],
  ['endpoint_process', /\b(process (events?|creation|execution|command lines?|telemetry|listing|tree|and (file|network|software|install))|sysmon eid 1\b|4688|edr process|edr\/defender|edr behavioral|process\/(file|network|api|install) events?|auditd|cortex xdr|powershell|4104|process and file|interpreter|software inventory|endpoint telemetry|host process|edr\b(?! (file|memory|image|network)))/i],
  ['endpoint_file', /\b(file (integrity|events?|creation|access|system|metadata|scanning)|filesystem|file-?system|sysmon eid 11|web root|site-packages|startup folder|\.ssh|wp-config|config file integrity|plugin directory|host file|daemon integrity|FIM)\b/i],
  ['endpoint_memory', /\b(image[- ]load|sysmon eid 7|memory(\/| )?(injection|events|process|telemetry)|injection|memory\/process)\b/i],
  ['shell_history', /\b(shell|bash|zsh)[\/ ]?history|\.bashrc|run dialog/i],
  ['auth_log', /\b(auth(entication)? logs?|auth\.log|sshd?\b|sudo|logon|failed auth|lockouts?|pam)\b/i],
  ['mobile', /\b(android|ios device|mobile|mdm|sms provider)\b/i],
  ['forensics', /\b(forensic|memory forensics|timeline|yara|file\/memory scan|crash(log| telemetry)|config revisions|live check|host integrity)\b/i],
];

/** Free text → ordered, de-duplicated canonical keys; ['other'] when nothing matches. */
export function logSourceKeys(text) {
  const t = String(text || '').trim();
  if (!t) return ['other'];
  const keys = [];
  for (const [key, re] of RULES) if (re.test(t) && !keys.includes(key)) keys.push(key);
  // "appliance syslog" alone must not also read as a host auth log; appliance wins the generic 'syslog'
  if (!keys.length && /\bsyslog\b/i.test(t)) keys.push('appliance_logs');
  return keys.length ? keys : ['other'];
}
