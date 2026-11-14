// Response actions for the hand-written cards, written by hand (lib/actions.js has the model for AI
// cards and the rules that turn either into classes and gates).
//
// Each entry restates a card's "Do now" list: `steps` is the list as the card prints it
// (test/actions.test.js fails when the two drift apart), `items` says what kind of action each step
// is, and `indicators` are the blockable indicators the card's sources published, with the role
// their context supports. Where the context does not say what an address is, the role is `unknown`
// and the block is a recommendation, not an automatic one. Values are public OSINT, raw.

const act = (step, kind, o = {}) => ({ step, kind, when: 'always', asset: 'any', reversible: true, pattern: null, ...o });
const ind = (type, role, ...values) => values.map((value) => ({ type, value, role }));

function card(steps, items, indicators = []) {
  const find = (v) => { const i = indicators.find((x) => x.value === v); if (!i) throw new Error(`hand action names an indicator the card does not list: ${v}`); return i; };
  return {
    v: 1, steps,
    items: items.map((a) => {
      if (!steps[a.step - 1]) throw new Error(`hand action names step ${a.step} of ${steps.length}`);
      return { ...a, text: steps[a.step - 1], targets: (a.targets || []).map(find) };
    }),
    indicators,
  };
}

const TRIPWIRE = 'Order matters: isolate, remove the daemon and hooks, and only then revoke. The token monitor may react to revocation.';

export const HAND_ACTIONS = {
  'beyondtrust-rs-2026': card([
    'Patch BT26-05 (upgrade to ≥24.3.1 first where needed); restrict appliance exposure',
    'Hunt back to late August: unknown .php POSTs and WebSocket paths at the reverse proxy; user_changed events raising Jump Item/team roles; file-transfer sessions by accounts whose roles changed',
    'Host: SUID binaries (/usr/bin/dbus-authd), post_boot.d additions, sudoers-template edits, haproxy.conf ACL changes',
    'Treat syslog-forwarding gaps bounded by a single session as tampering evidence',
    'Confirmed hit → rotate the vault\'s entire contents and every injected credential',
  ], [
    act(1, 'patch', { asset: 'appliance', reversible: false, pattern: 'BT26-05' }),
    act(1, 'restrict_exposure', { asset: 'appliance' }),
    act(2, 'hunt', { asset: 'appliance' }),
    act(3, 'hunt', { asset: 'appliance', pattern: '/usr/bin/dbus-authd' }),
    act(4, 'hunt', { asset: 'appliance' }),
    act(5, 'rotate_secret', { when: 'on_hit', asset: 'identity', reversible: false }),
  ], [
    ...ind('sha256', 'malware_file', '1f19b9a27d79c11bda00a1e8faf74a7fdd683d38ccef1b60df2fd0307e3aa462', 'dc14e215269a93fdbc4c1a80b984c23faf7af0911c6dbb85309796a6f2ae95fb'),
  ]),

  'litellm-2026': card([
    'Inventory: anywhere litellm resolved on Oct 21 — lockfiles, CI caches, image layers, pip list fleet-wide',
    'Sweep hosts for cook.pth / cook.py / sitecustomize.py in site-packages and /tmp/remote_code_loader.lock',
    'Hit = isolate, rebuild from clean base, rotate every credential the host could reach',
    'Check egress logs for litellm[.]dev and the GitHub dead drop (letters9813)',
    'CloudTrail: the STS → Bedrock pattern from the listed IPs since Oct 21',
  ], [
    act(1, 'hunt'),
    act(2, 'hunt', { pattern: '/tmp/remote_code_loader.lock' }),
    act(3, 'isolate_host', { when: 'on_hit' }),
    act(3, 'rebuild', { when: 'on_hit', reversible: false }),
    act(3, 'rotate_secret', { when: 'on_hit', asset: 'identity', reversible: false }),
    act(4, 'hunt', { asset: 'network', targets: ['litellm.dev', 'http://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt'] }),
    act(5, 'hunt', { asset: 'cloud', targets: ['165.227.201.8', '168.100.8.57'] }),
  ], [
    ...ind('ipv4', 'attack_source', '165.227.201.8', '168.100.8.57'),
    ...ind('domain', 'exfil', 'litellm.dev'),
    ...ind('url', 'exfil', 'http://litellm.dev/healthcheck'),
    ...ind('url', 'shared_service', 'http://github.com/letters9813', 'http://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt'),
  ]),

  'm365-token-spray-2026': card([
    'Verify CA truly covers all users / apps / client types — enumerate exclusions, don\'t assume',
    'Run the four hunts across Jul 14 → now: replayed sign-ins, DESKTOP-[hex8] device registrations, MFA wipe→re-register inside minutes, short/punctuation-named inbox rules',
    'Restrict device-code flow where not business-required',
    'Triage by credential validity, not spray volume: an AADSTS53003 block still means the password/session was good — reset it',
  ], [
    act(1, 'hunt', { asset: 'saas' }),
    act(2, 'hunt', { asset: 'saas' }),
    act(3, 'change_config', { asset: 'saas', pattern: 'device-code flow' }),
    act(4, 'revoke_session', { when: 'on_hit', asset: 'identity', pattern: 'AADSTS53003' }),
  ], [
    ...ind('ipv4', 'attack_source', '167.148.41.96', '192.159.99.172', '45.83.31.44', '124.198.132.33', '193.26.115.210', '193.26.115.72', '193.26.115.21', '193.26.115.16', '193.26.115.199', '193.26.115.221'),
    ...ind('ipv4', 'actor_infra', '185.238.2.195'),
    ...ind('ipv6', 'actor_infra', '2400:8d60:2::1:841d:5dd'),
  ]),

  'connectwise-m365-2026': card([
    'Query service-principal sign-ins for all seven appIds back to Oct 1 (review window Oct 13 → now at minimum)',
    'Entra audit: credential additions, new owners, app-role assignments, consent grants, privileged role changes since Oct 13 — on all apps, not just ConnectWise ones',
    'Pull user agents on any SP sign-ins found; Python/curl UAs from non-Azure IPs are the campaign shape',
    'Verify tenant presence by Graph lookup per appId; confirm Conditional Access evaluates multi-tenant SPs',
    'Review federated credentials on locally registered applications (guide §4) — issuer/subject trusts are persistence that survives secret rotation',
    'Former customers: run the same checks — stale consents were swept too',
    'Never a customer: filter the Service principal sign-ins tab for the all-zeros ID and the seven appIds; if present, apply Microsoft\'s documented block (create the service principal for that appId, then disable it) — defense in depth now that ConnectWise has disabled the identities, and it brings the app under Conditional Access',
  ], [
    act(1, 'hunt', { asset: 'saas' }),
    act(2, 'hunt', { asset: 'saas' }),
    act(3, 'hunt', { asset: 'saas' }),
    act(4, 'hunt', { asset: 'saas' }),
    act(5, 'hunt', { asset: 'saas' }),
    act(6, 'hunt', { asset: 'saas' }),
    act(7, 'hunt', { asset: 'saas' }),
    act(7, 'disable_account', { when: 'on_hit', asset: 'saas', note: 'Microsoft\'s documented block: create the service principal for the appId, then disable it.' }),
  ], [
    // the card's password-spray range; the reporting calls them VPN addresses, so others may share them
    ...ind('ipv4', 'shared_service', '187.15.89.186', '187.15.90.217', '187.15.88.186'),
    ...ind('ipv4', 'attack_source', '144.172.94.243', '144.172.64.60', '144.172.64.128'),
    ...ind('ipv4', 'unknown', '144.172.64.99'), // "likely unrelated to app sign-ins"
  ]),

  'php2shell-2026': card([
    'Patch internet-facing PHP first; then internal; verify EOL hosts got distro backports or are flagged for migration',
    'Run the hunt list against web-server logs and EDR for the window since Oct 20 (details leaked pre-patch)',
    'Inventory where session upload-progress is enabled and where mod_php still runs',
    'Container images bundling PHP need rebuilds, same as any runtime flaw',
    'OT/ICS: check Siemens, Schneider Electric, ABB, Johnson Controls, Belden, HMS and Wibu-Systems advisories for PHP-based products; PHP is often embedded and not visible to a version scan',
  ], [
    act(1, 'patch', { asset: 'server', reversible: false }),
    act(2, 'hunt', { asset: 'server' }),
    act(3, 'hunt', { asset: 'server', pattern: 'session upload-progress' }),
    act(4, 'patch', { asset: 'server', reversible: false }),
    act(5, 'hunt', { asset: 'appliance' }),
  ], [
    ...ind('ipv4', 'attack_source', '45.198.224.169', '217.60.242.76', '85.11.167.243'),
    ...ind('ipv4', 'payload_host', '206.188.197.105', '92.118.112.100'),
    ...ind('ipv4', 'c2', '134.199.154.64'),
    ...ind('domain', 'c2', 'thunder.godofthunder.st'),
    // published in a vendor's list without a statement of what each address did
    ...ind('ipv4', 'unknown', '103.147.220.17', '193.47.62.24', '107.189.14.87', '45.134.225.16', '152.233.51.69', '185.161.210.29', '185.196.220.132', '181.215.186.252', '87.121.84.174'),
    ...ind('ipv6', 'unknown', '2409:40d2:204e:4be:2a1f:f9c9:a055:e00b'),
  ]),

  'gitlab-onigmo-2026': card([
    'Inventory self-managed GitLab — including "someone\'s team runner box" instances outside central management',
    'Upgrade to the fixed version for the line; do not count Oct 12 patches as done',
    'Run GitLab\'s two Sigma rules over application logs back to Oct 20',
    'Internet-facing instances that cannot patch today: restrict unauthenticated access at the edge until they can',
  ], [
    act(1, 'hunt', { asset: 'server' }),
    act(2, 'patch', { asset: 'server', reversible: false }),
    act(3, 'hunt', { asset: 'server' }),
    act(4, 'restrict_exposure', { when: 'if_exposed', asset: 'server' }),
  ]),

  'emudhra-distrust-2026': card([
    'Inventory certificates chaining to emSign/eMudhra roots — servers first, then API clients, CI/CD runners, proxies and appliances',
    'Replace affected chains with another trusted CA before the Chrome removal — eMudhra replaces affected certs free via partners, but with their TLS business ending, migrate to a different CA rather than re-issuing under a sunsetting root',
    'Update independent trust stores: Go toolchains, ca-certificates bundles, NSS, vendor appliances',
    'Test critical clients against the disclosure site\'s test hosts',
    'Pre-brief the help desk: Chrome cert errors starting Oct 27 have a known cause — and never "fix" them by disabling certificate verification',
  ], [
    act(1, 'hunt'),
    act(2, 'rotate_secret', { when: 'if_exposed', reversible: false }),
    act(3, 'patch', { reversible: false }),
    act(4, 'hunt'),
    act(5, 'other'),
  ]),

  'nodejs-oct-2026': card([
    'Inventory every Node runtime: hosts, container images, SEA binaries — each image bundles its own copy and needs a rebuild, not just a host patch',
    'Upgrade to 26.12.1 / 24.22.1 / 22.23.4; rebuild and redeploy images',
    'Quick per-host check: npx is-my-node-vulnerable (official Node.js project tool)',
    'Flag anything on EOL 20.x or earlier for migration — it stays vulnerable forever',
    'Where patching lags: pin outbound Accept-Encoding away from br and audit routes accepting Brotli bodies',
  ], [
    act(1, 'hunt', { asset: 'server' }),
    act(2, 'patch', { asset: 'server', reversible: false }),
    act(3, 'hunt', { asset: 'server', pattern: 'npx is-my-node-vulnerable' }),
    act(4, 'other', { asset: 'server' }),
    act(5, 'change_config', { when: 'if_exposed', asset: 'server', pattern: 'Accept-Encoding' }),
    act(5, 'hunt', { when: 'if_exposed', asset: 'server' }),
  ]),

  'agentic-intrusion-hunts-2026': card([
    'Schedule A1, A2 and A4 against cloud control-plane and identity logs — these three catch the loop regardless of framework',
    'Seed canary credentials this week (runbook below) and wire A7 as an incident-severity alert',
    'Stand up one fake win beside them — a decoy admin API that accepts any credential and returns success; the agent records the win and moves on, and you get the source, the credential it tried and the timing',
    'Run A5 and A6 over the last 30 days as a one-time hunt; keep the ARTEX name-based layer running beside them',
    'Inventory long-lived credentials the frameworks feed on: static IAM keys, Kudu publishing credentials, SAS tokens, SP secrets — rotate to short-lived where possible',
  ], [
    act(1, 'hunt', { asset: 'cloud' }),
    act(2, 'other', { asset: 'identity' }),
    act(3, 'other', { asset: 'cloud' }),
    act(4, 'hunt', { asset: 'cloud' }),
    act(5, 'hunt', { asset: 'identity' }),
    act(5, 'rotate_secret', { asset: 'identity', reversible: false }),
  ], [
    ...ind('ipv4', 'c2', '85.11.167.52', '199.19.95.68', '199.19.95.67', '199.19.95.66'),
    ...ind('ipv4', 'actor_infra', '31.77.229.35', '178.16.54.129', '85.11.168.45', '91.92.240.238', '104.168.112.237', '204.44.66.81', '198.44.123.66', '192.236.172.197', '103.122.245.194'),
    ...ind('ipv4', 'attack_source', '199.19.77.84'),
    ...ind('ipv4', 'shared_service', '199.19.77.18'), // a Tor exit: "may carry unrelated traffic"
    // one value two tables of the same report disagree on, and two the source calls "potentially associated"
    ...ind('ipv4', 'unknown', '178.15.54.129', '157.22.126.128', '65.87.223.26'),
    ...ind('domain', 'shared_service', 'webhook.site'),
  ]),

  'jest-canvas-mock-2026': card([
    'Scope: search every lockfile and its git history since May 18 for the three versions, @antv/setup and commit 1916faa3…; then CI logs and registry-proxy caches. Purge cached tarballs',
    'Sweep developer laptops and self-hosted runners for the persistence files — they survive a rollback, and log retention may not reach back to May',
    'On a hit, order matters: isolate, remove the daemon and hooks first, then revoke. Snyk warns the token monitor may react to revocation, and the payload carries the string "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"',
    'Rotate everything the machine could read: npm and GitHub tokens, cloud keys, SSH keys, kubeconfig, Vault, database strings, Slack',
    'Audit GitHub and npm: Dune-named public repos, the injected branch and workflow, unexpected publishes from your accounts after May 19',
    'Block t.m-kosche[.]com at DNS and proxy; pin 2.5.8; use npm ci in CI',
  ], [
    act(1, 'hunt', { pattern: '@antv/setup' }),
    act(1, 'remove_artifact', { asset: 'server', reversible: false, pattern: 'Purge cached tarballs' }),
    act(2, 'hunt', { asset: 'workstation' }),
    act(3, 'isolate_host', { when: 'on_hit', asset: 'workstation', note: TRIPWIRE }),
    act(3, 'remove_artifact', { when: 'on_hit', asset: 'workstation', reversible: false, note: TRIPWIRE }),
    act(3, 'rotate_secret', { when: 'on_hit', asset: 'identity', reversible: false, note: TRIPWIRE }),
    act(4, 'rotate_secret', { when: 'on_hit', asset: 'identity', reversible: false, note: TRIPWIRE }),
    act(5, 'hunt', { asset: 'saas' }),
    act(6, 'block_indicator', { asset: 'network', targets: ['t.m-kosche.com'] }),
    act(6, 'change_config', { asset: 'server', pattern: 'npm ci' }),
  ], [
    ...ind('domain', 'exfil', 't.m-kosche.com'),
    ...ind('ipv4', 'exfil', '185.95.159.32'),
    // the alternative exfil route one source reports is a messenger's file service
    ...ind('domain', 'shared_service', 'filev2.getsession.org'),
  ]),
};
