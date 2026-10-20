# logsources/ (v1)

One YAML per appliance or product that Sigma has no built-in logsource for (NetScaler syslog,
Fortinet, Ivanti, Palo Alto, M365 UAL, Okta system log …): the Sigma `logsource` block, Splunk
sourcetype(s) + CIM mapping, ECS mapping, and a sample event for replay. A story needing a missing
one gets `logsource: missing` and a Discord line. Adding one should take ten minutes.
