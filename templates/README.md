# templates/ (v1)

Parameterized Sigma templates, one file per recurring behavior shape. Each file declares its
`pattern_kind`, a parameter schema, default false-positive notes, and (later) an Atomic Red Team
mapping. Seed set: `shell_from_server_process`, `discovery_burst`, `download_cradle`.

Adding one is meant to be a five-minute task: every pattern hand-rolled in chat becomes a template.
Empty in v0 — the behaviors extracted in v0 are what these will be built from.
