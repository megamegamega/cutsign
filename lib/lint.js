// v1 seam — deterministic query linter (SPL command denylist/allowlist, no literal index name except
// `index=*` with a comment, no hostnames/usernames/emails). Runs on every rendered query, no exceptions.
export function lintSpl() { throw new Error('lint: not implemented (v1)'); }
