// Stub by design. Intended mapping: pySigma Elasticsearch backend (ES|QL); ECS fields
// (process.parent.name, process.command_line, dns.question.name); sweeps as `terms` queries on ECS
// fields; preflights as `_count` per data stream.
const ni = (m) => () => { throw new Error(`elastic.${m}: not implemented`); };
export const renderBehavior = ni('renderBehavior');
export const renderSweep = ni('renderSweep');
export const renderPreflight = ni('renderPreflight');
