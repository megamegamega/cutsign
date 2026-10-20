// v1 seam — Splunk backend: CIM data models, tstats, inline lookups.
//   renderBehavior(sigma) · renderSweep(iocSet, dataModel) · renderPreflight(logsource)
// Sigma → SPL compile needs pySigma (Python); decided at v1 (Python function or Actions job).
const ni = (m) => () => { throw new Error(`splunk.${m}: not implemented (v1)`); };
export const renderBehavior = ni('renderBehavior');
export const renderSweep = ni('renderSweep');
export const renderPreflight = ni('renderPreflight');
