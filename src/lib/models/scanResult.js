/**
 * @typedef {Object} Finding
 * @property {string} name
 * @property {string} severity
 * @property {string} description
 * @property {Object} evidence
 * @property {string} [confidence]
 * @property {string} [remediation]
 * @property {Object} [remediation_snippets]
 * @property {string} [owasp]
 * @property {Object} [compliance]
 * @property {string} [module]
 * @property {string} [impact]
 * @property {number} [cvss]
 * @property {string} [domain]
 */

/**
 * @typedef {Object} TargetSurface
 * @property {string} [waf_server]
 * @property {string} [waf_status]
 * @property {string} [waf_pill]
 * @property {string} [frontend_stack]
 * @property {string} [frontend_subtext]
 * @property {string} [frontend_pill]
 * @property {string} [api_surface]
 * @property {string} [api_subtext]
 * @property {string} [api_pill]
 * @property {string} [js_health]
 * @property {string} [js_subtext]
 * @property {string} [js_pill]
 * @property {string} [performance]
 */

/**
 * @typedef {Object} ReportData
 * @property {string} target_url
 * @property {string} scan_start
 * @property {number} score
 * @property {Object} severity_counts
 * @property {Finding[]} findings
 * @property {TargetSurface} [target_surface]
 * @property {string} [executive_summary]
 * @property {string[]} [technologies]
 * @property {string} [detected_framework]
 * @property {string} [server]
 * @property {string} [latency]
 * @property {Object} [metadata]
 */

/**
 * Helper to ensure the data matches the expected ReportData shape conceptually.
 * 
 * @param {Object} rawData 
 * @returns {ReportData}
 */
export const normalizeScanResult = (rawData) => {
  return rawData; // Pass-through for now, preserves exact backend field names
};
