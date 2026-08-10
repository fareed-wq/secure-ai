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
 * @property {Object|string|null} [evidence] - Exact backend structure, do NOT mutate.
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
 * @property {string} [url] - Alias for target_url.
 * @property {Object} _raw - The unaltered raw backend response.
 */

/**
 * Normalizes the raw backend scan result into a stable frontend model without
 * losing or mutating any technical data.
 * 
 * @param {Object} rawData - The raw JSON response from the backend.
 * @returns {ReportData} The normalized report data with safe aliases and _raw preserved.
 */
export const normalizeScanResult = (rawData) => {
  if (!rawData) return rawData;

  const normalized = {
    ...rawData,
    _raw: rawData
  };

  // Safely establish url / target_url aliases if one is missing.
  if (rawData.target_url && !rawData.url) {
    normalized.url = rawData.target_url;
  } else if (rawData.url && !rawData.target_url) {
    normalized.target_url = rawData.url;
  }

  return normalized;
};
