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
 * @property {string} [cvss]
 * @property {number} [cvss_score]
 * @property {string} [cvss_severity]
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

  // 1. METADATA CONSOLIDATION
  normalized.metadata = {
    ...(rawData.metadata || {})
  };

  normalized.metadata.ip_address = normalized.metadata.ip_address || rawData.ip_address;
  normalized.metadata.location_or_cdn = normalized.metadata.location_or_cdn || rawData.location_or_cdn;
  normalized.metadata.server_header = normalized.metadata.server_header || rawData.server_header;
  normalized.metadata.ssl_issuer = normalized.metadata.ssl_issuer || rawData.ssl_issuer;
  normalized.metadata.ssl_days_left = normalized.metadata.ssl_days_left || rawData.ssl_days_left;

  // 2, 3 & 4. FINDING CATEGORY, MODULE DEFAULTS & OWASP NORMALIZATION
  if (Array.isArray(rawData.findings)) {
    normalized.findings = rawData.findings.map(finding => {
      let owaspDisplay = finding.owasp;
      if (owaspDisplay && (owaspDisplay === "A00: Informational" || owaspDisplay === "A00" || owaspDisplay.startsWith("A00:"))) {
        owaspDisplay = "Not Mapped";
      }

      return {
        ...finding,
        category: finding.category || "HTTP_HEADERS",
        module: finding.module || "SecurityHeaders",
        owasp: owaspDisplay
      };
    });
  }

  return normalized;
};
