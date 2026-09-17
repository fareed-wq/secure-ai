export function getTestedState(executionStatus, assessmentOutcome) {
  if (!executionStatus) return "Not available";
  
  if (executionStatus === "RETURNED") {
    if (assessmentOutcome === "COMPLETED") return "Tested";
    if (assessmentOutcome === "PARTIAL") return "Partially tested";
    if (assessmentOutcome === "NOT_APPLICABLE") return "Not applicable";
    if (assessmentOutcome === "BLOCKED") return "Blocked";
    if (assessmentOutcome === "FAILED") return "Not completed";
    return "Not available"; // fallback for missing/unknown/malformed
  }
  
  if (["FAILED", "TIMED_OUT", "NOT_COMPLETED"].includes(executionStatus)) {
    return "Not completed";
  }
  
  return "Not available";
}

export function getCapabilityLabel(moduleName) {
  const map = {
    "SecurityHeaders": "Security headers",
    "EnhancedTLS": "TLS configuration",
    "CORS": "Cross-origin resource sharing",
    "AuthenticationSessionSecurity": "Authentication and session security",
    "MixedContent": "Mixed content",
    "InformationDisclosure": "Information disclosure",
    "TechFingerprint": "Technology fingerprinting",
    "PermissionsPolicy": "Permissions policy",
    "CSPQuality": "Content security policy",
    "AdvancedCookie": "Cookie security",
    "AdvancedSecurityHeaders": "Advanced security headers",
    "GraphQLIntrospection": "GraphQL introspection",
    "VerboseStackTrace": "Verbose error handling",
    "ExposedFiles": "Exposed files",
    "RobotsTxt": "Robots.txt",
    "SitemapXml": "Sitemap",
    "SecurityTxt": "Security.txt",
    "OpenApiDiscovery": "OpenAPI discovery",
    "GraphqlIdeDiscovery": "GraphQL IDE discovery",
    "ActuatorDiscovery": "Actuator endpoints",
    "XmlRpcDiscovery": "XML-RPC discovery",
    "HTTPSRedirect": "HTTPS enforcement",
    "InfrastructureIntelligence": "Infrastructure intelligence",
    "JavaScriptSecurity": "JavaScript security",
    "SubdomainProbing": "Subdomain probing",
    "SubdomainTakeover": "Subdomain takeover",
    "PassiveSubdomainDiscovery": "Passive subdomain discovery",
    "NetworkServiceExposureModule": "Network service exposure",
    "DNSCAA": "DNS CAA security",
    "DNSEmailSecurity": "DNS and email security"
  };
  
  if (map[moduleName]) return map[moduleName];
  
  // Safe deterministic fallback: "BaseModule" -> "Base Module"
  return moduleName.replace(/([A-Z])/g, ' $1').trim();
}

export function getSimpleSummary(moduleExecution) {
  if (!moduleExecution || Object.keys(moduleExecution).length === 0) {
    return "Detailed scanner coverage information is not available for this scan.";
  }

  let totalApplicable = 0;
  let testedCount = 0;
  let hasBlocked = false;
  let hasNotAvailable = false;
  let allCompleted = true;

  for (const modKey of Object.keys(moduleExecution)) {
    const mod = moduleExecution[modKey];
    
    let status = null;
    let outcome = null;
    if (mod && typeof mod === 'object' && !Array.isArray(mod)) {
      status = mod.status;
      outcome = mod.assessment_outcome;
    }

    const state = getTestedState(status, outcome);
    
    if (state !== "Not applicable" && state !== "Not available") {
      totalApplicable++;
    }
    
    if (state === "Tested") {
      testedCount++;
    } else if (state === "Blocked") {
      hasBlocked = true;
      allCompleted = false;
    } else if (state === "Not available") {
      hasNotAvailable = true;
      allCompleted = false;
    } else if (state !== "Not applicable") {
      allCompleted = false;
    }
  }

  if (hasNotAvailable) {
    return "Some detailed scanner coverage information is unavailable for this scan.";
  }

  if (totalApplicable === 0) {
    return "No scanner checks were applicable to this target.";
  }

  if (allCompleted) {
    return "All applicable scanner checks completed.";
  }
  
  const mostTested = (testedCount / totalApplicable) > 0.5;

  if (hasBlocked) {
    return `${mostTested ? "Most scanner checks completed, but some" : "Some scanner checks"} were blocked, partially completed, or could not finish.`;
  }

  return `${mostTested ? "Most scanner checks completed, but some" : "Some scanner checks"} were only partially completed or could not finish.`;
}
