import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

function parseCSPDirectives(rawCSP) {
  if (!rawCSP) return {};
  const directives = {};
  rawCSP.split(';').forEach(part => {
    const trimmed = part.trim();
    if (!trimmed) return;
    const tokens = trimmed.split(/\s+/);
    const name = tokens.shift().toLowerCase();
    directives[name] = tokens.join(' ');
  });
  return directives;
}

export const CSPAnalysisPanel = ({ findings }) => {
  const [cspPanelOpen, setCspPanelOpen] = useState(true);

  const getFinding = (ruleId) => findings.find(f => f.rule_id === ruleId);
  const hasFinding = (ruleId) => !!getFinding(ruleId);

  const cspMissing = hasFinding('headers_csp_missing');
  const cspConfigured = getFinding('headers_csp_configured');
  const cspReportOnly = getFinding('headers_csp_report_only');
  const cspReportOnlyExtra = getFinding('headers_csp_report_only_extra');
  const rawCSP = cspConfigured?.evidence?.raw || '';
  const parsedCSP = parseCSPDirectives(rawCSP);

  // Weaknesses
  const weak = getFinding('csp_quality_weak');
  const inlineStyles = getFinding('csp_quality_inline_styles');
  const missingDefaultSrc = getFinding('csp_quality_missing_default_src');
  const objectSrcUnrestricted = getFinding('csp_quality_object_src_unrestricted');
  const baseUriUnrestricted = getFinding('csp_quality_base_uri_unrestricted');
  const formActionUnrestricted = getFinding('csp_quality_form_action_unrestricted');

  const weaknessFindings = [weak, inlineStyles, missingDefaultSrc, objectSrcUnrestricted, baseUriUnrestricted, formActionUnrestricted].filter(Boolean);

  let overallStatus = 'Not evaluated';
  let overallColor = 'text-slate-400';
  let recommendationCount = weaknessFindings.length;

  if (cspMissing) {
    overallStatus = 'Missing';
    overallColor = 'text-red-500';
  } else if (cspReportOnly && !cspConfigured) {
    overallStatus = 'Report Only';
    overallColor = 'text-amber-500';
  } else if (weaknessFindings.length > 0) {
    overallStatus = `Needs Review · ${recommendationCount} recommendation${recommendationCount !== 1 ? 's' : ''}`;
    overallColor = 'text-orange-500';
  } else if (hasFinding('headers_csp_hardened')) {
    overallStatus = 'Strong';
    overallColor = 'text-emerald-500';
  } else if (cspConfigured) {
    overallStatus = 'Good';
    overallColor = 'text-blue-500';
  }

  // Directive Statuses
  const getDirectiveStatus = (dir, weaknessCondition, isFormAction = false) => {
    if (weaknessCondition) return { label: 'Needs Review', color: 'text-orange-400' };

    if (isFormAction && hasFinding('headers_csp_form_action_configured')) {
      return { label: 'Configured', color: 'text-emerald-400' };
    }

    if (parsedCSP[dir] !== undefined) return { label: 'Restricted', color: 'text-emerald-400' };
    return { label: 'Not evaluated', color: 'text-slate-500' };
  };

  const getFrameAncestorsStatus = () => {
    if (hasFinding('headers_clickjacking_protection_missing')) {
      return { label: 'Needs Review', color: 'text-orange-400' };
    }
    if (parsedCSP['frame-ancestors'] !== undefined) {
      return { label: 'Protected', color: 'text-emerald-400' };
    }
    // Protected by X-Frame-Options or not evaluated but no finding
    return { label: 'Protected via X-Frame-Options', color: 'text-emerald-400' };
  };

  // Advanced Controls
  const weakRaw = weak?.evidence?.raw || '';
  const hardenedRaw = getFinding('headers_csp_hardened')?.evidence?.raw || '';

  const unsafeInlineScript = weakRaw.includes('unsafe-inline in script-src');
  const unsafeInlineStyle = !!inlineStyles;
  const unsafeEval = weakRaw.includes('unsafe-eval');
  const strictDynamic = hardenedRaw.includes('strict-dynamic');
  const nonceOrHash = hardenedRaw.includes('nonce') || hardenedRaw.includes('hashes');
  const broadSources = weakRaw.includes('wildcard') || weakRaw.includes('https:') || weakRaw.includes('data:') || weakRaw.includes('blob:') || weakRaw.includes('http:');

  if (cspMissing) {
    return (
      <div className="bg-slate-900/50 border-b border-slate-800">
        <button
          onClick={() => setCspPanelOpen(!cspPanelOpen)}
          className="w-full px-6 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
          aria-expanded={cspPanelOpen}
        >
          <div className="flex items-center gap-3">
            <span className="font-bold text-slate-200 text-sm">Content Security Policy Analysis</span>
            <span className={`text-xs font-bold ${overallColor}`}>{overallStatus}</span>
          </div>
          <div className="text-slate-500">
            {cspPanelOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </div>
        </button>
        {cspPanelOpen && (
          <div className="px-6 pb-4 pt-2 text-sm text-slate-400">
            Content-Security-Policy was not detected for this response.
          </div>
        )}
      </div>
    );
  }

  const renderRow = (label, value, statusObj) => (
    <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 last:border-0 text-sm">
      <div className="col-span-3 font-mono text-slate-400">{label}</div>
      <div className="col-span-6 font-mono text-slate-300 break-all">{value || <span className="text-slate-600">Not visible in policy evidence</span>}</div>
      <div className={`col-span-3 font-semibold ${statusObj.color}`}>{statusObj.label}</div>
    </div>
  );

  return (
    <div className="bg-slate-900/50 border-b border-slate-800">
      <button
        onClick={() => setCspPanelOpen(!cspPanelOpen)}
        className="w-full px-6 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
        aria-expanded={cspPanelOpen}
      >
        <div className="flex items-center gap-3">
          <span className="font-bold text-slate-200 text-sm">Content Security Policy Analysis</span>
          <span className={`text-xs font-bold ${overallColor}`}>
            {overallStatus}
          </span>
        </div>
        <div className="text-slate-500 hover:text-slate-300 transition-colors">
          {cspPanelOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {cspPanelOpen && (
        <div className="px-6 pb-6 pt-2 transition-all duration-300">
          {cspReportOnly && !cspConfigured && (
            <div className="mb-4 bg-amber-950/30 border border-amber-900/50 text-amber-500 px-4 py-2 rounded-lg text-sm">
              <span className="font-bold">Report-Only Mode: </span>
              The Content Security Policy is being monitored but is not actively enforced.
            </div>
          )}
          {cspReportOnlyExtra && cspConfigured && (
            <div className="mb-4 bg-blue-950/30 border border-blue-900/50 text-blue-400 px-4 py-2 rounded-lg text-sm">
              <span className="font-bold">Additional Report-Only Policy Detected: </span>
              An enforced CSP is active, and an additional Report-Only policy is also being evaluated.
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div>
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">Directive Analysis</h3>
              <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
                {renderRow('default-src', parsedCSP['default-src'], getDirectiveStatus('default-src', !!missingDefaultSrc))}
                {renderRow('script-src', parsedCSP['script-src'], getDirectiveStatus('script-src', !!weak))}
                {renderRow('style-src', parsedCSP['style-src'], getDirectiveStatus('style-src', !!inlineStyles))}
                {renderRow('object-src', parsedCSP['object-src'], getDirectiveStatus('object-src', !!objectSrcUnrestricted))}
                {renderRow('base-uri', parsedCSP['base-uri'], getDirectiveStatus('base-uri', !!baseUriUnrestricted))}
                {renderRow('form-action', parsedCSP['form-action'], getDirectiveStatus('form-action', !!formActionUnrestricted, true))}
                {renderRow('frame-ancestors', parsedCSP['frame-ancestors'], getFrameAncestorsStatus())}
              </div>
            </div>

            <div>
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">Advanced Controls</h3>
              <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
                <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 text-sm">
                  <div className="col-span-5 text-slate-400">unsafe-inline</div>
                  <div className="col-span-7">
                    <span className={unsafeInlineScript ? 'text-orange-400' : 'text-emerald-400'}>
                      Scripts: {unsafeInlineScript ? '✗' : '✓'}
                    </span>
                    {' / '}
                    <span className={unsafeInlineStyle ? 'text-orange-400' : 'text-emerald-400'}>
                      Styles: {unsafeInlineStyle ? '✗' : '✓'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 text-sm">
                  <div className="col-span-5 text-slate-400">unsafe-eval</div>
                  <div className="col-span-7 font-semibold">
                    {unsafeEval ? <span className="text-orange-400">Needs Review</span> : <span className="text-slate-500">Not detected</span>}
                  </div>
                </div>

                <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 text-sm">
                  <div className="col-span-5 text-slate-400">strict-dynamic</div>
                  <div className="col-span-7 font-semibold">
                    {strictDynamic ? <span className="text-emerald-400">Present</span> : <span className="text-slate-500">Not observed</span>}
                  </div>
                </div>

                <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 text-sm">
                  <div className="col-span-5 text-slate-400">Nonce / Hash Protection</div>
                  <div className="col-span-7 font-semibold">
                    {nonceOrHash ? <span className="text-emerald-400">Detected</span> : <span className="text-slate-500">Not observed</span>}
                  </div>
                </div>

                <div className="grid grid-cols-12 gap-4 py-2 border-b border-slate-800/50 text-sm">
                  <div className="col-span-5 text-slate-400">Broad Script Sources</div>
                  <div className="col-span-7 font-semibold">
                    {broadSources ? <span className="text-orange-400">Detected</span> : (weak ? <span className="text-emerald-400">None detected</span> : <span className="text-slate-500">Not evaluated</span>)}
                  </div>
                </div>

              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
