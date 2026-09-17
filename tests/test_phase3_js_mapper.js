import { getTestedState, getCapabilityLabel, getSimpleSummary } from '../src/lib/assessmentReporting.js';

let failed = false;
function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    console.error('FAIL: ' + msg + ' | Expected: ' + expected + ', Got: ' + actual);
    failed = true;
  }
}

// 1. Tested state mapping
assertEqual(getTestedState('RETURNED', 'COMPLETED'), 'Tested', 'RETURNED+COMPLETED');
assertEqual(getTestedState('RETURNED', 'PARTIAL'), 'Partially tested', 'RETURNED+PARTIAL');
assertEqual(getTestedState('RETURNED', 'NOT_APPLICABLE'), 'Not applicable', 'RETURNED+NOT_APPLICABLE');
assertEqual(getTestedState('RETURNED', 'BLOCKED'), 'Blocked', 'RETURNED+BLOCKED');
assertEqual(getTestedState('RETURNED', 'FAILED'), 'Not completed', 'RETURNED+FAILED');
assertEqual(getTestedState('RETURNED', undefined), 'Not available', 'RETURNED+missing');
assertEqual(getTestedState('RETURNED', 'XYZ'), 'Not available', 'RETURNED+unknown');
assertEqual(getTestedState('FAILED', null), 'Not completed', 'FAILED');
assertEqual(getTestedState('TIMED_OUT', null), 'Not completed', 'TIMED_OUT');
assertEqual(getTestedState('NOT_COMPLETED', null), 'Not completed', 'NOT_COMPLETED');
assertEqual(getTestedState(null, null), 'Not available', 'Missing');

// 2. Human-readable capabilities
assertEqual(getCapabilityLabel('SecurityHeaders'), 'Security headers', 'Known module');
assertEqual(getCapabilityLabel('DNSEmailSecurity'), 'DNS and email security', 'Known module DNS');
assertEqual(getCapabilityLabel('BaseModule'), 'Base Module', 'Unknown module safe fallback');
assertEqual(getCapabilityLabel('SomeUnknownModule'), 'Some Unknown Module', 'Unknown module safe fallback');

// 3. Simple Summary

// A. 2 Tested + 1 Blocked => Most... blocked
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm2': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm3': { status: 'RETURNED', assessment_outcome: 'BLOCKED' }
}), 'Most scanner checks completed, but some were blocked, partially completed, or could not finish.', 'A. 2 Tested, 1 Blocked');

// B. 2 Tested + 1 Partial => Most... partial
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm2': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm3': { status: 'RETURNED', assessment_outcome: 'PARTIAL' }
}), 'Most scanner checks completed, but some were only partially completed or could not finish.', 'B. 2 Tested, 1 Partial');

// C. 1 Tested + 2 Blocked => Some... blocked
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm2': { status: 'RETURNED', assessment_outcome: 'BLOCKED' },
  'm3': { status: 'RETURNED', assessment_outcome: 'BLOCKED' }
}), 'Some scanner checks were blocked, partially completed, or could not finish.', 'C. 1 Tested, 2 Blocked');

// D. 1 Tested + 3 Not completed => Some... partial
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm2': { status: 'FAILED' },
  'm3': { status: 'FAILED' },
  'm4': { status: 'FAILED' }
}), 'Some scanner checks were only partially completed or could not finish.', 'D. 1 Tested, 3 Not completed');

// E. all NOT_APPLICABLE => "No scanner checks were applicable to this target."
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'NOT_APPLICABLE' },
  'm2': { status: 'RETURNED', assessment_outcome: 'NOT_APPLICABLE' }
}), 'No scanner checks were applicable to this target.', 'E. all NOT_APPLICABLE');

// F. null module record => unavailable
assertEqual(getSimpleSummary({
  'm1': null
}), 'Some detailed scanner coverage information is unavailable for this scan.', 'F. null module record');

// G. malformed module record => Not available
assertEqual(getSimpleSummary({
  'm1': "malformed string"
}), 'Some detailed scanner coverage information is unavailable for this scan.', 'G. malformed module record');

// H. mixed Tested + malformed => unavailable
assertEqual(getSimpleSummary({
  'm1': { status: 'RETURNED', assessment_outcome: 'COMPLETED' },
  'm2': [1,2,3]
}), 'Some detailed scanner coverage information is unavailable for this scan.', 'H. mixed Tested + malformed');

// Empty execution
assertEqual(getSimpleSummary({}), 'Detailed scanner coverage information is not available for this scan.', 'Empty execution');
assertEqual(getSimpleSummary(null), 'Detailed scanner coverage information is not available for this scan.', 'Null execution');

if (failed) {
  process.exit(1);
} else {
  console.log('All JS mapper tests passed!');
}
