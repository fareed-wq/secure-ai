import { calculateFindingPriority, calculateCvePriority } from '../src/utils/priority.js';
import fs from 'fs';

// Mock finding
const finding1 = { severity: 'High', name: 'Test' };
console.log('JS_FINDING_HIGH:', calculateFindingPriority(finding1));

const findingCrit = { severity: 'Critical', name: 'Test' };
console.log('JS_FINDING_CRITICAL:', calculateFindingPriority(findingCrit));

const cveP1 = { cvss_score: 9.8 };
const ident = { vulnerability_state: 'MATCHED' };
console.log('JS_CVE_P1:', calculateCvePriority(ident, cveP1));

const legacyCve = { cvss_assessments: [{base_score: 9.5}], epss: {score: 0.05} };
console.log('JS_CVE_LEGACY_P1:', calculateCvePriority(ident, legacyCve));

// To test exportUtils, we can read the file, extract generateJSON and generateCSV, and run them.
const exportCode = fs.readFileSync('../src/lib/exportUtils.js', 'utf8');
const transformedCode = exportCode.replace(/export const/g, 'const').replace(/import.*?priority';/g, '');
const execute = new Function('calculateFindingPriority', transformedCode + `
  return {
    csv: generateCSV([{severity: 'High', name: 'HighFinding'}], {}),
    json: generateJSON([{severity: 'High', name: 'HighFinding'}], {})
  };
`);

const result = execute(calculateFindingPriority);
console.log('JS_EXPORT_CSV:', result.csv.includes('HighFinding,High,P2') ? 'PASS' : 'FAIL');
console.log('JS_EXPORT_JSON:', JSON.parse(result.json).findings[0].priority === 'P2' ? 'PASS' : 'FAIL');

const executeVuln = new Function('calculateFindingPriority', 'calculateCvePriority', transformedCode + '\nreturn generateVulnerabilitiesCSV;');
const generateVulnerabilitiesCSV = executeVuln(calculateFindingPriority, calculateCvePriority);

function assertEq(actual, expected, name) {
  if (actual === expected) {
    console.log(name + ': PASS');
  } else {
    console.log(name + ': FAIL');
    console.log('  Expected: ' + expected);
    console.log('  Actual: ' + actual);
  }
}

// A. Empty data
assertEq(generateVulnerabilitiesCSV([]).split('\n').length, 1, 'JS_VULN_EMPTY_ARRAY');
assertEq(generateVulnerabilitiesCSV([null]).split('\n').length, 1, 'JS_VULN_NULL_TECH');

// B. One technology, no CVEs (NO_MATCH)
const techNoMatch = [{ name: 'TechB', vulnerability_state: 'NO_MATCH', cves: [] }];
const csvB = generateVulnerabilitiesCSV(techNoMatch);
assertEq(csvB.split('\n').length, 2, 'JS_VULN_NO_MATCH_ROWS');
assertEq(csvB.includes('TechB,,,,,NO_MATCH,,,,,,,,,,,,'), true, 'JS_VULN_NO_MATCH_CONTENT');

// C. One technology, one CVE
const techOneCve = [{ name: 'TechC', cves: [{ id: 'CVE-1', severity: 'HIGH' }] }];
const csvC = generateVulnerabilitiesCSV(techOneCve);
assertEq(csvC.split('\n').length, 2, 'JS_VULN_ONE_CVE_ROWS');
assertEq(csvC.includes('TechC,,,,,,CVE-1,HIGH,,,,,,,,,UNSCORED,'), true, 'JS_VULN_ONE_CVE_CONTENT');

// D. One technology, multiple CVEs
const techMultiCve = [{ name: 'TechD', cves: [{ id: 'CVE-1' }, { id: 'CVE-2' }] }];
const csvD = generateVulnerabilitiesCSV(techMultiCve);
assertEq(csvD.split('\n').length, 3, 'JS_VULN_MULTI_CVE_ROWS');
assertEq(csvD.includes('CVE-1'), true, 'JS_VULN_MULTI_CVE_CONTENT_1');
assertEq(csvD.includes('CVE-2'), true, 'JS_VULN_MULTI_CVE_CONTENT_2');

// E. Multiple technologies with multiple CVEs
const multiTech = [techMultiCve[0], techOneCve[0]];
const csvE = generateVulnerabilitiesCSV(multiTech);
assertEq(csvE.split('\n').length, 4, 'JS_VULN_MULTI_TECH_ROWS');

// F. CVSS missing and present
const techCvss = [{ name: 'T', cves: [{ id: 'CVE-1', cvss_score: 9.8 }, { id: 'CVE-2', cvss_score: 'UNAVAILABLE' }] }];
const csvF = generateVulnerabilitiesCSV(techCvss);
assertEq(csvF.includes('9.8'), true, 'JS_VULN_CVSS_PRESENT');
assertEq(csvF.includes('UNAVAILABLE'), true, 'JS_VULN_CVSS_UNAVAILABLE');

// G. EPSS
const techEpss = [{ name: 'T', cves: [
  { id: 'C1', epss_info: { status: 'AVAILABLE', epss: 0, percentile: 0 } },
  { id: 'C2', epss_info: { status: 'AVAILABLE', epss: 0.15, percentile: 0.89 } },
  { id: 'C3', epss_info: { status: 'NOT_FOUND' } },
  { id: 'C4', epss_info: { status: 'UNAVAILABLE' } }
]}];
const csvG = generateVulnerabilitiesCSV(techEpss);
assertEq(csvG.includes('0.00%,0th'), true, 'JS_VULN_EPSS_ZERO');
assertEq(csvG.includes('15.00%,89th'), true, 'JS_VULN_EPSS_NORMAL');
assertEq(csvG.includes('Not Found'), true, 'JS_VULN_EPSS_NOT_FOUND');
assertEq(csvG.includes('Unavailable'), true, 'JS_VULN_EPSS_UNAVAILABLE');

// H. CWE
const techCwe = [{ name: 'T', cves: [{ id: 'C1', cwes: ['CWE-1', 'CWE-2'] }] }];
const csvH = generateVulnerabilitiesCSV(techCwe);
assertEq(csvH.includes('CWE-1 | CWE-2'), true, 'JS_VULN_CWE_MULTI');

// I. KEV / SSVC
const techKev = [{ name: 'T', cves: [
  {
    id: 'C1',
    kev: { name: 'Test Vuln', added: '2021-11-03', action: 'Apply updates.', due: '2021-11-17' },
    ssvc: { source: 'CISA', options: { exploitation: 'active', automatable: 'no' } }
  },
  {
    id: 'C2',
    kev: { name: 'Test 2' },
    ssvc: { source: 'CISA' }
  },
  {
    id: 'C3'
  }
]}];
const csvI = generateVulnerabilitiesCSV(techKev);
assertEq(csvI.includes('Test Vuln | Added: 2021-11-03 | Action: Apply updates. | Due: 2021-11-17'), true, 'JS_VULN_KEV_FULL');
assertEq(csvI.includes('exploitation: active | automatable: no'), true, 'JS_VULN_SSVC_FULL');
assertEq(csvI.includes('Test 2,'), true, 'JS_VULN_KEV_PARTIAL');
assertEq(csvI.includes(',C3,'), true, 'JS_VULN_KEV_SSVC_ABSENT');
assertEq(csvI.includes('IN_KEV'), false, 'JS_VULN_NO_IN_KEV');
assertEq(csvI.includes('AVAILABLE'), false, 'JS_VULN_NO_AVAILABLE');

// K. CVE Priority mapping
const techPrio = [{ vulnerability_state: 'MATCHED', cves: [
  { id: 'C1', cvss_score: 9.8 },
  { id: 'C2', cvss_score: 7.0 },
  { id: 'C3', cvss_score: -1.0, epss_info: {status: 'AVAILABLE', epss: 0.005} },
  { id: 'C4', cvss_score: 0.0 }
]}];
const csvK = generateVulnerabilitiesCSV(techPrio);
assertEq(csvK.includes('C1,,9.8,,,,,,,,P1,'), true, 'JS_VULN_PRIO_P1');
assertEq(csvK.includes('C2,,7,,,,,,,,P2,'), true, 'JS_VULN_PRIO_P2');
assertEq(csvK.includes('C3,,-1,,,,0.50%,,,,UNSCORED,'), true, 'JS_VULN_PRIO_UNSCORED');
assertEq(csvK.includes('C4,,0,,,,,,,,P5,'), true, 'JS_VULN_PRIO_P5');

// CSV Structure Validation (Quotes and commas)
const techCsv = [{ name: 'T', cves: [{ id: 'C1', severity: 'A,B"C' }] }];
const csvStr = generateVulnerabilitiesCSV(techCsv);
assertEq(csvStr.includes('"A,B""C"'), true, 'JS_VULN_CSV_ESCAPE');
