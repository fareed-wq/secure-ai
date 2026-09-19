# Security Policies

## Uncertainty
- **NOT_EVALUATED ? secure**: Missing assessments never imply safety.
- **UNAVAILABLE ? secure**: Network failures never imply safety.
- **NO_MATCH ? guarantee of security**: Absence of public CVEs does not prove invulnerability.
- **KEV/SSVC uncertainty**: Absence of KEV does not imply absence of exploitation. Absence of SSVC does not imply low/no risk. KEV/SSVC describe generalized vulnerability intelligence; they do not establish actual exploitability against the scanned target (target applicability remains strictly dependent on the scanner's technology/CPE matching pipeline).

## Background Intelligence
- **NVD/EPSS lookups are third-party intelligence requests**.
- **They do not generate additional probing traffic against the target**.
- **They occur outside the core scan critical path**.

## Compare Safety
- **CVE removal from a match set is NOT called resolved/fixed/remediated**.
- **Resolution requires independent target evidence**.

## Priority
- **Derived organizational metadata**: Exists purely for triage.
- **Distinct from official CVSS**: Represents local contextual sorting. Phase7 may compare Priority changes as derived trend metadata.
- **Not a replacement for scanner score/severity**.

## Evidence/Verification
- **Preserve uncertainty**: Never guess facts.
- **Do not invent evidence or conclusions**: Stick strictly to observational reality.
