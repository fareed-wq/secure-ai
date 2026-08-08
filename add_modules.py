import sys

with open('api/index.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_classes = '''
class GraphQLIntrospectionModule(ScannerModule):
    name = "GraphQL Introspection"
    description = "Checks if public GraphQL schemas can be extracted."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        base_url = url.rstrip('/')
        paths = ["/graphql", "/api/graphql"]
        
        with ThreadPoolExecutor(max_workers=2) as file_pool:
            futures = {}
            for path in paths:
                target_url = f"{base_url}{path}?query={{__typename}}"
                futures[file_pool.submit(safe_request, "GET", target_url, session=session, timeout=(1.5, 2.5))] = target_url
                
            for future in as_completed(futures):
                try:
                    resp = future.result()
                    if resp and resp.status_code == 200:
                        content_type = resp.headers.get("Content-Type", "").lower()
                        if "application/json" in content_type:
                            text = resp.text
                            if '"__typename"' in text or '"__schema"' in text:
                                findings.append(self.make_finding(
                                    "Public GraphQL Introspection Enabled",
                                    "Informational",
                                    "GraphQL endpoint is publicly accessible and accepts schema introspection queries.",
                                    target_url,
                                    impact="Public schema discovery allows developers and auditors to map available backend queries and data fields.",
                                    owasp="A05: Security Misconfiguration",
                                    category="information_exposure"
                                ))
                                break
                except Exception:
                    pass
        return findings

class VerboseStackTraceModule(ScannerModule):
    name = "Verbose Stack Trace"
    description = "Checks for backend error trace disclosures."

    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        findings = []
        base_url = url.rstrip('/')
        target_url = f"{base_url}/api/v1/debug_probe_404"
        
        try:
            resp = safe_request("GET", target_url, session=session, timeout=(1.5, 2.5))
            if resp and resp.status_code in [500, 502]:
                content_type = resp.headers.get("Content-Type", "").lower()
                if "application/json" in content_type or "text/plain" in content_type:
                    signatures = ["SQLSTATE[", "PostgreSQL query failed", "Django Version", "Traceback (most recent call last)", "Express error:"]
                    text = resp.text
                    for sig in signatures:
                        if sig in text:
                            findings.append(self.make_finding(
                                "Verbose Backend Error / Stack Trace Disclosure",
                                "Medium",
                                f"Target leaked verbose backend trace on error (Matched signature: {sig}).",
                                target_url,
                                impact="Exposes sensitive backend logic, database structures, or framework versions.",
                                remediation="Configure production environment to mask verbose error stack traces.",
                                owasp="A05: Security Misconfiguration",
                                category="information_exposure"
                            ))
                            break
        except Exception:
            pass
        return findings

'''

if 'class GraphQLIntrospectionModule' not in content:
    content = content.replace('REGISTERED_MODULES = [', new_classes + 'REGISTERED_MODULES = [\n    GraphQLIntrospectionModule(),\n    VerboseStackTraceModule(),')
    with open('api/index.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Modules added!")
else:
    print("Modules already exist!")
