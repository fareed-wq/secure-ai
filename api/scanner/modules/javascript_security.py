import logging
import re
import json
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse

from html.parser import HTMLParser

from api.scanner.base import ScannerModule
from api.scanner.transport import safe_request
from api.scanner.core import Config

logger = logging.getLogger(__name__)

class JSScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script_srcs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attr_dict = {k.lower(): v for k, v in attrs if k and v}
            if "src" in attr_dict:
                self.script_srcs.append(attr_dict["src"].strip())

class JavaScriptSecurityModule(ScannerModule):
    module_name = "JavaScriptSecurity"
    description = "Comprehensive passive intelligence gathering from client-side JavaScript assets."

    MAX_BUNDLES = 10
    MAX_MAPS = 10
    MAX_READ_BYTES = 2000000  # 2MB

    # 1. SECRET DETECTION PATTERNS
    SECRET_PATTERNS = {
        "AWS Access Key ID": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "Stripe Secret Key": re.compile(r'\b(sk_live_[0-9a-zA-Z]{20,34})\b'),
        "OpenAI Secret Key": re.compile(r'\b(sk-(?:proj-)?[a-zA-Z0-9\-_]{20,60})\b'),
        "GitHub Access Token": re.compile(r'\b(gh[po]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b'),
        "GitLab Personal Access Token": re.compile(r'\b(glpat-[a-zA-Z0-9\-_]{20,})\b'),
        "Slack Token": re.compile(r'\b(xox[baprs]-[a-zA-Z0-9\-]+)\b'),
        "NPM Token": re.compile(r'\b(npm_[a-zA-Z0-9]{36})\b'),
        "Bearer Token": re.compile(r'Bearer\s+([A-Za-z0-9._~+/=-]{20,})'),
        "Private RSA Key": re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----')
    }
    
    # Do not flag generic test values
    TEST_KEYWORDS = ["EXAMPLE", "TEST", "DUMMY", "SAMPLE", "MOCK", "123456", "000000", "AKIAIOSFODNN7EXAMPLE", "PK_LIVE_", "NEXT_PUBLIC_"]
    
    # PUBLIC CLIENT KEYS (Informational)
    PUBLIC_KEY_PATTERNS = {
        "Google / Firebase Client API Key": re.compile(r'\b(AIzaSy[0-9A-Za-z\-_]{35})\b')
    }
    
    # 2. INTERNAL INFRASTRUCTURE PATTERNS
    INTERNAL_HOST_PATTERNS = [
        re.compile(r'https?://(?:[a-zA-Z0-9\-]+\.)*(?:internal|staging|dev|corp)\.[a-zA-Z0-9\-]+\.[a-zA-Z]+(?::\d+)?'),
        re.compile(r'https?://localhost(?::\d+)?'),
        re.compile(r'https?://127\.0\.0\.1(?::\d+)?'),
        re.compile(r'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?'),
        re.compile(r'https?://192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?'),
        re.compile(r'https?://172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}(?::\d+)?')
    ]

    # 3. DEBUG / CONFIG ARTIFACTS
    DEBUG_INDICATORS = [
        r'\bdebugger;\b',
        r'//#\s*sourceURL=',
        r'\b__webpack_require__\b',
        r'\bReact is running in non-production mode\b',
        r'\bVue\.config\.devtools\b'
    ]

    # 4. FRAMEWORKS
    FRAMEWORKS = {
        "React": r'\bReact\b|\bcreateElement\b',
        "Vue": r'\bVue\.component\b|\b__VUE__\b',
        "Angular": r'\bangular\.module\b|\bng-app\b',
        "Next.js": r'\b__NEXT_DATA__\b',
        "Nuxt": r'\b__NUXT__\b',
        "Svelte": r'\bSvelteComponent\b',
        "Webpack": r'\bwebpackJsonp\b|\b__webpack_require__\b',
        "Vite": r'\b__vite_is_modern_browser\b'
    }

    # 5. LIBRARIES
    LIBRARIES = {
        "jQuery": re.compile(r'jQuery v?(\d+\.\d+\.\d+)'),
        "Bootstrap": re.compile(r'Bootstrap v?(\d+\.\d+\.\d+)'),
        "React": re.compile(r'React v?(\d+\.\d+\.\d+)'),
        "Vue": re.compile(r'Vue\.js v?(\d+\.\d+\.\d+)'),
        "Angular": re.compile(r'AngularJS v?(\d+\.\d+\.\d+)'),
        "Lodash": re.compile(r'lodash v?(\d+\.\d+\.\d+)'),
        "Moment.js": re.compile(r'moment\.js v?(\d+\.\d+\.\d+)')
    }

    # API ROUTES
    API_ROUTE_PATTERN = re.compile(r'["\'](/api/v\d+/[a-zA-Z0-9_\-\/\{\}]+|/graphql|/rest/[a-zA-Z0-9_\-\/\{\}]+)[\'"]')
    ABS_API_ROUTE_PATTERN = re.compile(r'["\'](https?://api\.[a-zA-Z0-9\.\-]+/[a-zA-Z0-9_\-\/\{\}]+)[\'"]')
    
    # IDOR / SEQUENTIAL ID
    SEQ_ID_PATTERN = re.compile(r'/(?:users|orders|accounts|customers)/(?:\{[a-zA-Z0-9_]+\}|\d+)')
    
    # CONFIG 
    DANGEROUS_CONFIG = re.compile(r'["\'](?:accessToken|private_key|client_secret|DB_PASSWORD|password|secret)["\']\s*[:=]\s*["\']([^"\'\s]+)["\']', re.IGNORECASE)

    # PHASE 31: AUTHORIZATION & ACCESS CONTROL
    AUTH_LOGIC_PATTERN = re.compile(r'\b(isAdmin|is_admin|userRole|user_role|hasPermission|has_permission|canDelete|can_delete|canEdit|can_edit|canManage|can_manage|isStaff|is_staff|isSuperuser|is_superuser)\b\s*(?:===|==|!==|!=|=|\()\s*[^;,\)]+', re.IGNORECASE)
    ROLE_MODEL_PATTERN = re.compile(r'(?:["\']?(?:role|roles|permission|permissions)["\']?\s*:\s*(?:["\'][a-zA-Z0-9_\-]+["\']|\[[^\]]{1,100}\]))', re.IGNORECASE)
    PRIVILEGED_API_PATTERN = re.compile(r'["\'](?:https?://api\.[a-zA-Z0-9\.\-]+)?(/api/(?:admin|administrator|staff|management|roles|permissions|users|accounts|config|settings|payments|billing|internal)[/a-zA-Z0-9_\-\{\}]*)["\']', re.IGNORECASE)
    API_VERSION_PATTERN = re.compile(r'/(?:api/)?(v\d+)/')

    def _is_test_value(self, match_str: str) -> bool:
        upper_match = match_str.upper()
        return any(keyword in upper_match for keyword in self.TEST_KEYWORDS)

    def _mask_secret(self, raw_secret: str) -> str:
        if len(raw_secret) > 8:
            return raw_secret[:4] + "*" * 6 + raw_secret[-4:]
        return "***"

    def run(self, url: str, hostname: str, session) -> List[dict]:
        findings = []
        try:
            resp = safe_request("GET", url, session=session, timeout=(1.5, 2.5))
            if not resp or not resp.text:
                return findings
                
            content_type = resp.headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                return findings
                
            parser = JSScriptParser()
            parser.feed(resp.text[:self.MAX_READ_BYTES])
            
            # Extract same-origin assets
            target_netloc = urlparse(url).netloc
            script_urls = []
            for src in parser.script_srcs:
                full_url = urljoin(url, src)
                parsed = urlparse(full_url)
                if parsed.netloc == target_netloc or parsed.netloc == "":
                    if full_url not in script_urls:
                        script_urls.append(full_url)
                        
            script_urls = script_urls[:self.MAX_BUNDLES]
            
            secrets_found = set()
            info_secrets_found = set()
            api_endpoints = set()
            internal_hosts = set()
            frameworks = set()
            outdated_libs = set()
            debug_artifacts = set()
            seq_id_routes = set()
            dangerous_config = set()
            auth_logic_found = set()
            role_models_found = set()
            privileged_apis = set()
            api_versions = set()
            source_maps = []
            
            map_count = 0
            
            for js_url in script_urls:
                js_resp = safe_request("GET", js_url, session=session, timeout=(1.5, 2.5), stream=True)
                if not js_resp or js_resp.status_code != 200:
                    continue
                    
                chunks = []
                bytes_read = 0
                for chunk in js_resp.iter_content(8192):
                    bytes_read += len(chunk)
                    chunks.append(chunk.decode('utf-8', errors='ignore'))
                    if bytes_read >= self.MAX_READ_BYTES:
                        break
                        
                js_text = "".join(chunks)
                filename = js_url.split('/')[-1].split('?')[0] or "bundle.js"
                
                # 1. SECRET DETECTION
                for secret_name, pattern in self.SECRET_PATTERNS.items():
                    for match in pattern.finditer(js_text):
                        raw_match = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        if not self._is_test_value(raw_match):
                            secrets_found.add(f"Pattern: {secret_name} | Location: {filename} | Value: {self._mask_secret(raw_match)}")
                
                # 1.5 PUBLIC KEY DETECTION
                for key_name, pattern in self.PUBLIC_KEY_PATTERNS.items():
                    for match in pattern.finditer(js_text):
                        raw_match = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        if not self._is_test_value(raw_match):
                            info_secrets_found.add(f"Pattern: {key_name} | Location: {filename} | Value: {self._mask_secret(raw_match)}")
                            
                # 2. INTERNAL HOSTS
                for pattern in self.INTERNAL_HOST_PATTERNS:
                    for match in pattern.finditer(js_text):
                        host = match.group(0)
                        if "example.com" not in host.lower(): # exclude generic
                            internal_hosts.add(host)
                            
                # 3. DEBUG ARTIFACTS
                for indicator in self.DEBUG_INDICATORS:
                    if re.search(indicator, js_text):
                        debug_artifacts.add(f"Indicator matched: {indicator.replace(r'\\b', '')} in {filename}")

                # 4. FRAMEWORKS
                for fw_name, pattern in self.FRAMEWORKS.items():
                    if re.search(pattern, js_text):
                        frameworks.add(fw_name)
                        
                # 5. OUTDATED LIBRARIES
                for lib_name, pattern in self.LIBRARIES.items():
                    match = pattern.search(js_text)
                    if match:
                        version = match.group(1)
                        outdated_libs.add(f"{lib_name} v{version}")
                        
                # 6. API ROUTES
                for match in self.API_ROUTE_PATTERN.finditer(js_text):
                    route = match.group(1)
                    api_endpoints.add(route)
                    if self.SEQ_ID_PATTERN.search(route):
                        seq_id_routes.add(route)
                        
                for match in self.ABS_API_ROUTE_PATTERN.finditer(js_text):
                    route = match.group(1)
                    api_endpoints.add(route)
                    if self.SEQ_ID_PATTERN.search(route):
                        seq_id_routes.add(route)
                        
                # 7. DANGEROUS CONFIG
                for match in self.DANGEROUS_CONFIG.finditer(js_text):
                    val = match.group(1)
                    if len(val) > 4 and not self._is_test_value(val):
                        if not val.startswith("sk_live_") and not val.startswith("AKIA"): # avoid duplicate with secrets
                            dangerous_config.add(f"Config Key in {filename}: masked value '{self._mask_secret(val)}'")

                # PHASE 31: AUTH LOGIC & PRIVILEGED APIS
                for match in self.AUTH_LOGIC_PATTERN.finditer(js_text):
                    # Truncate and clean the matched logic statement
                    snippet = match.group(0)[:50].strip()
                    if snippet:
                        auth_logic_found.add(snippet)
                        
                for match in self.ROLE_MODEL_PATTERN.finditer(js_text):
                    snippet = match.group(0)[:80].strip()
                    if snippet:
                        role_models_found.add(snippet)
                        
                for match in self.PRIVILEGED_API_PATTERN.finditer(js_text):
                    privileged_apis.add(match.group(1))
                    
                for match in self.API_VERSION_PATTERN.finditer(js_text):
                    api_versions.add(match.group(1).lower())

                # 8. SOURCE MAP DETECTION
                map_url = None
                sm_match = re.search(r'(?://#|/\*#)\s*sourceMappingURL=([^\s\*]+)', js_text)
                if sm_match:
                    map_url = urljoin(js_url, sm_match.group(1).strip())
                elif ".min.js" in js_url:
                    map_url = js_url.replace(".min.js", ".map")
                else:
                    map_url = js_url + ".map"
                    
                if map_url and map_count < self.MAX_MAPS:
                    map_count += 1
                    try:
                        m_resp = safe_request("GET", map_url, session=session, timeout=(1.5, 2.5), stream=True)
                        if m_resp and m_resp.status_code == 200:
                            m_chunks = []
                            m_bytes = 0
                            for m_c in m_resp.iter_content(8192):
                                m_bytes += len(m_c)
                                m_chunks.append(m_c.decode('utf-8', errors='ignore'))
                                if m_bytes >= self.MAX_READ_BYTES:
                                    break
                            m_text = "".join(m_chunks)
                            if m_text.strip().startswith("{") and ("\"version\"" in m_text or "\"sources\"" in m_text):
                                source_maps.append(map_url)
                                
                                # 8a. SENSITIVE CONTENT IN MAP
                                if "\"sourcesContent\"" in m_text:
                                    for secret_name, pattern in self.SECRET_PATTERNS.items():
                                        for match in pattern.finditer(m_text):
                                            raw_match = match.group(1) if len(match.groups()) > 0 else match.group(0)
                                            if not self._is_test_value(raw_match):
                                                secrets_found.add(f"Pattern: {secret_name} | Location: {map_url} (SourceMap) | Value: {self._mask_secret(raw_match)}")
                    except Exception as e:
                        logger.debug("Source map fetch failed: %s", e)
                        
            # FRONTEND CONFIG 
            if re.search(r'window\.(?:__CONFIG__|ENV|__INITIAL_STATE__|__ENV__|config)\s*=', resp.text):
                if re.search(r'["\']?(?:debug|env|environment)["\']?\s*:\s*(?:true|["\'](?:development|staging)["\'])', resp.text, re.IGNORECASE) or \
                   re.search(r'(?:\.internal\.|\.staging\.|localhost)', resp.text):
                    findings.append(self.make_finding(
                        "Exposed Frontend Environment & Debug Configuration",
                        "Medium",
                        "Your website's code reveals internal setup details that are normally hidden.",
                        "Configuration object found in HTML source with debug/staging indicators.",
                        impact="Hackers can use this behind-the-scenes information to better understand your website and plan an attack.",
                        confidence="Medium",
                        category="information_exposure",
                        owasp="A05: Security Misconfiguration"
                    ))

            # AGGREGATE FINDINGS
            if secrets_found:
                findings.append(self.make_finding(
                    "Hardcoded Third-Party Secret Key Exposed in JS Bundle",
                    "High",
                    "A highly sensitive password or secret key for another service was found left inside your website's code.",
                    "\\n".join(list(secrets_found)[:5]),
                    impact="Attackers can steal this key to access your accounts, steal data, or run up charges on services you use.",
                    confidence="High",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration"
                ))
            
            if info_secrets_found:
                findings.append(self.make_finding(
                    "Client-Side API Key Detected",
                    "Informational",
                    "A public key used to connect to external services (like Google Maps) is visible in your website's code.",
                    "\\n".join(list(info_secrets_found)[:5]),
                    impact="While this key is meant to be public, if it isn't properly restricted, others could use it on their own websites and run up your bill.",
                    remediation="Ensure public API keys have HTTP Referrer restrictions configured.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))
                
            if internal_hosts:
                findings.append(self.make_finding(
                    "Internal Infrastructure References Disclosed in Client-Side Code",
                    "Low",
                    "Your website's code accidentally mentions private servers or internal test addresses.",
                    "\\n".join(list(internal_hosts)[:5]),
                    impact="This gives attackers clues about how your private network is set up, which helps them find weaker targets.",
                    confidence="Medium",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration"
                ))
                
            if debug_artifacts:
                findings.append(self.make_finding(
                    "Client-Side Development Artifacts Detected",
                    "Low",
                    "Leftover testing or debugging code was found on your live website.",
                    "\\n".join(list(debug_artifacts)[:5]),
                    impact="This extra code can reveal details about how your website was built, giving hackers hints on where to look for weaknesses.",
                    confidence="Medium",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration"
                ))
                
            if frameworks:
                findings.append(self.make_finding(
                    "Client-Side Framework Detected",
                    "Informational",
                    "We can easily see which tools and frameworks were used to build your website.",
                    ", ".join(frameworks),
                    impact="Knowing the exact tools you use allows hackers to search for specific flaws related to those tools.",
                    confidence="High",
                    category="technology_detection",
                    owasp="A00: Informational"
                ))
                
            if outdated_libs:
                findings.append(self.make_finding(
                    "Outdated Client-Side JavaScript Library Detected",
                    "Informational",
                    "Your website is using older versions of some software libraries.",
                    ", ".join(outdated_libs),
                    impact="Older software often contains known security flaws that hackers can easily exploit to compromise your site.",
                    confidence="Medium",
                    category="technology_detection",
                    owasp="A06: Vulnerable and Outdated Components"
                ))
                
            if api_endpoints:
                count = len(api_endpoints)
                examples = "\\n".join(list(api_endpoints)[:5])
                evidence = f"{count} API endpoints discovered.\\nExamples:\\n{examples}"
                if count > 5:
                    evidence += f"\\n... (and {count-5} more omitted)"
                findings.append(self.make_finding(
                    "Client-Side API Endpoints Discovered",
                    "Informational",
                    "Your website's code contains a list of direct paths (API endpoints) to your backend system.",
                    evidence,
                    impact="This provides a complete map of your application for attackers to explore and find hidden vulnerabilities.",
                    confidence="High",
                    category="api_surface",
                    owasp="A00: Informational"
                ))
                
            if seq_id_routes:
                findings.append(self.make_finding(
                    "Sequential Object Identifiers Detected in API Routes (IDOR Risk)",
                    "Medium",
                    "Your website appears to use simple, predictable numbers (like 1, 2, 3) to identify users or records.",
                    "\\n".join(list(seq_id_routes)[:3]),
                    impact="If permissions aren't perfectly configured, hackers can easily guess the numbers to view other people's private information.",
                    confidence="Low",
                    category="api_surface",
                    owasp="A01: Broken Access Control"
                ))
                
            if dangerous_config:
                findings.append(self.make_finding(
                    "Sensitive Client-Side Configuration Reference Detected",
                    "Medium",
                    "We found sensitive configuration details, like passwords or secret keys, written directly into your website's code.",
                    "\\n".join(list(dangerous_config)[:5]),
                    impact="Anyone visiting your website can read these secrets and potentially use them to hack into your systems.",
                    remediation="Never bundle production passwords or secrets into client-side code.",
                    owasp="A05: Security Misconfiguration",
                    category="information_exposure"
                ))

            if source_maps:
                findings.append(self.make_finding(
                    "JavaScript Source Maps Exposed (.map)",
                    "Medium",
                    "Special files used by developers to debug code are publicly accessible on your live website.",
                    "\\n".join(source_maps[:3]),
                    impact="This allows anyone to read your original, uncompressed source code, making it much easier for hackers to find hidden flaws.",
                    confidence="High",
                    category="information_exposure",
                    owasp="A05: Security Misconfiguration"
                ))

            if auth_logic_found:
                findings.append(self.make_finding(
                    "Privileged Client-Side Authorization Logic Disclosed",
                    "Informational",
                    "The code that checks if a user is an admin or has special permissions is visible in your public website files.",
                    "\\n".join(list(auth_logic_found)[:5]),
                    impact="Hackers can study this code to understand how your security works and try to trick the system into giving them admin access.",
                    owasp="A01: Broken Access Control",
                    category="authentication",
                    confidence="Medium"
                ))

            if role_models_found:
                findings.append(self.make_finding(
                    "Authorization Roles / Permissions Disclosed",
                    "Informational",
                    "The list of user roles and permissions (like 'admin' or 'editor') is exposed in your website's code.",
                    "\\n".join(list(role_models_found)[:5]),
                    impact="This helps attackers understand exactly what permissions exist, giving them a target list of roles to try and steal.",
                    owasp="A01: Broken Access Control",
                    category="authentication",
                    confidence="High"
                ))

            if privileged_apis:
                findings.append(self.make_finding(
                    "Privileged API Surface Discovered in Client-Side Code",
                    "Informational",
                    "Paths to restricted administrative areas were found in the public code of your website.",
                    "\\n".join(list(privileged_apis)[:5]),
                    impact="Attackers can use these paths to find your private admin login pages or try to access restricted functions directly.",
                    owasp="A01: Broken Access Control",
                    category="api_surface",
                    confidence="High"
                ))
                
            if api_versions:
                findings.append(self.make_finding(
                    "Versioned API Surface Discovered",
                    "Informational",
                    "Your website reveals the exact version number of the backend services it communicates with.",
                    f"Versions observed: {', '.join(api_versions)}",
                    impact="Knowing the exact version helps hackers quickly look up known weaknesses for that specific system.",
                    owasp="A00: Informational",
                    category="api_surface",
                    confidence="High"
                ))

        except Exception as e:
            logger.debug("JavaScriptSecurityModule failed: %s", e)
            
        return findings
