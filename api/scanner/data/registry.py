from api.scanner.modules.headers import TechFingerprintModule, CORSModule, PermissionsPolicyModule
from api.scanner.modules.discovery import (
    ExposedFilesModule,
    InformationDisclosureModule,
    RobotsTxtModule,
    SitemapModule,
    SecurityTxtModule,
    OpenApiModule,
    GraphqlIdeModule,
    ActuatorModule,
    XmlRpcModule,
)
from api.scanner.modules.dns import DNSCAAModule, DNSEmailSecurityModule
from api.scanner.modules.http_security import (
    AdvancedCookieModule,
    HTTPSRedirectModule,
    SecurityHeadersModule,
    AdvancedSecurityHeadersModule,
)
from api.scanner.modules.network_checks import (
    SubdomainProbingModule,
    TLSCipherStrengthModule,
    GraphQLIntrospectionModule,
    VerboseStackTraceModule,
    PassiveSubdomainDiscoveryModule,
)
from api.scanner.modules.tls import EnhancedTLSModule
from api.scanner.modules.content import (
    MixedContentModule,
)
from api.scanner.modules.javascript_security import JavaScriptSecurityModule
from api.scanner.modules.infrastructure import InfrastructureIntelligenceModule
from api.scanner.modules.api_web_security import ApiWebSecurityModule
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule

DOMAIN_MAP = {
    "EnhancedTLSModule": "transport_tls",
    "TLSCipherStrengthModule": "transport_tls",
    "HTTPSRedirectModule": "transport_tls",
    "MixedContentModule": "transport_tls",
    "SecurityHeadersModule": "browser_defense",
    "AdvancedSecurityHeadersModule": "browser_defense",
    "PermissionsPolicyModule": "browser_defense",
    "CORSModule": "browser_defense",
    "AdvancedCookieModule": "browser_defense",
    "GraphQLIntrospectionModule": "api_surface",
    "VerboseStackTraceModule": "api_surface",
    "ExposedFilesModule": "api_surface",
    "JavaScriptSecurityModule": "api_surface",
    "InfrastructureIntelligenceModule": "domain_email",
    "ApiWebSecurityModule": "api_surface",
    "RobotsTxtModule": "api_surface",
    "SitemapModule": "api_surface",
    "TechFingerprintModule": "api_surface",
    "InformationDisclosureModule": "api_surface",
    "DNSCAAModule": "email_domain",
    "DNSEmailSecurityModule": "email_domain",
    "SecurityTxtModule": "email_domain",
    "OpenApiModule": "api_surface",
    "GraphqlIdeModule": "api_surface",
    "ActuatorModule": "api_surface",
    "XmlRpcModule": "api_surface",
    "PassiveSubdomainDiscoveryModule": "api_surface",
    "AuthenticationSessionSecurityModule": "api_surface",
}

PASSIVE_MODULES = [
    AuthenticationSessionSecurityModule(),
    MixedContentModule(),
    InformationDisclosureModule(),
    TechFingerprintModule(),
    PermissionsPolicyModule(),
    AdvancedCookieModule(),
    SecurityHeadersModule(),
    AdvancedSecurityHeadersModule(),
]

ACTIVE_MODULES = [
    GraphQLIntrospectionModule(),
    VerboseStackTraceModule(),
    ExposedFilesModule(),
    DNSCAAModule(),
    DNSEmailSecurityModule(),
    RobotsTxtModule(),
    SitemapModule(),
    SecurityTxtModule(),
    OpenApiModule(),
    GraphqlIdeModule(),
    ActuatorModule(),
    XmlRpcModule(),
    CORSModule(),
    HTTPSRedirectModule(),
    EnhancedTLSModule(),
    TLSCipherStrengthModule(),
    PassiveSubdomainDiscoveryModule(),
    JavaScriptSecurityModule(),
    InfrastructureIntelligenceModule(),
    ApiWebSecurityModule(),
]

REGISTERED_MODULES = PASSIVE_MODULES + ACTIVE_MODULES
