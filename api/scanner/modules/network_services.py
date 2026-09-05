from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from api.scanner.base import ScannerModule
import socket
from api.scanner.socket_helper import safe_create_connection

class NetworkServiceExposureModule(ScannerModule):
    module_name = "NetworkServiceExposureModule"
    version = "1.0.1"
    description = "Checks common ports for public reachability to detect potentially exposed services."
    author = "Secure-AI"
    enabled = True
    timeout = 10  # Max seconds for the whole module

    # Ports to check
    TARGET_PORTS = {
        21: ("FTP", "Informational", "Port 21 Publicly Reachable (FTP-associated)",
             "TCP port 21, commonly associated with FTP, is publicly reachable.",
             "If FTP is actually running, its exposure should be reviewed. It may allow unauthorized access or brute-force attacks if not properly secured."),
        22: ("SSH", "Informational", "Port 22 Publicly Reachable (SSH-associated)",
             "TCP port 22, commonly associated with SSH, is publicly reachable.",
             "If SSH is actually running, public management exposure increases the attack surface, though SSH itself is not automatically vulnerable."),
        23: ("Telnet", "Medium", "Port 23 Publicly Reachable (Telnet-associated)",
             "TCP port 23 is commonly associated with Telnet, a legacy unencrypted protocol.",
             "If Telnet is actually running, public exposure should be avoided."),
        25: ("SMTP", "Informational", "Port 25 Publicly Reachable (SMTP-associated)",
             "TCP port 25, commonly associated with SMTP, is publicly reachable.",
             "If a mail service is actually running, public exposure may be intentional, but can be targeted by spammers or attackers if misconfigured."),
        1433: ("Database", "Low", "Database-Associated Port Publicly Reachable",
               "A TCP port commonly associated with a database is publicly reachable.",
               "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private."),
        3306: ("Database", "Low", "Database-Associated Port Publicly Reachable",
               "A TCP port commonly associated with a database is publicly reachable.",
               "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private."),
        5432: ("Database", "Low", "Database-Associated Port Publicly Reachable",
               "A TCP port commonly associated with a database is publicly reachable.",
               "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private."),
        6379: ("Database", "Low", "Database-Associated Port Publicly Reachable",
               "A TCP port commonly associated with a database is publicly reachable.",
               "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private."),
        27017: ("Database", "Low", "Database-Associated Port Publicly Reachable",
                "A TCP port commonly associated with a database is publicly reachable.",
                "If a database is actually running, direct Internet reachability should be reviewed and normally restricted when the database is intended to be private.")
    }

    def _check_port(self, hostname: str, port: int, service: str, severity: str, finding_name: str, desc: str, impact: str) -> Optional[dict]:
        sock = None
        try:
            try:
                infos = socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM)
                if not infos:
                    return None
                target_ip = infos[0][4][0]
            except Exception:
                return None

            # Short timeout per port, safe_create_connection includes SSRF protection
            sock = safe_create_connection((target_ip, port), timeout=1.5)

            return self.make_finding(
                name=finding_name,
                severity=severity,
                category="network_services",
                description=desc,
                impact=impact,
                remediation="Restrict access to authorized IPs or VPNs if public access is not required.",
                evidence={"raw": f"TCP port {port}, commonly associated with {service}, is publicly reachable. The service itself was not fingerprinted."},
                confidence="High",
                owasp="Not Mapped"
            )
        except Exception:
            # Timeout, connection refused, unreachable, unexpected errors -> No finding
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def run(self, url: str, hostname: str, session) -> List[dict]:
        findings = []

        # Concurrently check ports
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []

            for port, (service, severity, finding_name, desc, impact) in self.TARGET_PORTS.items():
                futures.append(executor.submit(self._check_port, hostname, port, service, severity, finding_name, desc, impact))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        return findings
