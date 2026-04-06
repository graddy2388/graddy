import logging
import socket
from typing import List, Optional

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.rdatatype
import dns.reversename

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


def _get_domain(host: str) -> str:
    """Extract the domain from a host."""
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        pass
    return host


def _resolve_txt(domain: str, resolver: dns.resolver.Resolver) -> List[str]:
    """Resolve TXT records for a domain, returns list of record strings."""
    try:
        answers = resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.DNSException, Exception):
        return []


def _check_spf(domain: str, resolver: dns.resolver.Resolver) -> Finding:
    """Check SPF record existence and basic configuration."""
    txt_records = _resolve_txt(domain, resolver)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return Finding(
            title="SPF record missing",
            severity=Severity.MEDIUM,
            description=(
                f"No SPF (Sender Policy Framework) record found for {domain}. "
                "Without SPF, attackers can send emails that appear to come from your domain."
            ),
            recommendation=(
                "Add an SPF TXT record to your DNS. Example: "
                "'v=spf1 include:_spf.yourmailprovider.com ~all'. "
                "Use '-all' for strict enforcement or '~all' for soft fail."
            ),
            details={"domain": domain, "txt_records": txt_records},
        )

    spf = spf_records[0]
    if "+all" in spf:
        return Finding(
            title="SPF record uses +all (allows any sender)",
            severity=Severity.HIGH,
            description=(
                f"The SPF record for {domain} uses '+all', which allows any IP address to send "
                "email as this domain. This completely defeats the purpose of SPF."
            ),
            recommendation="Replace '+all' with '-all' (fail) or '~all' (soft fail) to restrict senders.",
            details={"spf_record": spf},
        )

    return Finding(
        title="SPF record configured",
        severity=Severity.INFO,
        description=f"SPF record found for {domain}: {spf}",
        details={"spf_record": spf},
    )


def _check_dmarc(domain: str, resolver: dns.resolver.Resolver) -> List[Finding]:
    """Check DMARC record existence and policy strength."""
    findings: List[Finding] = []
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _resolve_txt(dmarc_domain, resolver)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        findings.append(
            Finding(
                title="DMARC record missing",
                severity=Severity.HIGH,
                description=(
                    f"No DMARC record found at {dmarc_domain}. "
                    "Without DMARC, email spoofing and phishing using your domain is harder to detect or block."
                ),
                recommendation=(
                    "Add a DMARC TXT record at _dmarc.<yourdomain>. "
                    "Start with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' and move to "
                    "'p=quarantine' or 'p=reject' after reviewing reports."
                ),
                details={"dmarc_domain": dmarc_domain},
            )
        )
        return findings

    dmarc = dmarc_records[0]
    policy = None
    for part in dmarc.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:].strip().lower()
            break

    if policy == "none":
        findings.append(
            Finding(
                title="DMARC policy set to 'none' (monitoring only)",
                severity=Severity.MEDIUM,
                description=(
                    f"The DMARC policy for {domain} is set to 'p=none', which only monitors "
                    "email but does not block or quarantine spoofed messages."
                ),
                recommendation=(
                    "After reviewing DMARC reports, move to 'p=quarantine' then 'p=reject' "
                    "to actively block email spoofing."
                ),
                details={"dmarc_record": dmarc, "policy": policy},
            )
        )
    elif policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                title=f"DMARC policy enforced (p={policy})",
                severity=Severity.INFO,
                description=(
                    f"DMARC is configured with enforcement policy 'p={policy}' for {domain}. "
                    "Spoofed emails will be quarantined or rejected."
                ),
                details={"dmarc_record": dmarc, "policy": policy},
            )
        )
    else:
        findings.append(
            Finding(
                title="DMARC record found",
                severity=Severity.INFO,
                description=f"DMARC record found for {domain}: {dmarc}",
                details={"dmarc_record": dmarc, "policy": policy},
            )
        )

    return findings


def _attempt_zone_transfer(domain: str, resolver: dns.resolver.Resolver) -> Optional[Finding]:
    """Attempt DNS zone transfer (AXFR). If successful, this is a critical finding."""
    try:
        ns_answers = resolver.resolve(domain, "NS")
        nameservers = [str(rr.target).rstrip(".") for rr in ns_answers]
    except (dns.exception.DNSException, Exception) as exc:
        logger.debug("Could not resolve NS for %s: %s", domain, exc)
        return None

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            if zone:
                records = list(zone.nodes.keys())
                return Finding(
                    title="DNS zone transfer allowed (CRITICAL information disclosure)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The nameserver '{ns}' for domain '{domain}' allows zone transfers (AXFR). "
                        f"This exposes the complete DNS zone, revealing all subdomains and internal infrastructure. "
                        f"Discovered {len(records)} records."
                    ),
                    recommendation=(
                        "Restrict zone transfers to authorized secondary nameservers only. "
                        "Configure 'allow-transfer' in BIND or equivalent in your DNS software."
                    ),
                    details={
                        "nameserver": ns,
                        "domain": domain,
                        "record_count": len(records),
                        "sample_records": [str(r) for r in records[:10]],
                    },
                )
        except (dns.exception.FormError, dns.exception.DNSException, Exception) as exc:
            logger.debug("Zone transfer failed for %s via %s: %s", domain, ns, exc)
            continue

    return None


def _check_cname_takeover(domain: str, resolver: dns.resolver.Resolver) -> List[Finding]:
    """Check for potential subdomain takeover via dangling CNAME records."""
    findings: List[Finding] = []
    subdomains_to_check = ["www", "mail", "blog", "shop", "api", "dev", "staging"]

    for sub in subdomains_to_check:
        fqdn = f"{sub}.{domain}"
        try:
            cname_answers = resolver.resolve(fqdn, "CNAME")
            for rdata in cname_answers:
                target = str(rdata.target).rstrip(".")
                try:
                    resolver.resolve(target, "A")
                except dns.resolver.NXDOMAIN:
                    findings.append(
                        Finding(
                            title=f"Potential subdomain takeover: {fqdn}",
                            severity=Severity.HIGH,
                            description=(
                                f"'{fqdn}' has a CNAME pointing to '{target}', "
                                f"but '{target}' does not resolve (NXDOMAIN). "
                                "This may allow an attacker to register the target domain and take over this subdomain."
                            ),
                            recommendation=(
                                f"Remove the CNAME record for '{fqdn}' if the service is no longer in use, "
                                "or restore the target service."
                            ),
                            details={"subdomain": fqdn, "cname_target": target},
                        )
                    )
                except (dns.exception.DNSException, Exception):
                    pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.DNSException, Exception):
            pass

    return findings


class DNSCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dns"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        dns_config = self.config.get("dns", {})
        check_spf = dns_config.get("check_spf", True)
        check_dmarc_flag = dns_config.get("check_dmarc", True)

        # For IP addresses: run a PTR reverse lookup instead of domain checks
        is_ip = False
        try:
            socket.inet_aton(host)
            is_ip = True
        except socket.error:
            pass

        if is_ip:
            ptr_hostname = ""
            try:
                rev_name = dns.reversename.from_address(host)
                _res = dns.resolver.Resolver()
                _res.timeout = 5
                _res.lifetime = 10
                ptr_answers = _res.resolve(rev_name, "PTR")
                ptr_hostname = str(ptr_answers[0]).rstrip(".")
            except Exception:
                pass

            if ptr_hostname:
                description = f"Reverse DNS (PTR) lookup for {host} resolved to '{ptr_hostname}'."
            else:
                description = (
                    f"No PTR record found for {host}. "
                    "A missing reverse DNS record can indicate unmanaged infrastructure "
                    "or misconfigured DNS zones."
                )
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=True,
                findings=[Finding(
                    title="Reverse DNS (PTR)" + (f": {ptr_hostname}" if ptr_hostname else ": no record"),
                    severity=Severity.INFO,
                    description=description,
                    details={"ip": host, "ptr_hostname": ptr_hostname or None, "has_ptr": bool(ptr_hostname)},
                )],
                metadata={"ip": host, "ptr_hostname": ptr_hostname, "skipped_domain_checks": True},
            )

        domain = _get_domain(host)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        findings: List[Finding] = []

        if check_spf:
            spf_finding = _check_spf(domain, resolver)
            findings.append(spf_finding)

        if check_dmarc_flag:
            dmarc_findings = _check_dmarc(domain, resolver)
            findings.extend(dmarc_findings)

        zone_transfer_finding = _attempt_zone_transfer(domain, resolver)
        if zone_transfer_finding:
            findings.append(zone_transfer_finding)
        else:
            findings.append(
                Finding(
                    title="Zone transfer (AXFR) not allowed",
                    severity=Severity.INFO,
                    description=f"DNS zone transfer attempt for '{domain}' was rejected by all nameservers.",
                )
            )

        takeover_findings = _check_cname_takeover(domain, resolver)
        findings.extend(takeover_findings)

        findings.append(
            Finding(
                title="DNS security checks completed",
                severity=Severity.INFO,
                description=f"DNS security analysis completed for {domain}.",
                details={"domain": domain},
            )
        )

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={"domain": domain},
        )
