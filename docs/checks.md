# Security Checks Reference

Network Bot includes eight check modules. Each module is independent — you pick which ones run per target.

---

## Severity Reference

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Immediate risk. Fix now. |
| **HIGH** | Serious weakness. Fix soon. |
| **MEDIUM** | Notable misconfiguration. Schedule a fix. |
| **LOW** | Minor issue. Fix when convenient. |
| **INFO** | Informational only. |

---

## `port_scan` — TCP Port Scan

Concurrent TCP connect scan with banner grabbing.

**Dangerous ports flagged:** Telnet (23) CRITICAL, FTP (21) HIGH, RDP (3389) HIGH, SMB (445) HIGH, Redis (6379) HIGH, MongoDB (27017) HIGH, Elasticsearch (9200) HIGH.

---

## `ssl` — SSL/TLS Certificate Analysis

Checks cert expiry, self-signed, SAN, RSA key size, TLS 1.0/1.1 support, chain validation.

**Key findings:** Expired cert (CRITICAL), expiring within warn_expiry_days (HIGH), self-signed (HIGH), TLS 1.0/1.1 supported (HIGH each).

---

## `http` — HTTP Security Headers

Checks HSTS (HIGH if missing), CSP (MEDIUM), X-Frame-Options (MEDIUM), X-Content-Type-Options (LOW), Referrer-Policy (LOW), cookie Secure/HttpOnly flags, HTTP→HTTPS redirect.

---

## `dns` — DNS & Email Security

Checks SPF, DMARC, zone transfer (AXFR), subdomain takeover on common subdomains. Skipped for bare IP targets.

**Key findings:** Zone transfer allowed (CRITICAL), DMARC missing (HIGH), SPF +all (HIGH).

---

## `vuln` — Banner-Based Vulnerability Matching

Matches service banners against known CVEs: OpenSSH, Apache, nginx, OpenSSL, vsftpd (backdoor → CRITICAL), ProFTPD, Exim. Also tests anonymous FTP and open HTTP proxies.

---

## `smtp` — SMTP Mail Server Audit

Checks STARTTLS on ports 25/587, AUTH methods before STARTTLS, open relay, TLS version quality, banner version disclosure.

---

## `exposed_paths` — Sensitive File & Path Probe

Probes for `.env` (CRITICAL), `.git/HEAD` (CRITICAL), `wp-config.php` (CRITICAL), `phpinfo.php` (HIGH), `/admin` (MEDIUM), and 20+ more paths.

---

## `cipher` — Cipher Suite Probing

Tests for NULL (CRITICAL), EXPORT (CRITICAL), RC4 (CRITICAL), anonymous DH (CRITICAL), DES (HIGH), 3DES (HIGH), MD5 MAC (HIGH).

---

## Related Pages

- [Managing Targets](targets.md)
- [Web GUI Guide](web-gui.md)
- [Configuration](configuration.md)
