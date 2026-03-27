# Network Bot — Home

Network Bot is an autonomous network security scanner with a polished web GUI. Point it at your hosts, subnets, or mail servers and it will continuously probe for misconfigurations, weak TLS, exposed secrets, known CVEs, DNS spoofing risks, and more — then surface everything as colour-coded findings you can filter, export, and act on.

---

## Features

- Port scanning — TCP connect scan with banner grabbing and dangerous-port detection
- SSL/TLS analysis — cert expiry, self-signed detection, weak protocol versions, key size, chain validation
- HTTP security headers — HSTS, CSP, X-Frame-Options, cookie flags, HTTP→HTTPS redirect
- DNS & email security — SPF, DMARC, zone transfer (AXFR), subdomain takeover
- Vulnerability matching — banner-based CVE detection for OpenSSH, Apache, nginx, OpenSSL, vsftpd, Exim, and more
- SMTP checks — STARTTLS enforcement, open relay, cleartext AUTH, TLS quality
- Exposed path scanning — `.env`, `.git`, phpinfo, admin panels, backup archives, database configs
- Cipher suite probing — NULL, EXPORT, RC4, DES, 3DES, MD5-MAC, anonymous DH detection
- Live scan progress — WebSocket-powered real-time findings feed in the browser
- Groups & Tags — organise targets and scan subsets in one click
- Alerting — Microsoft Teams and email notifications for HIGH/CRITICAL findings
- Docker-first — single image, named volumes, health check included
- CIDR subnet support — scan entire subnets (e.g. `10.0.1.0/28`) from one target entry

---

## Quick Start

```bash
docker compose up -d
# Open http://localhost:8088
```

---

## Wiki Pages

| Page | What it covers |
|------|---------------|
| [Installation & Setup](installation.md) | Docker, pip install, development mode |
| [Configuration](configuration.md) | All config options, environment variables |
| [Managing Targets](targets.md) | YAML format, web GUI, CIDR subnets |
| [Security Checks Reference](checks.md) | Every check module documented |
| [Groups & Tags](groups-and-tags.md) | Organising targets, scanning subsets |
| [Alerting](alerting.md) | Teams and email setup |
| [Web GUI Guide](web-gui.md) | Page-by-page walkthrough |
| [CLI Reference](cli.md) | All commands and flags |
| [Deployment Guide](deployment.md) | Docker Compose, Portainer, reverse proxy, backups |
