# Network Bot — Home

Network Bot is an autonomous network security scanner with a built-in web GUI. Point it at your hosts, subnets, or mail servers and it will continuously check for misconfigurations, weak TLS, dangerous open ports, exposed sensitive files, missing email authentication records, and known software vulnerabilities — then surface everything in a clean dashboard with colour-coded severity findings.

Everything runs from a single Docker image (or a plain `pip install`). There are no external services to set up: the database is SQLite, reports are written to disk, and alerts go out over Microsoft Teams webhooks or SMTP email. The scheduler wakes up automatically every 60 minutes (configurable) so your findings stay fresh without any manual intervention.

---

## Features

- 🔍 **Port scanning** — TCP connect scan with banner grabbing and dangerous-port detection
- 🔒 **SSL/TLS analysis** — cert expiry, self-signed detection, weak protocol versions, key size, chain validation
- 🌐 **HTTP security headers** — HSTS, CSP, X-Frame-Options, cookie flags, HTTP→HTTPS redirect
- 📧 **DNS & email security** — SPF, DMARC, zone transfer (AXFR), subdomain takeover
- 🦠 **Vulnerability matching** — banner-based CVE detection for OpenSSH, Apache, nginx, OpenSSL, vsftpd, Exim, and more
- 📬 **SMTP checks** — STARTTLS enforcement, open relay, cleartext AUTH, TLS quality
- 🗂️ **Exposed path scanning** — `.env`, `.git`, phpinfo, admin panels, backup archives, database configs
- 🔑 **Cipher suite probing** — NULL, EXPORT, RC4, DES, 3DES, MD5-MAC detection
- 📊 **Live scan progress** — WebSocket-powered real-time findings feed in the browser
- 🏷️ **Groups & Tags** — organise targets and scan subsets in one click
- 🔔 **Alerting** — Microsoft Teams and email notifications for HIGH/CRITICAL findings
- 🐳 **Docker-first** — single image, named volumes, health check included

---

## Quick Start

Three commands and you're running:

```bash
curl -o docker-compose.yml https://raw.githubusercontent.com/graddy2388/graddy/main/docker-compose.yml
docker compose up -d
# Open http://localhost:8080
```

That's it. The web GUI will be available immediately. Add your first target through the UI or drop a `targets.yaml` into the `./config/` folder — it will be imported automatically on first run.

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
