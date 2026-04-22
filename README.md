# Viridis (Network Bot)

Viridis is an autonomous network security scanner and red-team support platform with both a CLI and a web GUI. It continuously scans hosts, domains, and CIDR ranges to identify misconfigurations, weak TLS settings, exposed sensitive files, and service/banner-based vulnerabilities.

## Key capabilities

- Port and service scanning with banner analysis
- SSL/TLS posture checks (expiry, weak protocols/ciphers, chain issues)
- HTTP header and exposed path checks
- DNS and SMTP security checks
- CVE matching for known software versions
- Real-time scan status and findings in the web interface
- Grouping/tagging of targets and scheduled scans
- Alerting integrations (email and Microsoft Teams)

## Quick start (Docker)

```bash
docker compose up -d
```

Then open `http://localhost:8088`.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
viridis --help
```

## Repository layout

- `src/viridis/` — core scanner, checks, scheduler, and reporting
- `src/viridis/web/` — FastAPI web app, templates, API routes, DB helpers
- `config/` — default and example target configuration files
- `wiki/` — project documentation (installation, configuration, checks, GUI usage)

## Documentation

Detailed docs are available under `wiki/`, starting with:

- `wiki/Home.md`
- `wiki/Installation-and-Setup.md`
- `wiki/Configuration.md`
- `wiki/Security-Checks-Reference.md`
