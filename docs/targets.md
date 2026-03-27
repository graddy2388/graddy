# Managing Targets

A **target** is anything you want Network Bot to scan — a hostname, IP address, or CIDR subnet.

---

## Target YAML Format

```yaml
targets:
  - name: "My Web Server"
    host: "example.com"
    group: "Production"
    tags: ["web", "external"]
    checks: ["port_scan", "ssl", "http", "dns", "vuln", "exposed_paths", "cipher"]
    ports: [80, 443, 8080]

  - name: "Internal Server"
    host: "192.168.1.100"
    group: "Internal"
    tags: ["internal", "linux"]
    checks: ["port_scan", "vuln"]
    ports: [22, 80, 443, 3306, 5432]

  - name: "Mail Server"
    host: "mail.example.com"
    group: "Production"
    tags: ["mail", "external"]
    checks: ["port_scan", "smtp", "ssl"]
    ports: [25, 587, 465, 443]
    smtp_ports: [25, 587, 465]

  - name: "Internal Subnet"
    host: "10.0.1.0/28"
    group: "Internal"
    checks: ["port_scan"]
    ports: [80, 443, 8080]
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name |
| `host` | Yes | Hostname, IP, or CIDR subnet |
| `group` | No | Group name (auto-created on import) |
| `tags` | No | Tag names (auto-created on import) |
| `checks` | No | Check modules to run (default: all) |
| `ports` | No | TCP ports to scan |
| `smtp_ports` | No | SMTP ports (default: 25, 587, 465) |

---

## CIDR Subnet Support

Point a target at an entire subnet and every host is scanned:

```yaml
- name: "DMZ Subnet"
  host: "10.0.1.0/24"
  checks: ["port_scan"]
  ports: [22, 80, 443]
```

---

## Hostname Resolution

When you add or edit a target, Network Bot automatically resolves:
- **IP → Hostname** (reverse DNS)
- **Hostname → IP** (forward DNS)

The Targets page shows both. Click the teal refresh icon on any target row to re-resolve on demand.

---

## Related Pages

- [Groups & Tags](groups-and-tags.md)
- [Security Checks Reference](checks.md)
- [CLI Reference](cli.md)
