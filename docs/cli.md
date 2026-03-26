# CLI Reference

Network Bot is invoked via the `network-bot` command. Running it with no arguments starts the web GUI on port 8080.

---

## Command Overview

```
network-bot                     Start web GUI (default)
network-bot serve               Start web GUI (explicit)
network-bot scan                Run headless CLI scan
```

---

## Global Flags

```
--config FILE        YAML config file to merge over defaults.
--verbose            Enable DEBUG-level logging.
--version            Print version and exit.
```

---

## `network-bot serve`

```
Options:
  --host HOST         Bind address. Default: 0.0.0.0
  --port PORT         Port. Default: 8080
  --targets FILE      YAML targets to import on first run (ignored after that).
  --reload            Auto-reload on file changes (development only).
```

### Examples

```bash
network-bot serve
network-bot serve --port 9090
network-bot serve --targets config/targets.yaml
network-bot --config myconfig.yaml serve --targets targets.yaml
```

---

## `network-bot scan`

Headless scan — no web server. Writes JSON/HTML reports to disk.

```
Options:
  --target HOST       Scan a single host (all checks).
  --targets FILE      YAML targets file.
  --once              Run once and exit (skip scheduler).
  --output DIR        Report output directory. Default: reports/
  --format FORMAT     json | html | both. Default: both
```

### Examples

```bash
network-bot scan --target example.com --once
network-bot scan --targets config/targets.yaml --once --format json
network-bot scan --targets config/targets.yaml          # repeating scheduler
network-bot --config prod.yaml scan --targets targets.yaml --once
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (no targets, config error, etc.) |

---

## Related Pages

- [Configuration](configuration.md)
- [Managing Targets](targets.md)
- [Deployment Guide](deployment.md)
