# CLI Reference

```
network-bot                  Start web GUI (default)
network-bot serve            Start web GUI (explicit)
network-bot scan             Headless scan mode
```

---

## Global Flags

```
--config FILE    Path to YAML config file
--verbose        Enable DEBUG logging
--version        Print version and exit
```

---

## `network-bot serve`

```
--host HOST      Bind address (default: 0.0.0.0)
--port PORT      Port (default: 8080)
--targets FILE   YAML targets file to import on first run
--reload         Auto-reload on code changes (dev only)
```

### Examples

```bash
network-bot serve
network-bot serve --port 9090
network-bot serve --targets config/targets.yaml
network-bot serve --reload
```

---

## `network-bot scan`

```
--target HOST    Scan a single host
--targets FILE   YAML targets file
--once           Run once and exit (no scheduler)
--output DIR     Report output directory
--format FORMAT  json | html | both
```

### Examples

```bash
network-bot scan --target example.com --once
network-bot scan --targets config/targets.yaml --once --format json
network-bot scan --targets config/targets.yaml   # runs on schedule
```

---

## Scheduler Behaviour

Without `--once`, the scanner runs immediately then repeats every `scheduler.interval_minutes` (default 60). Press Ctrl+C to stop.
