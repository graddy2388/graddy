# CLI Reference

```
viridis                  Start web GUI (default)
viridis serve            Start web GUI (explicit)
viridis scan             Headless scan mode
```

---

## Global Flags

```
--config FILE    Path to YAML config file
--verbose        Enable DEBUG logging
--version        Print version and exit
```

---

## `viridis serve`

```
--host HOST      Bind address (default: 0.0.0.0)
--port PORT      Port (default: 8080)
--targets FILE   YAML targets file to import on first run
--reload         Auto-reload on code changes (dev only)
```

### Examples

```bash
viridis serve
viridis serve --port 9090
viridis serve --targets config/targets.yaml
viridis serve --reload
```

---

## `viridis scan`

```
--target HOST    Scan a single host
--targets FILE   YAML targets file
--once           Run once and exit (no scheduler)
--output DIR     Report output directory
--format FORMAT  json | html | both
```

### Examples

```bash
viridis scan --target example.com --once
viridis scan --targets config/targets.yaml --once --format json
viridis scan --targets config/targets.yaml   # runs on schedule
```

---

## Scheduler Behaviour

Without `--once`, the scanner runs immediately then repeats every `scheduler.interval_minutes` (default 60). Press Ctrl+C to stop.
