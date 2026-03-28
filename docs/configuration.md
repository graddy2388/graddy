# Configuration

Network Bot ships with sensible defaults in `config/default.yaml`. You only need to include keys you want to override.

---

## How Configuration Works

On startup the bot loads `config/default.yaml`. If you supply `--config myconfig.yaml`, your file is merged on top of the defaults.

```bash
network-bot --config /etc/network-bot/myconfig.yaml
```

---

## Full Default Configuration

```yaml
scheduler:
  interval_minutes: 60
  enabled: true

scanning:
  port_timeout: 3
  common_ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
  max_workers: 50

ssl:
  warn_expiry_days: 30
  check_weak_ciphers: true

http:
  timeout: 10
  follow_redirects: true
  user_agent: "NetworkBot/1.0 Security Scanner"

dns:
  check_spf: true
  check_dmarc: true

reporting:
  output_dir: "reports"
  formats: ["json", "html"]
  keep_last: 10

logging:
  level: "INFO"
  file: "logs/network_bot.log"

alerting:
  enabled: false
  min_severity: "high"
  teams:
    enabled: false
    webhook_url: ""
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    smtp_user: ""
    smtp_password: ""
    from_addr: ""
    to_addrs: []
    use_tls: true

exposed_paths:
  timeout: 5
  max_paths: 50

smtp:
  timeout: 10
  test_relay: false

cipher:
  timeout: 5

web:
  db_path: "data/network_bot.db"
  host: "0.0.0.0"
  port: 8080
  secret_key: "change-me-in-production"
```

---

## Key Options

| Section | Option | Default | Description |
|---------|--------|---------|-------------|
| `scheduler` | `interval_minutes` | 60 | Scan repeat interval |
| `ssl` | `warn_expiry_days` | 30 | Days before cert expiry to raise HIGH |
| `alerting` | `enabled` | false | Master alerting switch |
| `alerting` | `min_severity` | high | Minimum severity to alert on |
| `web` | `secret_key` | *(change me)* | Session signing secret |
