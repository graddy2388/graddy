# Configuration

Network Bot ships with sensible defaults in `config/default.yaml`. You rarely need to change anything to get started, but this page documents every available option.

---

## How Configuration Works

On startup the bot loads `config/default.yaml` from inside the package. Supply `--config myconfig.yaml` to override specific values — you only need to include keys you want to change.

```bash
network-bot --config /etc/network-bot/myconfig.yaml
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `NETWORK_BOT_ROOT` | Base directory for resolving `db_path`, `output_dir`, and `logs/`. Set to `/app` automatically in Docker. |

---

## Section Reference

### `scheduler`

| Option | Default | Description |
|--------|---------|-------------|
| `interval_minutes` | `60` | How often the scheduler runs a full scan cycle. |
| `enabled` | `true` | Set to `false` to run once then exit. |

### `scanning`

| Option | Default | Description |
|--------|---------|-------------|
| `port_timeout` | `3` | Seconds to wait for TCP connect. |
| `common_ports` | *(see default.yaml)* | Default ports when target has no `ports` list. |
| `max_workers` | `50` | Max concurrent scan threads per target. |

### `ssl`

| Option | Default | Description |
|--------|---------|-------------|
| `warn_expiry_days` | `30` | Certs expiring within this many days → HIGH finding. |
| `check_weak_ciphers` | `true` | Test for TLS 1.0 / TLS 1.1 support. |

### `http`

| Option | Default | Description |
|--------|---------|-------------|
| `timeout` | `10` | HTTP request timeout in seconds. |
| `follow_redirects` | `true` | Follow HTTP redirects. |
| `user_agent` | `NetworkBot/1.0 Security Scanner` | User-Agent header. |

### `dns`

| Option | Default | Description |
|--------|---------|-------------|
| `check_spf` | `true` | Check for SPF TXT record. |
| `check_dmarc` | `true` | Check for DMARC record. |
| `check_dnssec` | `false` | DNSSEC validation (reserved). |

### `alerting`

See the [Alerting guide](alerting.md) for full setup.

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Master switch. |
| `min_severity` | `"high"` | Only alert on findings at this level or above. |
| `teams.webhook_url` | `""` | Teams Incoming Webhook URL. |
| `email.smtp_host` | `""` | SMTP server hostname. |
| `email.smtp_port` | `587` | SMTP port. |
| `email.from_addr` | `""` | Sender address. |
| `email.to_addrs` | `[]` | List of recipient addresses. |

### `web`

| Option | Default | Description |
|--------|---------|-------------|
| `db_path` | `"data/network_bot.db"` | SQLite database path. |
| `host` | `"0.0.0.0"` | Bind address. |
| `port` | `8080` | Listen port. |
| `secret_key` | `"change-me-in-production"` | Session signing key — change this! |

---

## Minimal Override Example

```yaml
scheduler:
  interval_minutes: 120

ssl:
  warn_expiry_days: 14

alerting:
  enabled: true
  min_severity: "high"
  teams:
    enabled: true
    webhook_url: "https://outlook.office.com/webhook/YOUR_URL"

web:
  secret_key: "your-long-random-secret"
```

---

## Related Pages

- [Alerting](alerting.md)
- [CLI Reference](cli.md)
- [Deployment Guide](deployment.md)
