# Alerting

Network Bot can send notifications when a scan produces HIGH or CRITICAL findings. Two channels: **Microsoft Teams** and **Email**.

---

## Microsoft Teams Setup

1. In Teams, open the channel you want alerts in.
2. Click **...** → **Connectors** → **Incoming Webhook** → **Configure**.
3. Copy the webhook URL.

```yaml
alerting:
  enabled: true
  min_severity: "high"
  teams:
    enabled: true
    webhook_url: "https://outlook.office.com/webhook/YOUR_WEBHOOK_URL"
```

---

## Email Setup

### Office 365

```yaml
alerting:
  enabled: true
  email:
    enabled: true
    smtp_host: "smtp.office365.com"
    smtp_port: 587
    smtp_user: "you@yourorg.com"
    smtp_password: "your-password"
    from_addr: "network-bot@yourorg.com"
    to_addrs:
      - "security@yourorg.com"
    use_tls: true
```

### Gmail

```yaml
alerting:
  enabled: true
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "you@gmail.com"
    smtp_password: "your-app-password"
    from_addr: "you@gmail.com"
    to_addrs:
      - "security@yourorg.com"
    use_tls: true
```

---

## Severity Threshold

| `min_severity` | Alerts fire for |
|----------------|---------------|
| `critical` | CRITICAL only |
| `high` | HIGH and CRITICAL |
| `medium` | MEDIUM and above |
| `low` | LOW and above |
