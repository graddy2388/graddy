# Deployment Guide

---

## Docker Compose (Recommended)

```yaml
services:
  network-bot:
    image: ghcr.io/graddy2388/graddy:latest
    ports:
      - "8088:8080"
    volumes:
      - netbot-data:/app/data
      - netbot-logs:/app/logs
    restart: unless-stopped

volumes:
  netbot-data:
  netbot-logs:
```

```bash
docker compose up -d
```

---

## Portainer

1. **Stacks** → **Add stack** → **Web editor**
2. Paste the compose YAML above
3. Click **Deploy the stack**
4. Navigate to `http://<your-host>:8088`

**Updating:** Open the stack → **Pull and redeploy**.

---

## Persistent Data

| Volume | Contents |
|--------|----------|
| `netbot-data` | SQLite database (`network_bot.db`) |
| `netbot-logs` | Log file |

### Backup

```bash
docker compose cp network-bot:/app/data/network_bot.db ./backup-$(date +%Y%m%d).db
```

---

## Reverse Proxy

### Nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:8088;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

---

## Security Tips

- Set `web.secret_key` to a random string: `openssl rand -hex 32`
- Restrict access with your reverse proxy (basic auth, SSO)
- Run `docker compose pull && docker compose up -d` regularly for updates
