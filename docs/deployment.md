# Deployment Guide

---

## Docker Compose / Portainer

```yaml
services:
  network-bot:
    image: ghcr.io/graddy2388/graddy:latest
    ports:
      - "8080:8080"
    volumes:
      - netbot-data:/app/data
      - netbot-logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  netbot-data:
  netbot-logs:
```

### Portainer Steps

1. **Stacks** → **Add stack**
2. Paste the YAML above
3. Click **Deploy the stack**
4. Wait 10–15s for health check → navigate to `http://<host>:8080`

> **Port conflict?** Change `8080:8080` to e.g. `8088:8080`. Don't change the right side.

---

## Updating

```bash
docker compose pull && docker compose up -d
```

In Portainer: **Pull and redeploy**. Named volumes (database, logs) are untouched.

---

## Persistent Data

| Volume | Contents |
|--------|----------|
| `netbot-data` | `network_bot.db` — SQLite with all targets, scans, findings |
| `netbot-logs` | `network_bot.log` |

### Backup

```bash
docker compose cp network-bot:/app/data/network_bot.db ./backup-$(date +%Y%m%d).db
```

### Restore

```bash
docker compose stop
docker compose cp ./backup.db network-bot:/app/data/network_bot.db
docker compose start
```

---

## Reverse Proxy

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name netbot.yourorg.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Required for WebSocket live scan progress
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

### Nginx Proxy Manager

- Forward port: `8080`
- Enable **Websockets Support** (required for live scan progress)

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.netbot.rule=Host(`netbot.yourorg.com`)"
  - "traefik.http.routers.netbot.entrypoints=websecure"
  - "traefik.http.routers.netbot.tls.certresolver=letsencrypt"
  - "traefik.http.services.netbot.loadbalancer.server.port=8080"
```

---

## Security Hardening

- **Change the secret key** — set `web.secret_key` in your config: `openssl rand -hex 32`
- **Restrict access** — bind to localhost only: `127.0.0.1:8080:8080`
- **Add authentication** — Network Bot has no built-in login; use your reverse proxy (NPM access lists, Traefik ForwardAuth, Nginx `auth_basic`)
- **Keep updated** — run `docker compose pull && docker compose up -d` regularly

---

## Related Pages

- [Installation & Setup](installation.md)
- [Configuration](configuration.md)
- [CLI Reference](cli.md)
