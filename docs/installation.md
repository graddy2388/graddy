# Installation & Setup

Network Bot requires **Python 3.10 or newer**. If you're using Docker you don't need Python on the host at all — the image bundles everything.

---

## Option 1 — Docker (Recommended)

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

```bash
docker compose up -d
# Open http://localhost:8080
```

### Portainer paste-and-deploy

1. **Stacks** → **Add stack**
2. Paste the YAML above into the Web editor
3. Click **Deploy the stack**
4. Navigate to `http://<your-host>:8080`

> **Port conflict?** Change `8080:8080` to e.g. `8088:8080` on the left side only.

---

## Option 2 — pip install

```bash
pip install .
network-bot
```

GUI starts on **http://0.0.0.0:8080**.

---

## Option 3 — Development

```bash
git clone https://github.com/graddy2388/graddy.git
cd graddy
pip install -e .
network-bot serve --reload
```

---

## Requirements

| Requirement | Minimum |
|-------------|--------|
| Python | 3.10+ |
| Docker Engine | 20.10+ (if using Docker) |
| RAM | 256 MB |
| Network | Outbound TCP to targets |

---

## Next Steps

- [Configure the scanner](configuration.md)
- [Add your targets](targets.md)
- [Set up alerting](alerting.md)
