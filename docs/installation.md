# Installation & Setup

Network Bot requires **Python 3.10 or newer**. If you're using Docker you don't need Python on the host at all — the image bundles everything.

---

## Option 1 — Docker (Recommended)

Docker is the easiest and most isolated way to run Network Bot. You get automatic restarts, named volumes for persistent data, and a health check out of the box.

**Requirements:** Docker Engine 20+ and Docker Compose v2 (the `docker compose` plugin, not the old `docker-compose` binary).

### docker-compose.yml

Save this file (or use the one already in the repo):

```yaml
services:
  network-bot:
    image: ghcr.io/graddy2388/graddy:latest
    ports:
      - "8080:8080"
    volumes:
      - netbot-data:/app/data      # SQLite database and scan history
      - netbot-logs:/app/logs      # Log files
      - ./config:/app/config       # Your targets.yaml and config overrides
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

### Start it

```bash
docker compose up -d
```

Open **http://localhost:8080** in your browser.

### Portainer paste-and-deploy

If you manage containers through Portainer:

1. In Portainer, go to **Stacks** → **Add stack**.
2. Give the stack a name (e.g. `network-bot`).
3. Choose **Web editor** and paste the `docker-compose.yml` content above.
4. Scroll down and click **Deploy the stack**.
5. Wait a few seconds for the container to start, then navigate to **http://\<your-host\>:8080**.

To supply a `targets.yaml` on first run, create a `config/` directory next to the stack file before deploying, or bind-mount a specific file:

```yaml
    volumes:
      - netbot-data:/app/data
      - netbot-logs:/app/logs
      - /path/to/your/config:/app/config
```

---

## Option 2 — pip install

If you prefer running Network Bot directly on a host with Python 3.10+:

```bash
pip install .
network-bot
```

The web GUI will start on **http://0.0.0.0:8080** by default.

To supply a targets file on first run:

```bash
network-bot serve --targets config/targets.example.yaml
```

To use a custom config file:

```bash
network-bot --config /etc/network-bot/config.yaml
```

---

## Option 3 — Development Mode

Clone the repository and install in editable mode so code changes are picked up without reinstalling:

```bash
git clone https://github.com/graddy2388/graddy.git
cd graddy
pip install -e .
network-bot serve --reload
```

The `--reload` flag passes auto-reload through to uvicorn, so saving a Python file restarts the server automatically. This is useful when developing new check modules or modifying the web app.

---

## Requirements Summary

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.10 | 3.11+ recommended |
| Docker Engine | 20.10 | Only if using Docker |
| Docker Compose | v2 (plugin) | `docker compose`, not `docker-compose` |
| RAM | 256 MB | More if scanning many targets simultaneously |
| Disk | 100 MB | Plus space for SQLite DB and reports |
| Network | Outbound TCP | Scanner needs to reach targets |

### Python dependencies (installed automatically)

`requests`, `pyyaml`, `dnspython`, `schedule`, `rich`, `jinja2`, `cryptography`, `fastapi`, `uvicorn`, `python-multipart`, `aiofiles`

---

## Next Steps

- [Configure the scanner](configuration.md) — scheduler intervals, SSL thresholds, alerting
- [Add your targets](targets.md) — via YAML or the web GUI
- [Set up alerting](alerting.md) — Teams webhook or email
