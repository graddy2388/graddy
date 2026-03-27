# Installation & Setup

Network Bot requires **Python 3.10 or newer**. If you're using Docker you don't need Python on the host at all.

---

## Option 1 — Docker (Recommended)

### docker-compose.yml

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

### Start it

```bash
docker compose up -d
```

Open **http://your-host:8088** in your browser.

### Portainer paste-and-deploy

1. In Portainer, go to **Stacks** → **Add stack**.
2. Give the stack a name (e.g. `network-bot`).
3. Choose **Web editor** and paste the `docker-compose.yml` content above.
4. Click **Deploy the stack**.
5. Navigate to `http://<your-host>:8088`.

---

## Option 2 — pip install

```bash
pip install .
network-bot
```

The web GUI starts on **http://0.0.0.0:8080**.

---

## Option 3 — Development Mode

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
| Python | 3.10 |
| Docker Engine | 20.10 (if using Docker) |
| RAM | 256 MB |
| Network | Outbound TCP to targets |
