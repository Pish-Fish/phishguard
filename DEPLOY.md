# Deploy PhishGuard (full site + all tools)

PhishGuard runs as a **Docker** container: Flask + Gunicorn + Nmap + your Python tools. The UI and API share the same origin, so no frontend changes are needed after deploy.

## Prerequisites

1. Copy `.env.example` to `.env` locally and set at least:
   - `ANTHROPIC_API_KEY` — required for AI verdict/summary
2. On the host (not in git), set the same variables in the platform’s **Environment** / **Secrets** UI.
3. Optional: `PHISHTANK_API_KEY`, `PHISHTANK_USE_LOCAL`, phishing score thresholds (see `.env.example`).

`NMAP_PATH` defaults to `/usr/bin/nmap` inside the container — you do not need to set it unless you use a custom image.

---

## Test locally with Docker

```bash
# From the project root (with .env present)
docker compose up --build
```

Open http://localhost:8080 and run a full scan.

---

## Railway

1. Push this repo to GitHub.
2. [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub** → select the repo.
3. Railway detects `Dockerfile` / `railway.toml` automatically.
4. **Variables** → add `ANTHROPIC_API_KEY` (and any optional keys from `.env.example`).
5. Deploy. Copy the public URL from **Settings → Networking → Generate Domain**.

No extra build command needed.

---

## Render

1. Push to GitHub.
2. [render.com](https://render.com) → **New** → **Blueprint** → connect the repo (uses `render.yaml`),  
   **or** **New Web Service** → **Docker** → point at this repo.
3. **Environment** → add `ANTHROPIC_API_KEY` (marked secret).
4. Deploy.

**Note:** Render’s **free** web tier limits HTTP requests to about **100 seconds**. Sooty’s first run can take longer (large feed download). Use a **paid** instance or expect Sooty to time out on free tier; other tools (WHOIS, DNS, SSL, port scan, phishing_catcher, AI) usually finish within the limit.

---

## Fly.io

```bash
fly auth login
fly launch          # accept Dockerfile, app name, region
fly secrets set ANTHROPIC_API_KEY=sk-your-key
fly deploy
```

`fly.toml` sets a **900s** proxy timeout for long Sooty runs. Use at least the **1GB** VM in the config (adjust if scans fail with OOM).

---

## VPS (Ubuntu)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
git clone <your-repo-url> phishguard && cd phishguard
cp .env.example .env   # edit with your keys
docker compose up -d --build
```

Put **Caddy** or **nginx** in front for HTTPS:

```text
your-domain.com  →  reverse proxy  →  localhost:8080
```

---

## Environment variables (production)

| Variable | Required | Notes |
|----------|----------|--------|
| `ANTHROPIC_API_KEY` | Yes (for AI) | Anthropic console |
| `NMAP_PATH` | Auto in Docker | `/usr/bin/nmap` |
| `PORT` | Set by platform | Do not hardcode; Gunicorn reads it |
| `PHISHTANK_API_KEY` | No | Improves Sooty when registration is open |
| `PHISHTANK_APP_NAME` | No | Default `PhishGuard` |
| `GUNICORN_TIMEOUT` | No | Default `900` (Sooty) |
| `WEB_CONCURRENCY` | No | Default `1` worker (heavy scans) |

Never commit `.env` to git.

---

## Security (public internet)

Anyone with the URL can trigger scans. For a university demo, consider:

- Password-protecting the site at the reverse proxy, or
- Deploying on a private network / VPN, or
- Adding rate limiting later.

Port scans and third-party APIs may be restricted by some hosts’ acceptable-use policies.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Port scan: “Nmap not found” | Set `NMAP_PATH=/usr/bin/nmap` or redeploy Docker image |
| AI errors | Set `ANTHROPIC_API_KEY` in platform secrets, redeploy |
| Sooty timeout | Use Fly/Railway paid tier or VPS; increase `GUNICORN_TIMEOUT` |
| 502 on long scan | Increase platform HTTP timeout (Fly `response_timeout`; Render plan limits) |

Logs: `docker compose logs -f` locally, or your platform’s log viewer.
