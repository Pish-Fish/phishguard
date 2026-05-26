# PhishGuard

University phishing detection system: WHOIS, DNS, Nmap port scan, SSL check, Sooty, phishing_catcher, and Anthropic-powered AI summary — from one web UI.

## Run locally (development)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
copy .env.example .env          # add ANTHROPIC_API_KEY and NMAP_PATH
python app.py
```

Open http://localhost:5000

## Run locally (production-like Docker)

```bash
docker compose up --build
```

Open http://localhost:8080

## Deploy online (all features)

See **[DEPLOY.md](DEPLOY.md)** for Railway, Render, Fly.io, and VPS steps.

Quick path: push to GitHub → connect repo on **Railway** or **Render** → set `ANTHROPIC_API_KEY` in environment variables → deploy.
