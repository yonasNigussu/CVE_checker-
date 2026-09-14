# CISA KEV Vendor Watch Dashboard — MVP

A small FastAPI + SQLite dashboard that polls the CISA Known Exploited Vulnerabilities JSON feed, stores CVEs, filters them by a configurable vendor watchlist, and sends optional Telegram/email alerts for newly observed matching CVEs.

## Features
- Automatic CISA KEV polling (default every 15 minutes)
- Initial full sync
- Configurable vendor watchlist from the web UI
- Add/remove vendors without changing code
- Cisco, Fortinet, and Check Point are preloaded
- Search/filter CVEs
- Dashboard counts and "new" indicators
- Optional Telegram and SMTP email notifications
- SQLite persistence
- Docker support

## Run locally

Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # Windows
# or: cp .env.example .env

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## Run with Docker

```bash
cp .env.example .env
docker compose up -d --build
```

Open http://127.0.0.1:8000

## Notifications

Telegram:
1. Create a bot with BotFather.
2. Put the token in TELEGRAM_BOT_TOKEN.
3. Put the destination chat ID in TELEGRAM_CHAT_ID.

Email:
Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM and SMTP_TO.

Notifications are only sent when a newly downloaded CVE matches a currently watched vendor. Existing records are not re-alerted on every poll.

## Vendor matching

The app matches the CISA `vendorProject` field against your vendor list case-insensitively. For example, adding `Palo Alto Networks` will match CISA records whose `vendorProject` is `Palo Alto Networks`.

## Security note

This is an MVP. Before production use, put it behind your organization's authentication/SSO, add CSRF protection and role-based access, use PostgreSQL, protect secrets, and restrict administrative endpoints.
