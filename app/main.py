import os
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
import smtplib
from fastapi.staticfiles import StaticFiles
import requests
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./kev.db")
if DATABASE_URL.startswith("sqlite:///./"):
    DATABASE_URL = "sqlite:///" + os.path.join(BASE_DIR, DATABASE_URL[len("sqlite:///./"):])

CISA_FEED_URL = os.getenv(
    "CISA_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
POLL_MINUTES = int(os.getenv("POLL_MINUTES", "15"))

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), unique=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    vendor = Column(String(200), nullable=False, index=True)
    product = Column(Text, default="")
    vulnerability_name = Column(Text, default="")
    date_added = Column(String(30), default="")
    short_description = Column(Text, default="")
    required_action = Column(Text, default="")
    due_date = Column(String(30), default="")
    ransomware_use = Column(String(50), default="")
    notes = Column(Text, default="")
    references = Column(Text, default="")
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    notified = Column(Boolean, default=False, nullable=False)

Base.metadata.create_all(engine)

def seed_vendors():
    db = SessionLocal()
    try:
        for name in ["Cisco", "Fortinet", "Check Point"]:
            if not db.query(Vendor).filter(func.lower(Vendor.name) == name.lower()).first():
                db.add(Vendor(name=name, enabled=True))
        db.commit()
    finally:
        db.close()

seed_vendors()

sync_lock = threading.Lock()
last_sync = {"time": None, "added": 0, "matched": 0, "error": None}

def normalize_vendor(s):
    return " ".join((s or "").strip().split()).casefold()

def get_watchlist(db):
    return [v for v in db.query(Vendor).filter(Vendor.enabled == True).all()]

def matching_vendor(vendor_name, watchlist):
    target = normalize_vendor(vendor_name)
    for v in watchlist:
        if normalize_vendor(v.name) == target:
            return v.name
    return None

def send_telegram(text):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    r = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=20)
    r.raise_for_status()
    return True

def send_email(subject, body):
    host = os.getenv("SMTP_HOST")
    to_addr = os.getenv("SMTP_TO")
    sender = os.getenv("SMTP_FROM") or os.getenv("SMTP_USERNAME")
    if not host or not to_addr or not sender:
        return False
    port = int(os.getenv("SMTP_PORT", "587"))
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_addr
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=20) as server:
        if os.getenv("SMTP_TLS", "true").lower() == "true":
            server.starttls()
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    return True

def notify(v):
    body = (
        "🔴 NEW CISA KEV VENDOR ALERT\n\n"
        f"CVE: {v.cve_id}\n"
        f"Vendor: {v.vendor}\n"
        f"Product: {v.product}\n"
        f"Vulnerability: {v.vulnerability_name}\n"
        f"Date Added: {v.date_added}\n"
        f"Known Ransomware Use: {v.ransomware_use or 'Unknown'}\n"
        f"Due Date: {v.due_date or 'N/A'}\n\n"
        f"Description: {v.short_description}\n\n"
        f"Required Action: {v.required_action}\n"
    )
    sent = False
    try:
        sent = send_telegram(body) or sent
    except Exception:
        pass
    try:
        sent = send_email(f"[CISA KEV] {v.cve_id} - {v.vendor}", body) or sent
    except Exception:
        pass
    return sent

def sync_cisa():
    if not sync_lock.acquire(blocking=False):
        return
    db = SessionLocal()
    try:
        last_sync["error"] = None
        response = requests.get(CISA_FEED_URL, timeout=30)
        response.raise_for_status()
        payload = response.json()
        records = payload.get("vulnerabilities", [])
        watchlist = get_watchlist(db)
        added = matched = 0

        for item in records:
            cve_id = item.get("cveID")
            vendor_project = item.get("vendorProject") or ""
            if not cve_id:
                continue
            existing = db.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if existing:
                # Keep the local record updated with CISA's current values.
                existing.vendor = vendor_project
                existing.product = item.get("product", "")
                existing.vulnerability_name = item.get("vulnerabilityName", "")
                existing.date_added = item.get("dateAdded", "")
                existing.short_description = item.get("shortDescription", "")
                existing.required_action = item.get("requiredAction", "")
                existing.due_date = item.get("dueDate", "")
                existing.ransomware_use = item.get("knownRansomwareCampaignUse", "")
                continue

            matched_name = matching_vendor(vendor_project, watchlist)
            # Store all KEVs so the watchlist can be changed later without losing history.
            v = Vulnerability(
                cve_id=cve_id,
                vendor=vendor_project,
                product=item.get("product", ""),
                vulnerability_name=item.get("vulnerabilityName", ""),
                date_added=item.get("dateAdded", ""),
                short_description=item.get("shortDescription", ""),
                required_action=item.get("requiredAction", ""),
                due_date=item.get("dueDate", ""),
                ransomware_use=item.get("knownRansomwareCampaignUse", ""),
                references=str(item.get("notes", "")),
                notes=item.get("notes", ""),
                notified=False,
            )
            db.add(v)
            added += 1
            if matched_name:
                matched += 1

        db.commit()

        # Notify only for newly stored records matching the current watchlist.
        for v in db.query(Vulnerability).filter(Vulnerability.notified == False).all():
            if matching_vendor(v.vendor, watchlist):
                notify(v)
                v.notified = True
        db.commit()

        last_sync["time"] = datetime.now(timezone.utc)
        last_sync["added"] = added
        last_sync["matched"] = matched
    except Exception as exc:
        last_sync["error"] = str(exc)
    finally:
        db.close()
        sync_lock.release()

app = FastAPI(title="CISA KEV Vendor Watch")
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "static")),
    name="static",
)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.on_event("startup")
def startup():
    scheduler = BackgroundScheduler()
    scheduler.add_job(sync_cisa, "interval", minutes=POLL_MINUTES, id="cisa_sync", replace_existing=True)
    scheduler.start()
    app.state.scheduler = scheduler
    sync_cisa()

@app.on_event("shutdown")
def shutdown():
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler:
        scheduler.shutdown(wait=False)

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    vendor: str = "my_vendors",
    q: str = "",
    date_from: str = "",
    date_to: str = "",
):
    db = SessionLocal()
    try:
        vendors = db.query(Vendor).order_by(Vendor.name).all()
        watched_vendors = [v.name for v in vendors if v.enabled]

        query = db.query(Vulnerability)

        # Default filter: My Vendors
        if vendor == "my_vendors":
            if watched_vendors:
                query = query.filter(
                    func.lower(Vulnerability.vendor).in_(
                        [v.lower() for v in watched_vendors]
                    )
                )
            else:
                query = query.filter(False)

        # Specific vendor
        elif vendor:
            query = query.filter(
                func.lower(Vulnerability.vendor) == vendor.lower()
            )

        # Date Added - From
        if date_from:
            query = query.filter(
                Vulnerability.date_added >= date_from
            )

        # Date Added - To
        if date_to:
            query = query.filter(
                Vulnerability.date_added <= date_to
            )

        # Search
        if q:
            like = f"%{q}%"
            query = query.filter(
                (Vulnerability.cve_id.ilike(like)) |
                (Vulnerability.vendor.ilike(like)) |
                (Vulnerability.product.ilike(like)) |
                (Vulnerability.vulnerability_name.ilike(like))
            )

        vulnerabilities = (
            query
            .order_by(
                Vulnerability.date_added.desc(),
                Vulnerability.id.desc()
            )
            .limit(300)
            .all()
        )

        watched_count = sum(
            db.query(Vulnerability)
            .filter(
                func.lower(Vulnerability.vendor) == v.lower()
            )
            .count()
            for v in watched_vendors
        )

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "vendors": vendors,
                "vulnerabilities": vulnerabilities,
                "selected_vendor": vendor,
                "q": q,
                "date_from": date_from,
                "date_to": date_to,
                "total": db.query(Vulnerability).count(),
                "watched_count": watched_count,
                "new_count": db.query(Vulnerability)
                    .filter(Vulnerability.notified == False)
                    .count(),
                "last_sync": last_sync,
                "poll_minutes": POLL_MINUTES,
            },
        )

    finally:
        db.close()


@app.post("/vendors")
def add_vendor(name: str = Form(...)):
    name = " ".join(name.strip().split())
    if name:
        db = SessionLocal()
        try:
            if not db.query(Vendor).filter(func.lower(Vendor.name) == name.lower()).first():
                db.add(Vendor(name=name, enabled=True))
                db.commit()
        finally:
            db.close()
    return RedirectResponse("/", status_code=303)

@app.post("/vendors/{vendor_id}/toggle")
def toggle_vendor(vendor_id: int):
    db = SessionLocal()
    try:
        v = db.get(Vendor, vendor_id)
        if v:
            v.enabled = not v.enabled
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/", status_code=303)

@app.post("/vendors/{vendor_id}/delete")
def delete_vendor(vendor_id: int):
    db = SessionLocal()
    try:
        v = db.get(Vendor, vendor_id)
        if v:
            db.delete(v)
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/", status_code=303)

@app.post("/sync")
def manual_sync():
    sync_cisa()
    return RedirectResponse("/", status_code=303)

@app.get("/api/status")
def status():
    db = SessionLocal()
    try:
        return JSONResponse({
            "cisa_feed": CISA_FEED_URL,
            "poll_minutes": POLL_MINUTES,
            "last_sync": last_sync["time"].isoformat() if last_sync["time"] else None,
            "last_added": last_sync["added"],
            "last_matched": last_sync["matched"],
            "error": last_sync["error"],
            "total_cves": db.query(Vulnerability).count(),
            "vendors": [v.name for v in db.query(Vendor).filter(Vendor.enabled == True).all()],
        })
    finally:
        db.close()