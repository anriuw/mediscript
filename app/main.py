"""MediScript - API server (hackathon prototype, fictional data only)."""
import hashlib
import json
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, knowledge, security

COOKIE = "zs_session"
IDLE_SECONDS = int(os.environ.get("ZS_IDLE_SECONDS", "600"))      # 10 min idle lock
ABSOLUTE_SECONDS = int(os.environ.get("ZS_SESSION_SECONDS", str(8 * 3600)))  # one shift
PREAUTH_SECONDS = 300
BREAK_GLASS_SECONDS = 1800
MAX_ACCESS_DAYS = 90
MAX_FAILS_USER = 5
MAX_FAILS_IP = 20
LOCK_WINDOW = 900
STALE_DAYS = 60
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SECURE_COOKIE = os.environ.get("ZS_SECURE_COOKIES", "0") == "1"
DEMO = os.environ.get("ZS_DEMO", "0") == "1"
STATIC_DIR = Path(__file__).resolve().parent / "static"
FLAGGED_ACTIONS = {"break_glass", "access_denied", "login_locked", "anomaly_bulk_access",
                   "login_failed", "totp_failed", "csrf_blocked"}


@asynccontextmanager
async def lifespan(_app):
    conn = db.connect()
    db.init_schema(conn)
    conn.close()
    yield


app = FastAPI(title="MediScript", lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if SECURE_COOKIE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------- helpers ----------

def get_db():
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()


def client_ip(request: Request) -> str:
    # Behind a trusted reverse proxy this would read X-Forwarded-For.
    return request.client.host if request.client else "unknown"


def check_origin(request: Request, conn=None):
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc != request.headers.get("host"):
        if conn is not None:
            db.audit(conn, "csrf_blocked", detail=f"origin={origin[:80]}", ip=client_ip(request),
                     username="-")
        raise HTTPException(403, "Ungültige Herkunft der Anfrage.")


def patient_code(pid: int) -> str:
    return f"P-{pid:04d}"


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None


def current_user(request: Request, conn=Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Nicht angemeldet.")
    th = security.token_hash(token)
    sess = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
    now = db.now()
    ua = hashlib.sha256(request.headers.get("user-agent", "").encode()).hexdigest()
    if (not sess or now - sess["last_seen"] > IDLE_SECONDS
            or now - sess["created_at"] > ABSOLUTE_SECONDS
            or not security.safe_equal(sess["ua_hash"], ua)):
        if sess:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        raise HTTPException(401, "Sitzung abgelaufen. Bitte neu anmelden.")
    user = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (sess["user_id"],)).fetchone()
    if not user:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        raise HTTPException(401, "Konto nicht aktiv.")
    if request.method not in SAFE_METHODS:
        check_origin(request, conn)
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not security.safe_equal(sent, sess["csrf"]):
            db.audit(conn, "csrf_blocked", user=user, detail="missing/invalid token",
                     ip=client_ip(request))
            raise HTTPException(403, "CSRF-Prüfung fehlgeschlagen.")
    conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, th))
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "role": user["role"], "csrf": sess["csrf"], "session_created": sess["created_at"],
            "token_hash": th}


def require_roles(*roles):
    def dep(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Keine Berechtigung für diese Funktion.")
        return user
    return dep


admin_user = require_roles("stationsleitung", "pdl")
pdl_user = require_roles("pdl")


def active_assignments(conn, user_id, now=None):
    now = now or db.now()
    return conn.execute(
        "SELECT a.*, w.name AS ward_name FROM assignments a JOIN wards w ON w.id=a.ward_id "
        "WHERE a.user_id=? AND a.revoked_at IS NULL AND a.valid_from<=? AND a.valid_until>?",
        (user_id, now, now)).fetchall()


def has_ward_access(conn, user_id, ward_id) -> bool:
    return any(a["ward_id"] == ward_id for a in active_assignments(conn, user_id))


def access_mode(conn, user, patient):
    """Default deny. Assignment to the patient's ward, or a live break-glass."""
    now = db.now()
    if patient["discharged_at"] is None and has_ward_access(conn, user["id"], patient["ward_id"]):
        return "assignment"
    bg = conn.execute("SELECT 1 FROM break_glass WHERE user_id=? AND patient_id=? AND expires_at>?",
                      (user["id"], patient["id"], now)).fetchone()
    return "break_glass" if bg else None


def load_patient(conn, user, pid, request, action):
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    mode = access_mode(conn, user, patient) if patient else None
    if not mode:
        # identical response for "does not exist" and "not allowed"
        db.audit(conn, "access_denied", user=user, patient_id=pid if patient else None,
                 detail=action, ip=client_ip(request))
        raise HTTPException(403, "kein_zugriff")
    return patient, mode


def patient_data(patient) -> dict:
    return json.loads(security.decrypt(patient["data_enc"]))


def check_bulk_access(conn, user, request):
    since = db.now() - 600
    row = conn.execute(
        "SELECT COUNT(DISTINCT patient_id) AS n FROM audit WHERE user_id=? AND "
        "action='patient_view' AND ts>=?", (user["id"], since)).fetchone()
    if row["n"] >= 8:
        recent = conn.execute("SELECT 1 FROM audit WHERE user_id=? AND action='anomaly_bulk_access' "
                              "AND ts>=?", (user["id"], since)).fetchone()
        if not recent:
            db.audit(conn, "anomaly_bulk_access", user=user,
                     detail=f"{row['n']} Patientenakten in 10 Minuten", ip=client_ip(request))


# ---------- models ----------

class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class TotpIn(BaseModel):
    pre_token: str = Field(min_length=10, max_length=100)
    code: str = Field(min_length=6, max_length=6)


class BreakGlassIn(BaseModel):
    reason: str = Field(min_length=15, max_length=300)


class AssistIn(BaseModel):
    summary: str = Field(min_length=1, max_length=4000)
    recheck: bool = False   # only re-evaluate open questions, keep the nurse's text untouched


class ReportIn(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    dismissals: dict[str, str] = Field(default_factory=dict)


class AccessRequestIn(BaseModel):
    target_user_id: int
    ward_id: int
    valid_until: str = Field(min_length=10, max_length=10)
    reason: str = Field(min_length=5, max_length=300)


class DecideIn(BaseModel):
    approve: bool
    comment: str = Field(default="", max_length=300)


class ReviewIn(BaseModel):
    note: str = Field(default="", max_length=300)


# ---------- auth ----------

def _record_failure(conn, username, ip):
    conn.execute("INSERT INTO login_attempts(username,ip,ts) VALUES(?,?,?)",
                 (username[:64], ip, db.now()))


def _locked(conn, username, ip) -> bool:
    since = db.now() - LOCK_WINDOW
    by_user = conn.execute("SELECT COUNT(*) AS n FROM login_attempts WHERE username=? AND ts>=?",
                           (username[:64], since)).fetchone()["n"]
    by_ip = conn.execute("SELECT COUNT(*) AS n FROM login_attempts WHERE ip=? AND ts>=?",
                         (ip, since)).fetchone()["n"]
    return by_user >= MAX_FAILS_USER or by_ip >= MAX_FAILS_IP


def _me_payload(conn, user):
    assigns = active_assignments(conn, user["id"])
    return {
        "user": {"id": user["id"], "username": user["username"],
                 "display_name": user["display_name"], "role": user["role"]},
        "csrf": user["csrf"],
        "idle_seconds": IDLE_SECONDS,
        "assignments": [{"ward_id": a["ward_id"], "ward_name": a["ward_name"],
                         "valid_until": iso(a["valid_until"])} for a in assigns],
    }


@app.post("/api/login")
def login(body: LoginIn, request: Request, conn=Depends(get_db)):
    check_origin(request, conn)
    ip = client_ip(request)
    uname = body.username.strip().lower()
    if _locked(conn, uname, ip):
        db.audit(conn, "login_locked", detail="zu viele Fehlversuche", ip=ip, username=uname[:64])
        raise HTTPException(429, "Zu viele Versuche. Bitte später erneut versuchen.")
    user = conn.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
    ok = security.verify_password(user["pw_hash"] if user and user["active"] else None,
                                  body.password)
    if not ok:
        _record_failure(conn, uname, ip)
        db.audit(conn, "login_failed", detail="Passwort/Benutzer", ip=ip, username=uname[:64])
        raise HTTPException(401, "Anmeldung fehlgeschlagen.")
    pre = security.new_token()
    conn.execute("DELETE FROM preauth WHERE expires_at<?", (db.now(),))
    conn.execute("INSERT INTO preauth(token_hash,user_id,expires_at) VALUES(?,?,?)",
                 (security.token_hash(pre), user["id"], db.now() + PREAUTH_SECONDS))
    return {"pre_token": pre, "needs_totp": True}


@app.post("/api/login/totp")
def login_totp(body: TotpIn, request: Request, response: Response, conn=Depends(get_db)):
    check_origin(request, conn)
    ip = client_ip(request)
    ph = security.token_hash(body.pre_token)
    pre = conn.execute("SELECT * FROM preauth WHERE token_hash=?", (ph,)).fetchone()
    if not pre or pre["expires_at"] < db.now() or pre["attempts"] >= 5:
        if pre:
            conn.execute("DELETE FROM preauth WHERE token_hash=?", (ph,))
        raise HTTPException(401, "Anmeldung abgelaufen. Bitte von vorn beginnen.")
    user = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (pre["user_id"],)).fetchone()
    if not user:
        raise HTTPException(401, "Anmeldung fehlgeschlagen.")
    if _locked(conn, user["username"], ip):
        db.audit(conn, "login_locked", user=user, detail="zu viele Fehlversuche", ip=ip)
        raise HTTPException(429, "Zu viele Versuche. Bitte später erneut versuchen.")
    secret = security.decrypt(user["totp_enc"])
    step = security.verify_totp(secret, body.code, user["totp_last_step"])
    if step is None:
        conn.execute("UPDATE preauth SET attempts=attempts+1 WHERE token_hash=?", (ph,))
        _record_failure(conn, user["username"], ip)
        db.audit(conn, "totp_failed", user=user, detail="Code falsch oder wiederverwendet", ip=ip)
        raise HTTPException(401, "Code ungültig.")
    now = db.now()
    token = security.new_token()
    csrf = security.new_token()
    ua = hashlib.sha256(request.headers.get("user-agent", "").encode()).hexdigest()
    with db.tx(conn):
        conn.execute("UPDATE users SET totp_last_step=?, last_login=? WHERE id=?",
                     (step, now, user["id"]))
        conn.execute("DELETE FROM preauth WHERE token_hash=?", (ph,))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND last_seen<?",
                     (user["id"], now - IDLE_SECONDS))
        conn.execute("INSERT INTO sessions(token_hash,user_id,csrf,created_at,last_seen,ua_hash) "
                     "VALUES(?,?,?,?,?,?)",
                     (security.token_hash(token), user["id"], csrf, now, now, ua))
        db.audit(conn, "login_ok", user=user, ip=ip)
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=SECURE_COOKIE,
                        path="/")
    payload = _me_payload(conn, {"id": user["id"], "username": user["username"],
                                 "display_name": user["display_name"], "role": user["role"],
                                 "csrf": csrf})
    return payload


@app.post("/api/logout")
def logout(request: Request, response: Response, user=Depends(current_user), conn=Depends(get_db)):
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (user["token_hash"],))
    db.audit(conn, "logout", user=user, ip=client_ip(request))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user), conn=Depends(get_db)):
    return _me_payload(conn, user)


# ---------- patients ----------

def _card(conn, patient, mode):
    data = patient_data(patient)
    ward = conn.execute("SELECT name FROM wards WHERE id=?", (patient["ward_id"],)).fetchone()
    age = datetime.now().year - data["birth_year"]
    return {"id": patient["id"], "code": patient_code(patient["id"]), "ward_id": patient["ward_id"],
            "ward_name": ward["name"], "room": patient["room"], "name": data["name"], "age": age,
            "diagnosis": data["diagnosis"], "mobility": data["facts"].get("mobility"),
            "mode": mode}


@app.get("/api/patients")
def list_patients(request: Request, user=Depends(current_user), conn=Depends(get_db)):
    wards = [a["ward_id"] for a in active_assignments(conn, user["id"])]
    cards = []
    if wards:
        marks = ",".join("?" * len(wards))
        for p in conn.execute(f"SELECT * FROM patients WHERE ward_id IN ({marks}) AND "
                              "discharged_at IS NULL ORDER BY ward_id, room", wards):
            cards.append(_card(conn, p, "assignment"))
    now = db.now()
    for p in conn.execute("SELECT p.* FROM patients p JOIN break_glass b ON b.patient_id=p.id "
                          "WHERE b.user_id=? AND b.expires_at>?", (user["id"], now)):
        if not any(c["id"] == p["id"] for c in cards):
            cards.append(_card(conn, p, "break_glass"))
    db.audit(conn, "patient_list", user=user, detail=f"{len(cards)} Karten",
             ip=client_ip(request))
    return {"patients": cards}


@app.get("/api/patients/{pid}")
def get_patient(pid: int, request: Request, user=Depends(current_user), conn=Depends(get_db)):
    patient, mode = load_patient(conn, user, pid, request, "patient_view")
    data = patient_data(patient)
    card = _card(conn, patient, mode)
    reports = []
    for r in conn.execute("SELECT r.*, u.display_name FROM reports r JOIN users u ON u.id=r.author_id "
                          "WHERE r.patient_id=? ORDER BY r.created_at DESC LIMIT 20", (pid,)):
        reports.append({"id": r["id"], "author": r["display_name"], "created_at": iso(r["created_at"]),
                        "text": security.decrypt(r["text_enc"]),
                        "dismissals": json.loads(security.decrypt(r["dismissals_enc"]))})
    db.audit(conn, "patient_view", user=user, patient_id=pid, detail=mode, ip=client_ip(request))
    check_bulk_access(conn, user, request)
    return {**card, "birth_year": data["birth_year"], "notes": data["notes"],
            "facts": data["facts"], "reports": reports}


@app.post("/api/patients/{pid}/break-glass")
def break_glass(pid: int, body: BreakGlassIn, request: Request, user=Depends(current_user),
                conn=Depends(get_db)):
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not patient:
        db.audit(conn, "access_denied", user=user, detail="break_glass", ip=client_ip(request))
        raise HTTPException(403, "kein_zugriff")
    now = db.now()
    with db.tx(conn):
        conn.execute("INSERT INTO break_glass(user_id,patient_id,reason,created_at,expires_at) "
                     "VALUES(?,?,?,?,?)", (user["id"], pid, body.reason.strip(), now,
                                           now + BREAK_GLASS_SECONDS))
        db.audit(conn, "break_glass", user=user, patient_id=pid, reason=body.reason.strip(),
                 detail="Notfallzugriff 30 Min", ip=client_ip(request))
    return {"ok": True, "expires_at": iso(now + BREAK_GLASS_SECONDS)}


@app.post("/api/patients/{pid}/assist")
def assist(pid: int, body: AssistIn, request: Request, user=Depends(current_user),
           conn=Depends(get_db)):
    patient, mode = load_patient(conn, user, pid, request, "assist")
    facts = dict(patient_data(patient)["facts"])
    facts["age"] = datetime.now().year - patient_data(patient)["birth_year"]
    if body.recheck:
        result = {"questions": knowledge.find_gaps(body.summary, facts),
                  "disclaimer": knowledge.DISCLAIMER}
    else:
        result = knowledge.analyze(body.summary, facts)
    # the spoken/typed text itself is never stored in the audit log
    db.audit(conn, "assist_used", user=user, patient_id=pid,
             detail=f"{len(result['questions'])} Rückfragen", ip=client_ip(request))
    return result


@app.post("/api/patients/{pid}/reports")
def sign_report(pid: int, body: ReportIn, request: Request, user=Depends(current_user),
                conn=Depends(get_db)):
    patient, mode = load_patient(conn, user, pid, request, "report_sign")
    data = patient_data(patient)
    facts = dict(data["facts"])
    facts["age"] = datetime.now().year - data["birth_year"]
    open_gaps = knowledge.find_gaps(body.text, facts)
    dismissals = {}
    missing = []
    for gap in open_gaps:
        reason = (body.dismissals.get(gap["id"]) or "").strip()
        if len(reason) < 3:
            missing.append(gap["id"])
        else:
            dismissals[gap["id"]] = reason[:200]
    if missing:
        raise HTTPException(422, {"message": "Offene Rückfragen: ergänzen oder begründen.",
                                  "missing": missing})
    now = db.now()
    with db.tx(conn):
        conn.execute("INSERT INTO reports(patient_id,author_id,text_enc,dismissals_enc,created_at) "
                     "VALUES(?,?,?,?,?)",
                     (pid, user["id"], security.encrypt(body.text.strip()),
                      security.encrypt(json.dumps(dismissals)), now))
        db.audit(conn, "report_signed", user=user, patient_id=pid,
                 detail=f"{len(dismissals)} Rückfragen begründet verworfen", ip=client_ip(request))
    return {"ok": True}


# ---------- administration (ward managers / PDL) ----------

def _parse_until(value: str) -> int:
    try:
        d = date.fromisoformat(value)
    except ValueError:
        raise HTTPException(422, "Datum ungültig (JJJJ-MM-TT).")
    end = int(datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    now = db.now()
    if end <= now or end > now + MAX_ACCESS_DAYS * 86400:
        raise HTTPException(422, f"Enddatum muss in der Zukunft und höchstens {MAX_ACCESS_DAYS} Tage entfernt liegen.")
    return end


def _can_manage_ward(conn, user, ward_id) -> bool:
    return user["role"] == "pdl" or has_ward_access(conn, user["id"], ward_id)


@app.get("/api/admin/overview")
def admin_overview(user=Depends(admin_user), conn=Depends(get_db)):
    now = db.now()
    users = []
    for u in conn.execute("SELECT * FROM users ORDER BY role DESC, display_name"):
        assigns = [{"id": a["id"], "ward_id": a["ward_id"], "ward_name": a["ward_name"],
                    "valid_until": iso(a["valid_until"]),
                    "expires_soon": a["valid_until"] - now < 3 * 86400}
                   for a in active_assignments(conn, u["id"], now)]
        last = u["last_login"]
        users.append({"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                      "role": u["role"], "active": bool(u["active"]), "last_login": iso(last),
                      "stale": bool(u["active"]) and (last is None or now - last > STALE_DAYS * 86400),
                      "assignments": assigns})
    requests = []
    for r in conn.execute(
            "SELECT r.*, t.display_name AS target_name, q.display_name AS requester_name, "
            "w.name AS ward_name FROM access_requests r "
            "JOIN users t ON t.id=r.target_user_id JOIN users q ON q.id=r.requested_by "
            "JOIN wards w ON w.id=r.ward_id ORDER BY r.requested_at DESC LIMIT 30"):
        can = (r["status"] == "pending" and r["requested_by"] != user["id"]
               and r["target_user_id"] != user["id"]
               and _can_manage_ward(conn, user, r["ward_id"]))
        requests.append({"id": r["id"], "target_name": r["target_name"],
                         "requester_name": r["requester_name"], "ward_name": r["ward_name"],
                         "valid_until": iso(r["valid_until"]), "reason": r["reason"],
                         "status": r["status"], "requested_at": iso(r["requested_at"]),
                         "can_decide": can})
    wards = [{"id": w["id"], "name": w["name"]} for w in conn.execute("SELECT * FROM wards")]
    manageable = [w for w in wards if _can_manage_ward(conn, user, w["id"])]
    return {"users": users, "requests": requests, "wards": wards,
            "manageable_wards": manageable, "max_days": MAX_ACCESS_DAYS}


@app.post("/api/admin/requests")
def create_request(body: AccessRequestIn, request: Request, user=Depends(admin_user),
                   conn=Depends(get_db)):
    if not _can_manage_ward(conn, user, body.ward_id):
        raise HTTPException(403, "Sie verwalten diese Station nicht.")
    target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (body.target_user_id,)).fetchone()
    ward = conn.execute("SELECT * FROM wards WHERE id=?", (body.ward_id,)).fetchone()
    if not target or not ward:
        raise HTTPException(404, "Person oder Station nicht gefunden.")
    until = _parse_until(body.valid_until)
    dup = conn.execute("SELECT 1 FROM access_requests WHERE target_user_id=? AND ward_id=? "
                       "AND status='pending'", (target["id"], ward["id"])).fetchone()
    if dup:
        raise HTTPException(409, "Für diese Person und Station liegt schon ein offener Antrag vor.")
    with db.tx(conn):
        conn.execute("INSERT INTO access_requests(target_user_id,ward_id,valid_until,reason,"
                     "requested_by,requested_at) VALUES(?,?,?,?,?,?)",
                     (target["id"], ward["id"], until, body.reason.strip(), user["id"], db.now()))
        db.audit(conn, "access_requested", user=user,
                 detail=f"{target['username']} -> {ward['name']} bis {body.valid_until}",
                 reason=body.reason.strip(), ip=client_ip(request))
    return {"ok": True}


@app.post("/api/admin/requests/{rid}/decide")
def decide_request(rid: int, body: DecideIn, request: Request, user=Depends(admin_user),
                   conn=Depends(get_db)):
    with db.tx(conn):
        req = conn.execute("SELECT * FROM access_requests WHERE id=?", (rid,)).fetchone()
        if not req or req["status"] != "pending":
            raise HTTPException(404, "Antrag nicht (mehr) offen.")
        # four-eyes principle
        if req["requested_by"] == user["id"]:
            raise HTTPException(403, "Eigene Anträge dürfen nicht selbst genehmigt werden.")
        if req["target_user_id"] == user["id"]:
            raise HTTPException(403, "Eigener Zugriff darf nicht selbst genehmigt werden.")
        if not _can_manage_ward(conn, user, req["ward_id"]):
            raise HTTPException(403, "Sie verwalten diese Station nicht.")
        now = db.now()
        target = conn.execute("SELECT username FROM users WHERE id=?", (req["target_user_id"],)).fetchone()
        ward = conn.execute("SELECT name FROM wards WHERE id=?", (req["ward_id"],)).fetchone()
        if body.approve:
            if req["valid_until"] <= now:
                raise HTTPException(422, "Antrag ist bereits abgelaufen.")
            conn.execute("INSERT INTO assignments(user_id,ward_id,valid_from,valid_until,granted_by,"
                         "approved_by,request_id) VALUES(?,?,?,?,?,?,?)",
                         (req["target_user_id"], req["ward_id"], now, req["valid_until"],
                          req["requested_by"], user["id"], rid))
        conn.execute("UPDATE access_requests SET status=?, decided_by=?, decided_at=?, comment=? "
                     "WHERE id=?", ("approved" if body.approve else "rejected", user["id"], now,
                                    body.comment.strip(), rid))
        db.audit(conn, "access_granted" if body.approve else "access_rejected", user=user,
                 detail=f"{target['username']} -> {ward['name']} bis {iso(req['valid_until'])[:10]}",
                 reason=body.comment.strip(), ip=client_ip(request))
    return {"ok": True}


@app.post("/api/admin/assignments/{aid}/revoke")
def revoke_assignment(aid: int, request: Request, user=Depends(admin_user), conn=Depends(get_db)):
    a = conn.execute("SELECT a.*, u.username, w.name AS ward_name FROM assignments a "
                     "JOIN users u ON u.id=a.user_id JOIN wards w ON w.id=a.ward_id "
                     "WHERE a.id=? AND a.revoked_at IS NULL", (aid,)).fetchone()
    if not a:
        raise HTTPException(404, "Zugriff nicht gefunden.")
    if not _can_manage_ward(conn, user, a["ward_id"]):
        raise HTTPException(403, "Sie verwalten diese Station nicht.")
    with db.tx(conn):
        conn.execute("UPDATE assignments SET revoked_at=?, revoked_by=? WHERE id=?",
                     (db.now(), user["id"], aid))
        db.audit(conn, "access_revoked", user=user,
                 detail=f"{a['username']} -> {a['ward_name']}", ip=client_ip(request))
    return {"ok": True}


@app.post("/api/admin/users/{uid}/deactivate")
def deactivate_user(uid: int, request: Request, user=Depends(pdl_user), conn=Depends(get_db)):
    if uid == user["id"]:
        raise HTTPException(403, "Das eigene Konto kann nicht deaktiviert werden.")
    target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
    if not target:
        raise HTTPException(404, "Person nicht gefunden.")
    now = db.now()
    with db.tx(conn):
        conn.execute("UPDATE users SET active=0, deactivated_at=? WHERE id=?", (now, uid))
        conn.execute("UPDATE assignments SET revoked_at=?, revoked_by=? WHERE user_id=? "
                     "AND revoked_at IS NULL", (now, user["id"], uid))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM preauth WHERE user_id=?", (uid,))
        db.audit(conn, "user_deactivated", user=user, detail=target["username"],
                 ip=client_ip(request))
    return {"ok": True}


# ---------- audit & break-glass review ----------

def _audit_row(r):
    return {"id": r["id"], "ts": iso(r["ts"]), "username": r["username"], "action": r["action"],
            "patient_code": patient_code(r["patient_id"]) if r["patient_id"] else None,
            "detail": r["detail"], "reason": r["reason"], "ip": r["ip"],
            "flagged": r["action"] in FLAGGED_ACTIONS}


@app.get("/api/audit")
def audit_feed(limit: int = 100, patient: int | None = None, user=Depends(admin_user),
               conn=Depends(get_db)):
    limit = max(1, min(limit, 300))
    if patient is not None:
        rows = conn.execute("SELECT * FROM audit WHERE patient_id=? ORDER BY id DESC LIMIT ?",
                            (patient, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"entries": [_audit_row(r) for r in rows]}


@app.get("/api/audit/verify")
def audit_verify(user=Depends(admin_user), conn=Depends(get_db)):
    return db.verify_chain(conn)


@app.get("/api/break-glass")
def break_glass_list(user=Depends(pdl_user), conn=Depends(get_db)):
    rows = conn.execute(
        "SELECT b.*, u.display_name FROM break_glass b JOIN users u ON u.id=b.user_id "
        "ORDER BY b.created_at DESC LIMIT 50").fetchall()
    return {"entries": [{"id": b["id"], "user": b["display_name"],
                         "patient_code": patient_code(b["patient_id"]), "reason": b["reason"],
                         "created_at": iso(b["created_at"]), "reviewed": b["reviewed_at"] is not None,
                         "review_note": b["review_note"]} for b in rows]}


@app.post("/api/break-glass/{bid}/review")
def break_glass_review(bid: int, body: ReviewIn, request: Request, user=Depends(pdl_user),
                       conn=Depends(get_db)):
    b = conn.execute("SELECT * FROM break_glass WHERE id=?", (bid,)).fetchone()
    if not b:
        raise HTTPException(404, "Eintrag nicht gefunden.")
    if b["user_id"] == user["id"]:
        raise HTTPException(403, "Eigene Notfallzugriffe können nicht selbst geprüft werden.")
    with db.tx(conn):
        conn.execute("UPDATE break_glass SET reviewed_by=?, reviewed_at=?, review_note=? WHERE id=?",
                     (user["id"], db.now(), body.note.strip(), bid))
        db.audit(conn, "break_glass_reviewed", user=user, patient_id=b["patient_id"],
                 detail=f"Eintrag {bid}", reason=body.note.strip(), ip=client_ip(request))
    return {"ok": True}


# ---------- demo helper (loopback only, off by default) ----------

if DEMO:
    @app.get("/api/demo/credentials")
    def demo_credentials(request: Request, conn=Depends(get_db)):
        proxied = any(h in request.headers for h in (
            "x-forwarded-for", "forwarded", "x-real-ip", "cf-connecting-ip", "x-forwarded-host"))
        if proxied or client_ip(request) not in ("127.0.0.1", "::1", "testclient"):
            raise HTTPException(404, "Nicht gefunden.")   # a tunnel/proxy makes remote users look local
        path = db.data_dir() / "DEMO_CREDENTIALS.json"
        if not path.exists():
            return {"accounts": []}
        creds = json.loads(path.read_text())
        out = []
        for c in creds:
            row = conn.execute("SELECT * FROM users WHERE username=?", (c["username"],)).fetchone()
            if row and row["active"]:
                out.append({"username": c["username"], "password": c["password"],
                            "display_name": row["display_name"], "role": row["role"],
                            "code": security.current_totp(c["totp_secret"])})
        return {"accounts": out}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
