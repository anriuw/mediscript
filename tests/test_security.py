import json
import sqlite3
import sys
from pathlib import Path

import pytest
import pyotp
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, main, security, seed  # noqa: E402


class Env:
    def __init__(self, client, creds, conn, tmp):
        self.client, self.creds, self.conn, self.tmp = client, {c["username"]: c for c in creds}, conn, tmp
        self.step = 1_000_000

    def login(self, username, password=None, client=None):
        c = client or self.client
        cred = self.creds[username]
        r = c.post("/api/login", json={"username": username, "password": password or cred["password"]})
        assert r.status_code == 200, r.text
        self.step += 1                              # each login uses a fresh 30s window
        security.clock = lambda s=self.step: s * 30 + 1
        code = pyotp.TOTP(cred["totp_secret"]).generate_otp(self.step)
        r = c.post("/api/login/totp", json={"pre_token": r.json()["pre_token"], "code": code})
        assert r.status_code == 200, r.text
        c.headers["x-csrf-token"] = r.json()["csrf"]
        return r.json()

    def new_client(self):
        return TestClient(main.app)

    def uid(self, username):
        return self.conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]

    def pid(self, room):
        return self.conn.execute("SELECT id FROM patients WHERE room=?", (room,)).fetchone()["id"]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZS_DATA_DIR", str(tmp_path))
    conn = db.connect()
    db.init_schema(conn)
    creds = seed.seed(conn)
    with TestClient(main.app) as client:
        e = Env(client, creds, conn, tmp_path)
        yield e
    security.clock = __import__("time").time


# ---------- authentication ----------

def test_unauthenticated_is_rejected(env):
    assert env.client.get("/api/patients").status_code == 401
    assert env.client.get("/api/admin/overview").status_code == 401


def test_login_needs_second_factor_and_is_generic(env):
    bad_user = env.client.post("/api/login", json={"username": "nobody", "password": "x" * 14})
    bad_pass = env.client.post("/api/login", json={"username": "anna.keller", "password": "wrong-password"})
    assert bad_user.status_code == bad_pass.status_code == 401
    assert bad_user.json() == bad_pass.json()          # no user enumeration
    ok = env.client.post("/api/login", json={"username": "anna.keller",
                                             "password": env.creds["anna.keller"]["password"]})
    assert ok.status_code == 200 and "pre_token" in ok.json()
    assert "zs_session" not in env.client.cookies      # password alone gives no session


def test_wrong_totp_rejected_and_replay_blocked(env):
    r = env.client.post("/api/login", json={"username": "anna.keller",
                                            "password": env.creds["anna.keller"]["password"]})
    r2 = env.client.post("/api/login/totp", json={"pre_token": r.json()["pre_token"], "code": "000000"})
    assert r2.status_code == 401
    # a valid code can be used only once
    security.clock = lambda: 5_000_000 * 30 + 1
    code = pyotp.TOTP(env.creds["anna.keller"]["totp_secret"]).generate_otp(5_000_000)
    r = env.client.post("/api/login", json={"username": "anna.keller",
                                            "password": env.creds["anna.keller"]["password"]})
    assert env.client.post("/api/login/totp", json={"pre_token": r.json()["pre_token"], "code": code}).status_code == 200
    other = env.new_client()
    r = other.post("/api/login", json={"username": "anna.keller",
                                       "password": env.creds["anna.keller"]["password"]})
    assert other.post("/api/login/totp", json={"pre_token": r.json()["pre_token"], "code": code}).status_code == 401


def test_lockout_after_repeated_failures(env):
    for _ in range(main.MAX_FAILS_USER):
        env.client.post("/api/login", json={"username": "anna.keller", "password": "wrong-password"})
    r = env.client.post("/api/login", json={"username": "anna.keller",
                                            "password": env.creds["anna.keller"]["password"]})
    assert r.status_code == 429                         # even the right password is refused


def test_passwords_hashed_with_argon2id_and_secrets_encrypted(env):
    row = env.conn.execute("SELECT pw_hash, totp_enc FROM users WHERE username='anna.keller'").fetchone()
    assert row["pw_hash"].startswith("$argon2id$")
    assert env.creds["anna.keller"]["totp_secret"] not in row["totp_enc"]


def test_session_cookie_flags_and_idle_timeout(env, monkeypatch):
    env.login("anna.keller")
    header = env.client.get("/api/me").headers
    assert "default-src 'self'" in header["content-security-policy"]
    assert header["cache-control"] == "no-store"
    raw = env.conn.execute("SELECT token_hash FROM sessions").fetchone()["token_hash"]
    assert raw != env.client.cookies["zs_session"]      # only a hash is stored
    real = db.now()
    monkeypatch.setattr(db, "now", lambda: real + main.IDLE_SECONDS + 5)
    assert env.client.get("/api/me").status_code == 401


def test_csrf_and_origin_enforced(env):
    env.login("anna.keller")
    pid = env.pid("101")
    token = env.client.headers.pop("x-csrf-token")
    r = env.client.post(f"/api/patients/{pid}/assist", json={"summary": "ok"})
    assert r.status_code == 403
    env.client.headers["x-csrf-token"] = token
    r = env.client.post(f"/api/patients/{pid}/assist", json={"summary": "ok"},
                        headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    assert env.client.post(f"/api/patients/{pid}/assist", json={"summary": "ok"}).status_code == 200


# ---------- access control ----------

def test_nurse_sees_only_her_ward(env):
    env.login("anna.keller")
    rooms = {p["room"] for p in env.client.get("/api/patients").json()["patients"]}
    assert rooms == {"101", "102", "104"}


def test_other_ward_patient_denied_and_logged(env):
    env.login("anna.keller")
    surgical = env.pid("201")
    r = env.client.get(f"/api/patients/{surgical}")
    assert r.status_code == 403 and r.json()["detail"] == "kein_zugriff"
    assert "Demir" not in r.text
    # unknown id looks exactly the same
    assert env.client.get("/api/patients/9999").json() == r.json()
    n = env.conn.execute("SELECT COUNT(*) AS n FROM audit WHERE action='access_denied'").fetchone()["n"]
    assert n >= 1


def test_ward_manager_has_no_special_read_access_to_other_wards(env):
    env.login("clara.richter")                          # Stationsleitung of ward 1
    assert env.client.get(f"/api/patients/{env.pid('201')}").status_code == 403
    assert env.client.get(f"/api/patients/{env.pid('101')}").status_code == 200


def test_patient_data_is_encrypted_at_rest(env):
    raw = sqlite3.connect(env.tmp / "app.db")
    blob = " ".join(r[0] for r in raw.execute("SELECT data_enc FROM patients"))
    assert "Brandt" not in blob and "Pneumonie" not in blob


def test_break_glass_needs_reason_and_is_flagged(env):
    env.login("anna.keller")
    target = env.pid("201")
    assert env.client.post(f"/api/patients/{target}/break-glass", json={"reason": "kurz"}).status_code == 422
    r = env.client.post(f"/api/patients/{target}/break-glass",
                        json={"reason": "Notfall: Patientin kollabiert, Station besetzt"})
    assert r.status_code == 200
    assert env.client.get(f"/api/patients/{target}").status_code == 200
    env.login("dirk.hoffmann", client=(pdl := env.new_client()))
    entries = pdl.get("/api/break-glass").json()["entries"]
    assert len(entries) == 1 and not entries[0]["reviewed"]
    assert pdl.post(f"/api/break-glass/{entries[0]['id']}/review", json={"note": "plausibel"}).status_code == 200
    feed = pdl.get("/api/audit").json()["entries"]
    assert any(e["action"] == "break_glass" and e["flagged"] for e in feed)


def test_break_glass_expires(env, monkeypatch):
    env.login("anna.keller")
    target = env.pid("201")
    env.client.post(f"/api/patients/{target}/break-glass",
                    json={"reason": "Notfall: Patientin kollabiert, Station besetzt"})
    real = db.now()
    monkeypatch.setattr(db, "now", lambda: real + main.BREAK_GLASS_SECONDS + 5)
    env.conn.execute("UPDATE sessions SET last_seen=?", (real + main.BREAK_GLASS_SECONDS,))
    assert env.client.get(f"/api/patients/{target}").status_code == 403


# ---------- worker management ----------

def _request(c, target_id, ward_id, until=None, reason="Springerdienst diese Woche"):
    from datetime import date, timedelta
    until = until or (date.today() + timedelta(days=5)).isoformat()
    return c.post("/api/admin/requests", json={"target_user_id": target_id, "ward_id": ward_id,
                                               "valid_until": until, "reason": reason})


def test_four_eyes_principle(env):
    clara = env.new_client()
    env.login("clara.richter", client=clara)
    ward1 = env.conn.execute("SELECT id FROM wards ORDER BY id").fetchone()["id"]
    assert _request(clara, env.uid("eva.novak"), ward1).status_code == 200
    rid = env.conn.execute("SELECT id FROM access_requests").fetchone()["id"]
    # requester cannot approve her own request
    assert clara.post(f"/api/admin/requests/{rid}/decide", json={"approve": True}).status_code == 403
    # a normal nurse cannot administer at all
    anna = env.new_client()
    env.login("anna.keller", client=anna)
    assert anna.post(f"/api/admin/requests/{rid}/decide", json={"approve": True}).status_code == 403
    # target gets nothing yet
    eva = env.new_client()
    env.login("eva.novak", client=eva)
    assert eva.get("/api/patients").json()["patients"] == []
    # second person approves
    dirk = env.new_client()
    env.login("dirk.hoffmann", client=dirk)
    assert dirk.post(f"/api/admin/requests/{rid}/decide", json={"approve": True}).status_code == 200
    assert {p["room"] for p in eva.get("/api/patients").json()["patients"]} == {"101", "102", "104"}


def test_manager_cannot_grant_wards_she_does_not_run_and_assignments_expire(env, monkeypatch):
    clara = env.new_client()
    env.login("clara.richter", client=clara)
    ward2 = env.conn.execute("SELECT id FROM wards ORDER BY id DESC").fetchone()["id"]
    assert _request(clara, env.uid("eva.novak"), ward2).status_code == 403
    from datetime import date, timedelta
    assert _request(clara, env.uid("eva.novak"), 1,
                    until=(date.today() + timedelta(days=400)).isoformat()).status_code == 422
    assert _request(clara, env.uid("eva.novak"), 1,
                    until=(date.today() - timedelta(days=1)).isoformat()).status_code == 422


def test_revoke_and_deactivate(env):
    anna = env.new_client()
    env.login("anna.keller", client=anna)
    assert anna.get("/api/patients").json()["patients"]
    dirk = env.new_client()
    env.login("dirk.hoffmann", client=dirk)
    ov = dirk.get("/api/admin/overview").json()
    anna_row = next(u for u in ov["users"] if u["username"] == "anna.keller")
    assert dirk.post(f"/api/admin/assignments/{anna_row['assignments'][0]['id']}/revoke").status_code == 200
    assert anna.get("/api/patients").json()["patients"] == []
    # leaver: PDL deactivates, live session dies
    ben = env.new_client()
    env.login("ben.yilmaz", client=ben)
    assert ben.get("/api/me").status_code == 200
    assert dirk.post(f"/api/admin/users/{env.uid('ben.yilmaz')}/deactivate").status_code == 200
    assert ben.get("/api/me").status_code == 401
    assert env.client.post("/api/login", json={"username": "ben.yilmaz",
                                               "password": env.creds["ben.yilmaz"]["password"]}).status_code == 401
    # PDL cannot lock herself out; ward managers cannot deactivate
    assert dirk.post(f"/api/admin/users/{env.uid('dirk.hoffmann')}/deactivate").status_code == 403


def test_admin_screens_never_contain_patient_data(env):
    clara = env.new_client()
    env.login("clara.richter", client=clara)
    clara.get(f"/api/patients/{env.pid('101')}")
    text = clara.get("/api/admin/overview").text + clara.get("/api/audit").text
    assert "Brandt" not in text and "Pneumonie" not in text


# ---------- audit log ----------

def test_audit_chain_is_append_only_and_detects_tampering(env):
    env.login("anna.keller")
    env.client.get(f"/api/patients/{env.pid('101')}")
    assert db.verify_chain(env.conn)["ok"]
    with pytest.raises(sqlite3.DatabaseError):
        env.conn.execute("UPDATE audit SET action='nothing' WHERE id=1")
    with pytest.raises(sqlite3.DatabaseError):
        env.conn.execute("DELETE FROM audit WHERE id=1")
    # an attacker with raw file access drops the trigger and edits a row
    env.conn.execute("DROP TRIGGER audit_no_update")
    env.conn.execute("UPDATE audit SET detail='manipuliert' WHERE id=2")
    result = db.verify_chain(env.conn)
    assert result["ok"] is False and result["first_bad_id"] == 2


def test_views_are_logged_with_user_patient_and_mode(env):
    env.login("anna.keller")
    pid = env.pid("102")
    env.client.get(f"/api/patients/{pid}")
    row = env.conn.execute("SELECT * FROM audit WHERE action='patient_view'").fetchone()
    assert row["username"] == "anna.keller" and row["patient_id"] == pid and row["detail"] == "assignment"


# ---------- report assistant ----------

def test_assistant_asks_for_missing_standard_topics_with_sources(env):
    env.login("anna.keller")
    pid = env.pid("101")        # bettlägerig, 85 J.
    r = env.client.post(f"/api/patients/{pid}/assist",
                        json={"summary": "Herr Brandt wurde gewaschen. RR 128/76, Puls 82, Temp 37,4."}).json()
    ids = {q["id"] for q in r["questions"]}
    assert {"dekubitus_haut", "dekubitus_lagerung", "ernaehrung_zufuhr"} <= ids
    assert all(q["source"] for q in r["questions"])
    assert r["vitals"] == {"RR": "128/76", "Puls": "82", "Temperatur": "37,4"}
    done = env.client.post(f"/api/patients/{pid}/assist",
                           json={"summary": "Haut am Kreuzbein unauffällig, umgelagert. "
                                            "Hat gut gegessen und getrunken."}).json()
    assert not {"dekubitus_haut", "dekubitus_lagerung", "ernaehrung_zufuhr"} & {q["id"] for q in done["questions"]}


def test_report_needs_human_decision_on_every_open_question(env):
    env.login("anna.keller")
    pid = env.pid("101")
    text = "Herr Brandt ruhig, Atmung stabil."
    r = env.client.post(f"/api/patients/{pid}/reports", json={"text": text})
    assert r.status_code == 422 and r.json()["detail"]["missing"]
    dismissals = {m: "nicht zutreffend, siehe Arztanordnung" for m in r.json()["detail"]["missing"]}
    assert env.client.post(f"/api/patients/{pid}/reports",
                           json={"text": text, "dismissals": dismissals}).status_code == 200
    shown = env.client.get(f"/api/patients/{pid}").json()["reports"][0]
    assert shown["author"] == "Anna Keller" and shown["text"] == text
    raw = sqlite3.connect(env.tmp / "app.db").execute("SELECT text_enc FROM reports").fetchone()[0]
    assert "Atmung" not in raw


def test_report_not_allowed_without_access(env):
    env.login("anna.keller")
    r = env.client.post(f"/api/patients/{env.pid('201')}/reports", json={"text": "x"})
    assert r.status_code == 403


def test_session_cookie_is_httponly_and_strict(env):
    cred = env.creds["anna.keller"]
    pre = env.client.post("/api/login", json={"username": "anna.keller", "password": cred["password"]}).json()
    security.clock = lambda: 7_000_000 * 30 + 1
    code = pyotp.TOTP(cred["totp_secret"]).generate_otp(7_000_000)
    r = env.client.post("/api/login/totp", json={"pre_token": pre["pre_token"], "code": code})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_audit_log_holds_no_patient_names_or_report_text(env):
    env.login("anna.keller")
    pid = env.pid("101")
    text = "Herr Brandt ruhig, Atmung stabil."
    env.client.get(f"/api/patients/{pid}")
    r = env.client.post(f"/api/patients/{pid}/reports", json={"text": text})
    dismissals = {m: "nicht zutreffend, siehe Arztanordnung" for m in r.json()["detail"]["missing"]}
    env.client.post(f"/api/patients/{pid}/reports", json={"text": text, "dismissals": dismissals})
    dump = json.dumps([dict(x) for x in env.conn.execute("SELECT * FROM audit")], default=str)
    assert "Brandt" not in dump and "Atmung" not in dump and "ruhig" not in dump

