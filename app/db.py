"""SQLite storage with a hash-chained, append-only audit log."""
import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS wards(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('pflege','stationsleitung','pdl')),
  pw_hash TEXT NOT NULL,
  totp_enc TEXT NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_login INTEGER,
  deactivated_at INTEGER);

CREATE TABLE IF NOT EXISTS patients(
  id INTEGER PRIMARY KEY,
  ward_id INTEGER NOT NULL REFERENCES wards(id),
  room TEXT NOT NULL,
  data_enc TEXT NOT NULL,
  admitted_at INTEGER NOT NULL,
  discharged_at INTEGER);

CREATE TABLE IF NOT EXISTS assignments(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  ward_id INTEGER NOT NULL REFERENCES wards(id),
  valid_from INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  granted_by INTEGER, approved_by INTEGER, request_id INTEGER,
  revoked_at INTEGER, revoked_by INTEGER);

CREATE TABLE IF NOT EXISTS access_requests(
  id INTEGER PRIMARY KEY,
  target_user_id INTEGER NOT NULL REFERENCES users(id),
  ward_id INTEGER NOT NULL REFERENCES wards(id),
  valid_until INTEGER NOT NULL,
  reason TEXT NOT NULL,
  requested_by INTEGER NOT NULL REFERENCES users(id),
  requested_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','approved','rejected')),
  decided_by INTEGER, decided_at INTEGER, comment TEXT);

CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  ua_hash TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS preauth(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS login_attempts(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip TEXT NOT NULL, ts INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS break_glass(
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  reviewed_by INTEGER, reviewed_at INTEGER, review_note TEXT);

CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY,
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  author_id INTEGER NOT NULL REFERENCES users(id),
  text_enc TEXT NOT NULL,
  dismissals_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_id INTEGER,
  username TEXT,
  action TEXT NOT NULL,
  patient_id INTEGER,
  detail TEXT NOT NULL,
  reason TEXT NOT NULL,
  ip TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

CREATE INDEX IF NOT EXISTS idx_assign_user ON assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts(username, ts);
CREATE INDEX IF NOT EXISTS idx_audit_patient ON audit(patient_id);
"""


def now() -> int:
    return int(time.time())


def data_dir() -> Path:
    default = Path(__file__).resolve().parent.parent / "data"
    path = Path(os.environ.get("ZS_DATA_DIR", default))
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def connect() -> sqlite3.Connection:
    # One connection per request, used sequentially. FastAPI may run the dependency and the
    # endpoint on different worker threads, hence check_same_thread=False.
    conn = sqlite3.connect(data_dir() / "app.db", isolation_level=None, timeout=10,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextmanager
def tx(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# ---------- audit log ----------

def chain_hash(prev: str, entry: dict) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev}|{payload}".encode("utf-8")).hexdigest()


def _entry(ts, user_id, username, action, patient_id, detail, reason, ip) -> dict:
    return {"ts": ts, "user_id": user_id, "username": username, "action": action,
            "patient_id": patient_id, "detail": detail, "reason": reason, "ip": ip}


def audit(conn, action, user=None, patient_id=None, detail="", reason="",
          ip="", username=None):
    """Append one entry to the hash chain. Works standalone or inside tx()."""
    own = not conn.in_transaction
    if own:
        conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        uid = user["id"] if user else None
        uname = user["username"] if user else username
        entry = _entry(now(), uid, uname, action, patient_id,
                       (detail or "")[:300], (reason or "")[:300], ip or "")
        digest = chain_hash(prev, entry)
        conn.execute(
            "INSERT INTO audit(ts,user_id,username,action,patient_id,detail,reason,ip,"
            "prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (entry["ts"], uid, uname, action, patient_id, entry["detail"],
             entry["reason"], entry["ip"], prev, digest))
        if own:
            conn.execute("COMMIT")
    except BaseException:
        if own:
            conn.execute("ROLLBACK")
        raise


def verify_chain(conn) -> dict:
    prev = GENESIS
    count = 0
    for row in conn.execute("SELECT * FROM audit ORDER BY id"):
        entry = _entry(row["ts"], row["user_id"], row["username"], row["action"],
                       row["patient_id"], row["detail"], row["reason"], row["ip"])
        if row["prev_hash"] != prev or row["hash"] != chain_hash(prev, entry):
            return {"ok": False, "count": count, "first_bad_id": row["id"]}
        prev = row["hash"]
        count += 1
    return {"ok": True, "count": count, "first_bad_id": None}
