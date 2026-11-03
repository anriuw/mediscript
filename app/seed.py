"""Seed a fictional hospital: 2 wards, 5 staff (all nurses), 6 fictional patients.

Passwords and TOTP secrets are generated randomly on every seed and written to
data/DEMO_CREDENTIALS.json (mode 0600). They are never part of the source code.
"""
import json
import os
import secrets
import sys

from . import db, security

WARDS = ["Station 1 · Innere Medizin", "Station 2 · Chirurgie"]

# (username, display name, role, ward index or None)
STAFF = [
    ("anna.keller", "Anna Keller", "pflege", 0),
    ("ben.yilmaz", "Ben Yılmaz", "pflege", 1),
    ("clara.richter", "Clara Richter (Stationsleitung 1)", "stationsleitung", 0),
    ("dirk.hoffmann", "Dirk Hoffmann (Pflegedienstleitung)", "pdl", None),
    ("eva.novak", "Eva Novak (Springerin)", "pflege", None),
]

PATIENTS = [
    (0, "101", {"name": "Walter Brandt", "birth_year": 1941, "diagnosis": "Pneumonie, bettlägerig",
                "notes": "Sauerstoff nach Bedarf. Tochter wird nachmittags erwartet.",
                "facts": {"mobility": "bettlaegerig", "poor_intake": True}}),
    (0, "102", {"name": "Ingrid Sommer", "birth_year": 1947, "diagnosis": "Herzinsuffizienz",
                "notes": "Sturz vor drei Wochen zu Hause. Geht mit Rollator.",
                "facts": {"mobility": "eingeschraenkt", "fall_history": True}}),
    (0, "104", {"name": "Karl-Heinz Vogel", "birth_year": 1956, "diagnosis": "Diabetes mellitus Typ 2, Infekt",
                "notes": "Blutzuckerprofil laut ärztlicher Anordnung.",
                "facts": {"mobility": "mobil", "diabetes": True}}),
    (1, "201", {"name": "Fatma Demir", "birth_year": 1963, "diagnosis": "Hüft-TEP, 2. postoperativer Tag",
                "notes": "Mobilisation mit Physiotherapie.",
                "facts": {"mobility": "eingeschraenkt", "pain": True, "postop": True}}),
    (1, "202", {"name": "Lukas Meyer", "birth_year": 1980, "diagnosis": "Appendektomie, 1. postoperativer Tag",
                "notes": "Kostaufbau läuft.",
                "facts": {"mobility": "mobil", "postop": True}}),
    (1, "203", {"name": "Helga Winter", "birth_year": 1944, "diagnosis": "Schenkelhalsfraktur, operiert",
                "notes": "Leichte Verwirrtheit nachts.",
                "facts": {"mobility": "bettlaegerig", "pain": True, "postop": True,
                          "confusion": True, "fall_history": True}}),
]


def seed(conn) -> list[dict]:
    now = db.now()
    ward_ids = []
    for name in WARDS:
        cur = conn.execute("INSERT INTO wards(name) VALUES(?)", (name,))
        ward_ids.append(cur.lastrowid)
    creds = []
    for username, display, role, ward_idx in STAFF:
        password = secrets.token_urlsafe(12) + "7a"
        secret = security.new_totp_secret()
        cur = conn.execute(
            "INSERT INTO users(username,display_name,role,pw_hash,totp_enc,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (username, display, role, security.hash_password(password),
             security.encrypt(secret), now))
        uid = cur.lastrowid
        creds.append({"username": username, "password": password, "totp_secret": secret})
        if ward_idx is not None:
            conn.execute("INSERT INTO assignments(user_id,ward_id,valid_from,valid_until,"
                         "granted_by) VALUES(?,?,?,?,?)",
                         (uid, ward_ids[ward_idx], now, now + 60 * 86400, uid))
    for ward_idx, room, data in PATIENTS:
        conn.execute("INSERT INTO patients(ward_id,room,data_enc,admitted_at) VALUES(?,?,?,?)",
                     (ward_ids[ward_idx], room, security.encrypt(json.dumps(data)), now))
    db.audit(conn, "system_seeded", detail="fictional demo data", username="system")
    return creds


def main():
    conn = db.connect()
    db.init_schema(conn)
    if conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]:
        print("Datenbank ist schon befüllt. Zum Neustart den Ordner data/ löschen.")
        return
    creds = seed(conn)
    path = db.data_dir() / "DEMO_CREDENTIALS.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(creds, fh, indent=2)
    print(f"Demo-Daten angelegt. Zugangsdaten (nur Demo): {path}")


if __name__ == "__main__":
    sys.exit(main())
