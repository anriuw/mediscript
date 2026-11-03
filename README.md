# MediScript (hackathon prototype)

> **English summary.** MediScript is an AI-assisted nursing-documentation prototype for hospitals: patient index cards per ward, a report assistant that asks follow-up questions from care standards and names the source, and access limited to hospital staff (per-ward default-deny, four-eyes approval, break-glass with review, hash-chained audit log). **Fictional data only. Prototype, not audited, not a medical device.** Run `./run.sh`; set `ZS_DEMO=0` for anything that is not a local demo. Details below (German).

## Deutsch

Pflege-Assistent für Krankenhäuser: Karteikarten pro Patient, Berichtsassistent mit Rückfragen
aus Pflegestandards, Zugriff nur nach Bedarf. **Nur fiktive Daten. Kein Medizinprodukt.**

## Starten

```bash
./run.sh            # http://127.0.0.1:8000  (PORT=8765 ./run.sh für anderen Port)
```

Beim ersten Start werden 2 Stationen, 5 Beschäftigte (alle Pflege) und 6 fiktive Patienten angelegt.
Zufällige Passwörter und 2.-Faktor-Schlüssel liegen in `data/DEMO_CREDENTIALS.json`.
Im Demo-Modus (`ZS_DEMO=1`, Standard in `run.sh`) zeigt die Startseite einen Schnell-Login, der nur
von 127.0.0.1 aus funktioniert. **Für alles andere `ZS_DEMO=0` setzen.** Der Schnell-Login lehnt Anfragen mit Proxy-Headern ab.
Zurücksetzen: Ordner `data/` löschen.

Tests: `python3 -m pip install pytest httpx && python3 -m pytest -q tests`

## Demo-Ablauf (3 Minuten)

1. **Anna Keller** (Station 1): sieht nur die 3 Karteikarten ihrer Station.
2. Karte *Walter Brandt* öffnen, Schichtzusammenfassung eingeben, „Bericht entwerfen".
   Der Assistent fragt nach (Hautkontrolle, Lagerung) und nennt jeweils die Quelle.
   Unterschreiben ist erst möglich, wenn jede Frage ergänzt oder begründet ist.
3. Code `P-0004` (andere Station) eingeben: **kein Zugriff**, dann Notfallzugriff mit Begründung.
4. **Clara Richter** (Stationsleitung, Pflegekraft): Zugriff für *Eva Novak* beantragen. Eigener Antrag
   lässt sich nicht selbst genehmigen.
5. **Dirk Hoffmann** (Pflegedienstleitung): genehmigt (Vier-Augen), prüft den Notfallzugriff,
   Protokoll zeigt „Kette intakt".

## Sicherheit: was umgesetzt ist

| Bereich | Umsetzung |
|---|---|
| Passwörter | argon2id, Passwortprüfung mit konstanter Zeit auch bei unbekanntem Benutzer |
| 2. Faktor | TOTP (RFC 6238), jeder Code nur einmal nutzbar (Replay-Schutz), max. 5 Versuche pro Anmeldung |
| Sperre | 5 Fehlversuche pro Benutzer / 20 pro IP in 15 Min, Sperren werden protokolliert |
| Sitzung | zufälliges 256-Bit-Token, nur der Hash in der DB, Cookie `HttpOnly` + `SameSite=Strict`, 10 Min Leerlauf, max. 8 Std, an User-Agent gebunden |
| CSRF | Token im Header + Origin-Prüfung bei jeder ändernden Anfrage |
| Zugriff | Standard = verweigert. Nur Patienten der aktuell zugewiesenen Station, Zuweisungen sind befristet (max. 90 Tage) |
| Admin ≠ Leser | Verwaltungs- und Protokollansichten enthalten nie Patientendaten; Stationsleitung hat keinen Sonderzugriff auf Akten |
| Vier-Augen | Anträge brauchen eine zweite Person, nie der Antragsteller oder die betroffene Person selbst |
| Notfallzugriff | Begründung Pflicht, 30 Min gültig, rot markiert, Prüfung durch PDL (nicht durch sich selbst) |
| Austritt | PDL deaktiviert: Zugriffe und laufende Sitzungen enden sofort |
| Verschlüsselung | Patientendaten, Berichte und 2.-Faktor-Schlüssel verschlüsselt in der DB (Fernet / AES + HMAC) |
| Protokoll | Hash-Kette, per DB-Trigger append-only, Prüfung in der Oberfläche |
| Auffälligkeiten | Meldung bei 8+ verschiedenen Akten in 10 Minuten |
| Web | strenge CSP (nur eigene Skripte), kein `innerHTML`, `no-store`, `X-Frame-Options`, `nosniff`, parametrisierte SQL-Abfragen |
| Datensparsamkeit | Der eingegebene Berichtstext wird nur zur Analyse verarbeitet, nie im Protokoll gespeichert; keine externen Aufrufe |

## Ehrlich: was fehlt für einen echten Einsatz

- **Anmeldung** über das Krankenhausverzeichnis (SSO/OIDC) und Hardware-Schlüssel (FIDO2) statt lokaler Konten und TOTP.
- **Schlüsselverwaltung** in einem KMS/HSM statt Datei `data/field.key`. DB-Server statt SQLite, HTTPS mit `ZS_SECURE_COOKIES=1` hinter einem Reverse Proxy.
- **Protokoll-Manipulation:** Die Hash-Kette erkennt Änderungen, aber wer die ganze Datei ersetzt, kann sie neu aufbauen. In der Praxis wird der aktuelle Hash regelmäßig extern abgelegt (z. B. WORM-Speicher).
- **Der Assistent ist regelbasiert**, kein Sprachmodell. Das ist Absicht (erfindet nichts, nennt immer die Quelle). An der Stelle `knowledge.analyze` könnte ein lokal betriebenes Modell ergänzt werden.
- **Hinweistexte** sind sinngemäß den DNQP-Expertenstandards nachempfunden, nicht im Wortlaut, und müssen fachlich geprüft werden.
- **Diktierfunktion:** bewusst nicht eingebaut, weil Browser-Spracherkennung Audio oft an Cloud-Dienste schickt. Das Betriebssystem-Diktat im Textfeld funktioniert.
- Zertifizierungen und Rechtliches: Medizinprodukte-Verordnung, DSGVO Art. 9, Krankenhaus-IT-Sicherheit (KRITIS/B3S), Penetrationstest, Datenschutz-Folgenabschätzung.
