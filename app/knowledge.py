"""Care-standard knowledge base and report assistant (prototype).

The engine is deliberately rule-based: it can only ask questions that come
from the stored standards and always names its source. It never invents
facts and makes no external calls. The `analyze` function is the seam where
a locally hosted language model could be plugged in later.

All hint texts are paraphrased and must be reviewed by clinical staff before
any real use. This is not a medical device and gives no diagnoses.
"""
import re

DISCLAIMER = ("Prototyp: Hinweise aus hinterlegten Pflegestandards, sinngemäß und "
              "nicht im Wortlaut. Keine Diagnose, keine Therapieempfehlung. "
              "Die Pflegekraft prüft und verantwortet den Bericht.")


def _age(f):
    return f.get("age") or 0


STANDARDS = [
    {
        "id": "dekubitus",
        "title": "Dekubitusprophylaxe",
        "source": "DNQP Expertenstandard „Dekubitusprophylaxe in der Pflege“",
        "reasons": lambda f: (
            (["Mobilität eingeschränkt"] if f.get("mobility") in ("bettlaegerig", "eingeschraenkt") else [])
            + (["Alter ab 75"] if _age(f) >= 75 else [])),
        "topics": [
            {"id": "dekubitus_haut",
             "question": "Wurde die Haut kontrolliert (z. B. Kreuzbein, Fersen)? Bitte den Befund festhalten.",
             "keywords": ["haut", "dekubitus", "kreuzbein", "ferse", "druckstelle", "rötung", "hautbefund"]},
            {"id": "dekubitus_lagerung",
             "question": "Gab es Lagerungswechsel oder Bewegungsförderung? Bitte Zeitpunkt oder Rhythmus nennen.",
             "keywords": ["umgelagert", "lagerung", "positionswechsel", "mobilisiert", "bewegt", "gedreht"]},
        ],
    },
    {
        "id": "sturz",
        "title": "Sturzprophylaxe",
        "source": "DNQP Expertenstandard „Sturzprophylaxe in der Pflege“",
        "reasons": lambda f: (
            (["Sturz in der Vorgeschichte"] if f.get("fall_history") else [])
            + (["Verwirrtheit"] if f.get("confusion") else [])
            + (["Alter ab 75"] if _age(f) >= 75 and f.get("mobility") != "bettlaegerig" else [])),
        "topics": [
            {"id": "sturz_risiko",
             "question": "Ist das Sturzrisiko heute eingeschätzt oder bestätigt worden?",
             "keywords": ["sturz", "fallrisiko", "sturzrisiko"]},
            {"id": "sturz_hilfsmittel",
             "question": "Wie wurde mobilisiert (Begleitung, Hilfsmittel, Bettgitter-Entscheidung)?",
             "keywords": ["gehhilfe", "rollator", "begleitet", "hilfsmittel", "aufgestanden", "mobilisiert"]},
        ],
    },
    {
        "id": "schmerz",
        "title": "Schmerzmanagement",
        "source": "DNQP Expertenstandard „Schmerzmanagement in der Pflege“",
        "reasons": lambda f: (["Schmerzen bekannt"] if f.get("pain") else [])
                             + (["Zustand nach Operation"] if f.get("postop") else []),
        "topics": [
            {"id": "schmerz_erfassung",
             "question": "Wie stark waren die Schmerzen (z. B. Skala 0–10) und wo?",
             "keywords": ["schmerz", "nrs", "skala", "vas"]},
            {"id": "schmerz_wirkung",
             "question": "Wurde Schmerzmedikation gegeben und wie war die Wirkung?",
             "keywords": ["schmerzmittel", "analget", "bedarfsmedikation", "opioid", "wirkung", "wirksam"]},
        ],
    },
    {
        "id": "ernaehrung",
        "title": "Ernährung und Flüssigkeit",
        "source": "DNQP Expertenstandard „Sicherstellung und Förderung der oralen Ernährung in der Pflege“",
        "reasons": lambda f: (["Alter ab 75"] if _age(f) >= 75 else [])
                             + (["Appetit/Zufuhr auffällig"] if f.get("poor_intake") else []),
        "topics": [
            {"id": "ernaehrung_zufuhr",
             "question": "Wie war die Zufuhr von Essen und Trinken (ungefähre Menge)?",
             "keywords": ["essen", "trink", "ernähr", "flüssigkeit", "appetit", "mahlzeit", "nahrung"]},
        ],
    },
    {
        "id": "diabetes",
        "title": "Blutzuckerkontrolle",
        "source": "Stationsstandard (Demo-Beispiel, kein DNQP-Standard)",
        "reasons": lambda f: (["Diabetes bekannt"] if f.get("diabetes") else []),
        "topics": [
            {"id": "diabetes_bz",
             "question": "Wurden Blutzuckerwerte gemessen und dokumentiert?",
             "keywords": ["blutzucker", "bz ", "bz:", "glukose", "insulin"]},
        ],
    },
]

_SECTION_RULES = [
    ("vitalwerte", ["rr ", "rr:", "blutdruck", "puls", "temp", "spo2", "sättigung", "fieber gemessen"]),
    ("massnahmen", ["gewaschen", "mobilisiert", "umgelagert", "verbandswechsel", "verabreicht",
                    "gegeben", "kontrolliert", "gemessen", "infusion", "physio", "begleitet",
                    "angezogen", "gelagert", "versorgt"]),
    ("auffaelligkeiten", ["schmerz", "unruhig", "verwirrt", "sturz", "fieber", "atemnot", "übel",
                          "erbrochen", "gerötet", "appetitlos", "schwindel", "schwitzt", "müde"]),
    ("offen", ["morgen", "noch offen", "ausstehend", "arzt informieren", "arzt bitte", "bitte ",
               "nachher", "später", "muss noch", "visite"]),
]

_SECTION_TITLES = {
    "befinden": "Allgemeinbefinden",
    "vitalwerte": "Vitalwerte",
    "massnahmen": "Durchgeführte Maßnahmen",
    "auffaelligkeiten": "Auffälligkeiten",
    "offen": "Offene Aufgaben",
}

_VITAL_PATTERNS = {
    "RR": r"\b(?:rr|blutdruck)[:\s]*(\d{2,3}\s*/\s*\d{2,3})",
    "Puls": r"\bpuls[:\s]*(\d{2,3})",
    "Temperatur": r"\btemp(?:eratur)?[:\s]*(\d{2}[.,]\d)",
    "SpO2": r"\bspo2[:\s]*(\d{2,3})\s*%?",
}


def _sentences(text: str):
    parts = re.split(r"(?<=[.!?])\s+|\n+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _mentions(text_lower: str, keywords) -> bool:
    return any(k in text_lower for k in keywords)


def extract_vitals(text: str) -> dict:
    low = text.lower()
    out = {}
    for name, pattern in _VITAL_PATTERNS.items():
        m = re.search(pattern, low)
        if m:
            out[name] = m.group(1).replace(" ", "")
    return out


def find_gaps(summary: str, facts: dict) -> list[dict]:
    low = summary.lower()
    gaps = []
    for std in STANDARDS:
        reasons = std["reasons"](facts)
        if not reasons:
            continue
        for topic in std["topics"]:
            if not _mentions(low, topic["keywords"]):
                gaps.append({
                    "id": topic["id"],
                    "question": topic["question"],
                    "standard": std["title"],
                    "source": std["source"],
                    "because": ", ".join(reasons),
                })
    return gaps


def analyze(summary: str, facts: dict) -> dict:
    sections = {key: [] for key in _SECTION_TITLES}
    for sentence in _sentences(summary):
        low = sentence.lower() + " "
        placed = False
        for key, words in _SECTION_RULES:
            if _mentions(low, words):
                sections[key].append(sentence)
                placed = True
                break
        if not placed:
            sections["befinden"].append(sentence)
    vitals = extract_vitals(summary)
    lines = []
    for key, title in _SECTION_TITLES.items():
        if key == "vitalwerte" and vitals:
            lines.append(f"{title}: " + ", ".join(f"{k} {v}" for k, v in vitals.items()))
        elif sections[key]:
            lines.append(f"{title}: " + " ".join(sections[key]))
    return {
        "sections": {_SECTION_TITLES[k]: v for k, v in sections.items() if v},
        "vitals": vitals,
        "draft_text": "\n".join(lines),
        "questions": find_gaps(summary, facts),
        "disclaimer": DISCLAIMER,
    }
