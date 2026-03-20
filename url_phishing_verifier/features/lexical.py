import math
import re
from typing import Dict


SUSPICIOUS_WORD_PATTERNS = [
    r"login",
    r"secure",
    r"verify",
    r"verification",
    r"signin",
    r"sign-in",
    r"account",
    r"update",
    r"wallet",
    r"billing",
    r"confirm",
    r"recovery",
    r"password",
    r"banking",
    r"ssn",
]

SUSPICIOUS_WORD_RE = re.compile("|".join(SUSPICIOUS_WORD_PATTERNS), re.IGNORECASE)
EXCESSIVE_DIGIT_RE = re.compile(r"\d")


def shannon_entropy(s: str) -> float:
    """
    Entropia de Shannon (base 2) para caracteres do texto.
    URLs aleatorias tendem a ter entropia maior.
    """

    if not s:
        return 0.0

    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1

    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log(p, 2)
    return float(ent)


def lexical_features(url: str) -> Dict[str, float]:
    # Trabalha com a string original (sem "consertar" o schema)
    s = url or ""
    digits = EXCESSIVE_DIGIT_RE.findall(s)
    digits_count = len(digits)
    digits_ratio = digits_count / max(1, len(s))

    suspicious_word_count = len(SUSPICIOUS_WORD_RE.findall(s))

    # Heuristica: "muitos numeros" pode indicar id aleatorio / tracking / phishing.
    # Ajuste conforme seu dataset.
    excessive_digits = 1.0 if (digits_count >= 10 or digits_ratio >= 0.25) else 0.0

    return {
        "url_length": float(len(s)),
        "url_entropy": shannon_entropy(s),
        "num_digits": float(digits_count),
        "digits_ratio": float(digits_ratio),
        "has_at": 1.0 if "@" in s else 0.0,
        "has_dash": 1.0 if "-" in s else 0.0,
        "has_question_mark": 1.0 if "?" in s else 0.0,
        "has_suspicious_words": 1.0 if suspicious_word_count > 0 else 0.0,
        "suspicious_words_count": float(suspicious_word_count),
        "excessive_digits": excessive_digits,
    }

