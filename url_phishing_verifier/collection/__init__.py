__all__ = [
    "download_text_file",
    "collect_phishtank",
    "collect_mendeley_phishing",
    "collect_alexa_legit",
]

from .utils import download_text_file
from .phishtank import collect_phishtank
from .mendeley import collect_mendeley_phishing
from .alexa import collect_alexa_legit

