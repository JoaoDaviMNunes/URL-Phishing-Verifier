import socket
from dataclasses import dataclass
from typing import Optional, Tuple

import tldextract

from url_phishing_verifier.config import DEFAULT_GEO_RISK


@dataclass(frozen=True)
class GeoResult:
    country_cc: Optional[str]
    country_risk: float
    method: str


def _hostname(url: str) -> str:
    # Esta import é intencionalmente evitada para não criar dependência circular.
    # A lógica de parse já acontece em outros módulos; aqui precisamos apenas do host.
    from urllib.parse import urlparse
    import re

    s = (url or "").strip()
    if not s:
        return ""
    if not re.match(r"^https?://", s, flags=re.IGNORECASE):
        s = "http://" + s
    return urlparse(s).hostname or ""


def _guess_cc_by_tld(url: str, extractor: tldextract.TLDExtract) -> Optional[str]:
    host = _hostname(url)
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        return None
    res = extractor(host)
    return (res.suffix or None) if res.suffix else None


def resolve_country_by_cc_tld(url: str, extractor: tldextract.TLDExtract) -> GeoResult:
    cc = _guess_cc_by_tld(url, extractor)
    if cc and len(cc) == 2:
        risk = DEFAULT_GEO_RISK.risk_for_cc(cc)
        return GeoResult(country_cc=cc.lower(), country_risk=risk, method="ccTLD")
    return GeoResult(country_cc=None, country_risk=0.2, method="unknown")


def resolve_country_by_dns_and_api(url: str, extractor: tldextract.TLDExtract, timeout_s: int = 2) -> GeoResult:
    """
    Implementação opcional/leve.
    Resolve o domínio -> IP via DNS e (se desejar) consulta uma API externa.
    Para evitar que o pipeline quebre sem rede/API, esta função tem fallback por ccTLD.
    """

    # Fallback "sempre funciona" (mesmo sem rede)
    fallback = resolve_country_by_cc_tld(url, extractor)

    host = _hostname(url)
    if not host:
        return fallback

    try:
        # Apenas A record (IPv4). Se precisar IPv6, ajustar.
        ip = socket.gethostbyname(host)
    except Exception:
        return fallback

    # Consulta API: opcional. Usamos uma API publica comum, mas pode ter rate-limit.
    # Se falhar, caímos no fallback.
    try:
        import requests

        # ipapi.co: retorna texto/JSON conforme endpoint.
        resp = requests.get(f"https://ipapi.co/{ip}/country_code/", timeout=timeout_s)
        if resp.status_code == 200:
            cc = (resp.text or "").strip().lower()
            if cc and len(cc) == 2:
                risk = DEFAULT_GEO_RISK.risk_for_cc(cc)
                return GeoResult(country_cc=cc, country_risk=risk, method="ipapi.co")
    except Exception:
        return fallback

    return fallback

