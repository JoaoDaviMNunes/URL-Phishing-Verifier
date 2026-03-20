import ipaddress
import re
from typing import Dict, Optional, Tuple

import tldextract
from urllib.parse import urlparse


SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "adf.ly",
}

SHORTENER_DOMAINS = {h.split(".")[0] for h in SHORTENER_HOSTS}

_INT_RE = re.compile(r"^\d+$")


def _safe_url_for_parse(url: str) -> str:
    s = (url or "").strip()
    if not s:
        return ""
    if not re.match(r"^https?://", s, flags=re.IGNORECASE):
        return "http://" + s
    return s


def _hostname_from_url(url: str) -> str:
    parsed = urlparse(_safe_url_for_parse(url))
    return parsed.hostname or ""


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def parse_domain_parts(url: str, extractor: tldextract.TLDExtract) -> Tuple[str, str, str]:
    hostname = _hostname_from_url(url)
    if not hostname:
        return "", "", ""
    # Se for IP, tldextract pode retornar valores vazios.
    if is_ip_address(hostname):
        return "", "", ""
    res = extractor(hostname)
    return res.subdomain or "", res.domain or "", res.suffix or ""


def structural_features(url: str, extractor: tldextract.TLDExtract) -> Dict[str, float]:
    s = url or ""
    parsed = urlparse(_safe_url_for_parse(s))
    hostname = parsed.hostname or ""

    # Subdominio via tldextract
    subdomain, domain, suffix = parse_domain_parts(s, extractor)

    # Subdominios: quantidade de partes (ex: a.b.c -> 3 subdominios)
    num_subdomains = float(len(subdomain.split(".")) if subdomain else 0.0)

    # Uso de IP ao invés de domínio
    ip_as_domain = 1.0 if (hostname and is_ip_address(hostname)) else 0.0

    # Url encurtada
    host_norm = hostname.lower().rstrip(".")
    is_shortened = 0.0
    if host_norm in SHORTENER_HOSTS:
        is_shortened = 1.0
    else:
        # Cobertura extra: alguns encurtadores podem não bater 1:1.
        # Ex: t.co -> host "t.co". bit.ly -> "bit.ly".
        if any(host_norm.startswith(f"{d}.") for d in SHORTENER_DOMAINS):
            is_shortened = 1.0

    return {
        "num_subdomains": num_subdomains,
        "subdomain_length": float(len(subdomain)) if subdomain else 0.0,
        "domain_length": float(len(domain)) if domain else 0.0,
        "suffix_length": float(len(suffix)) if suffix else 0.0,
        "is_ip_address": ip_as_domain,
        "is_shortened_url": is_shortened,
        "has_path": 1.0 if (parsed.path and parsed.path != "/") else 0.0,
        "path_length": float(len(parsed.path or "")),
        "has_query": 1.0 if bool(parsed.query) else 0.0,
        "query_length": float(len(parsed.query or "")),
        "uses_https": 1.0 if (parsed.scheme.lower() == "https") else 0.0,
    }

