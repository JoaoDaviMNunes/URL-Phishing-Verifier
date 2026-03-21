"""
Verificações externas de URL com múltiplas fontes.
Inclui scraping do Cloudflare Radar e ESET, além de APIs opcionais
(VirusTotal e Google Safe Browsing).
"""
from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests

# Timeout padrão para requests HTTP
_TIMEOUT = 20


@dataclass
class ExternalCheckResult:
    source: str
    safe: Optional[bool]  # True=safe, False=malicious, None=unknown
    details: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PageMetadata:
    title: Optional[str] = None
    status_code: Optional[int] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    country: Optional[str] = None
    ip_address: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    has_ssl: bool = False


def _safe_url(url: str) -> str:
    s = url.strip()
    if not re.match(r"^https?://", s, re.IGNORECASE):
        s = "http://" + s
    return s


# ─────────────────────────────────────────────────
# Fetch page metadata (title, server, technologies)
# ─────────────────────────────────────────────────
def fetch_page_metadata(url: str) -> PageMetadata:
    """Fetches basic metadata about a URL: title, server, technologies, IP, country."""
    meta = PageMetadata()
    safe = _safe_url(url)

    # Resolve IP
    try:
        parsed = urlparse(safe)
        hostname = parsed.hostname or ""
        if hostname:
            meta.ip_address = socket.gethostbyname(hostname)
    except Exception:
        pass

    # Fetch page
    try:
        resp = requests.get(
            safe,
            timeout=_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; URLPhishingVerifier/1.0)"},
            verify=False,
        )
        meta.status_code = resp.status_code
        meta.has_ssl = safe.startswith("https://") or resp.url.startswith("https://")
        meta.content_type = resp.headers.get("Content-Type", "")

        # Redirect chain
        if resp.history:
            meta.redirect_chain = [r.url for r in resp.history] + [resp.url]

        # Server / technologies
        server = resp.headers.get("Server", "")
        if server:
            meta.server = server
            meta.technologies.append(f"Server: {server}")

        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            meta.technologies.append(f"X-Powered-By: {powered}")

        via = resp.headers.get("Via", "")
        if via:
            meta.technologies.append(f"Via: {via}")

        # Title from HTML
        if "text/html" in (meta.content_type or ""):
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>", resp.text[:8000], re.IGNORECASE | re.DOTALL
            )
            if title_match:
                meta.title = title_match.group(1).strip()[:200]

        # Detect common technologies from HTML
        html_lower = resp.text[:15000].lower()
        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes"],
            "React": ["react", "__next"],
            "Angular": ["ng-app", "angular"],
            "Vue.js": ["vue.js", "__vue"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Cloudflare": ["cf-ray"],
            "Google Analytics": ["google-analytics", "gtag"],
            "Google Tag Manager": ["googletagmanager"],
        }
        for tech, markers in tech_patterns.items():
            if any(m in html_lower for m in markers):
                meta.technologies.append(tech)

        # Check Cloudflare from headers
        if resp.headers.get("CF-RAY"):
            if "Cloudflare" not in meta.technologies:
                meta.technologies.append("Cloudflare")

    except requests.exceptions.SSLError:
        meta.has_ssl = False
    except Exception:
        pass

    return meta


# ─────────────────────────────────────────────────
# VirusTotal API (free: 4 req/min, 500/day)
# ─────────────────────────────────────────────────
def check_virustotal(url: str) -> ExternalCheckResult:
    """Consulta VirusTotal API v3. Requer VIRUSTOTAL_API_KEY no env."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return ExternalCheckResult(
            source="VirusTotal",
            safe=None,
            details="API key não configurada (VIRUSTOTAL_API_KEY)",
        )

    try:
        # Submit URL for scan
        headers = {"x-apikey": api_key}
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 429:
            return ExternalCheckResult(
                source="VirusTotal", safe=None, details="Rate limit atingido"
            )
        resp.raise_for_status()
        analysis_id = resp.json().get("data", {}).get("id", "")

        if not analysis_id:
            return ExternalCheckResult(
                source="VirusTotal", safe=None, details="Sem ID de análise"
            )

        # Poll for results (max 30s)
        for _ in range(6):
            time.sleep(5)
            r2 = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=_TIMEOUT,
            )
            if r2.status_code != 200:
                continue
            data = r2.json().get("data", {})
            attrs = data.get("attributes", {})
            status = attrs.get("status", "")
            if status == "completed":
                stats = attrs.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1
                is_safe = (malicious + suspicious) == 0
                return ExternalCheckResult(
                    source="VirusTotal",
                    safe=is_safe,
                    details=f"{malicious} malicious, {suspicious} suspicious de {total} engines",
                    raw=stats,
                )

        return ExternalCheckResult(
            source="VirusTotal", safe=None, details="Análise em andamento (timeout)"
        )
    except Exception as e:
        return ExternalCheckResult(
            source="VirusTotal", safe=None, details=f"Erro: {str(e)[:100]}"
        )


# ─────────────────────────────────────────────────
# Google Safe Browsing v4 (free with API key)
# ─────────────────────────────────────────────────
def check_google_safebrowsing(url: str) -> ExternalCheckResult:
    """Consulta Google Safe Browsing v4. Requer GOOGLE_SAFEBROWSING_KEY no env."""
    api_key = os.environ.get("GOOGLE_SAFEBROWSING_KEY", "")
    if not api_key:
        return ExternalCheckResult(
            source="Google Safe Browsing",
            safe=None,
            details="API key não configurada (GOOGLE_SAFEBROWSING_KEY)",
        )

    try:
        body = {
            "client": {"clientId": "url-phishing-verifier", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        if matches:
            threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
            return ExternalCheckResult(
                source="Google Safe Browsing",
                safe=False,
                details=f"Ameaças detectadas: {', '.join(threat_types)}",
                raw={"matches": matches},
            )
        return ExternalCheckResult(
            source="Google Safe Browsing",
            safe=True,
            details="Nenhuma ameaça detectada",
        )
    except Exception as e:
        return ExternalCheckResult(
            source="Google Safe Browsing",
            safe=None,
            details=f"Erro: {str(e)[:100]}",
        )


# ─────────────────────────────────────────────────
# Cloudflare Radar (scrape public scan page)
# ─────────────────────────────────────────────────
def check_cloudflare_radar(url: str) -> ExternalCheckResult:
    """Verifica URL no Cloudflare Radar via requisição pública."""
    try:
        safe = _safe_url(url)
        parsed = urlparse(safe)
        domain = parsed.hostname or parsed.netloc or url
        scan_url = f"https://radar.cloudflare.com/scan/{domain}"

        resp = requests.get(
            scan_url,
            timeout=_TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7",
                "Referer": "https://radar.cloudflare.com/",
            },
        )

        if resp.status_code == 200:
            body = resp.text[:20000].lower()
            if "malicious" in body or "phishing" in body:
                return ExternalCheckResult(
                    source="Cloudflare Radar",
                    safe=False,
                    details=f"Indicadores de risco encontrados para {domain}",
                    raw={"scan_url": scan_url},
                )
            return ExternalCheckResult(
                source="Cloudflare Radar",
                safe=True,
                details=f"Nenhum indicador de risco para {domain}",
                raw={"scan_url": scan_url},
            )
        return ExternalCheckResult(
            source="Cloudflare Radar",
            safe=None,
            details=f"HTTP {resp.status_code}",
        )
    except Exception as e:
        return ExternalCheckResult(
            source="Cloudflare Radar",
            safe=None,
            details=f"Erro: {str(e)[:100]}",
        )


# ─────────────────────────────────────────────────
# ESET Link Checker (API)
# ─────────────────────────────────────────────────
def check_eset(url: str) -> ExternalCheckResult:
    """Verifica URL no ESET Link Checker via API GET."""
    try:
        # Endpoint correto descoberto via análise de rede
        api_url = "https://api.eset.com/v1/url-proxy/link-checker/"
        resp = requests.get(
            api_url,
            params={"url": url},
            timeout=_TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Origin": "https://www.eset.com",
                "Referer": "https://www.eset.com/",
            },
        )
        if resp.status_code == 200:
            res_text = resp.text.strip().lower()
            # ESET retorna "Clean" para URLs seguras
            if res_text == "clean":
                return ExternalCheckResult(
                    source="ESET Link Checker",
                    safe=True,
                    details="URL considerada segura pelo ESET",
                )
            elif any(x in res_text for x in ["malicious", "phishing", "dangerous", "perigosa"]):
                return ExternalCheckResult(
                    source="ESET Link Checker",
                    safe=False,
                    details="URL identificada como perigosa pelo ESET",
                )
            return ExternalCheckResult(
                source="ESET Link Checker",
                safe=None,
                details=f"Resultado: {res_text}",
            )
        return ExternalCheckResult(
            source="ESET Link Checker",
            safe=None,
            details=f"HTTP {resp.status_code}",
        )
    except Exception as e:
        return ExternalCheckResult(
            source="ESET Link Checker",
            safe=None,
            details=f"Erro: {str(e)[:100]}",
        )


# ─────────────────────────────────────────────────
# Aggregated runner with progress callback
# ─────────────────────────────────────────────────
def run_all_external_checks(
    url: str, progress_callback: Optional[Callable[[str, float], None]] = None
) -> Dict[str, Any]:
    """
    Roda todas as verificações externas com progresso.
    progress_callback(step_label, fraction_0_1)
    """
    results: List[ExternalCheckResult] = []
    metadata: Optional[PageMetadata] = None

    steps = [
        ("Buscando metadados da página...", 0.15, lambda: None),
        ("Consultando Cloudflare Radar...", 0.35, lambda: check_cloudflare_radar(url)),
        ("Consultando ESET Link Checker...", 0.55, lambda: check_eset(url)),
        ("Consultando VirusTotal...", 0.70, lambda: check_virustotal(url)),
        ("Consultando Google Safe Browsing...", 0.85, lambda: check_google_safebrowsing(url)),
    ]

    # Step 0: metadata
    if progress_callback:
        progress_callback(steps[0][0], steps[0][1])
    metadata = fetch_page_metadata(url)

    # Steps 1-4: external checks
    for label, pct, fn in steps[1:]:
        if progress_callback:
            progress_callback(label, pct)
        try:
            result = fn()
            if result:
                results.append(result)
        except Exception:
            pass

    if progress_callback:
        progress_callback("Finalizando análise...", 0.95)

    # Aggregate
    external_votes = {"safe": 0, "malicious": 0, "unknown": 0}
    for r in results:
        if r.safe is True:
            external_votes["safe"] += 1
        elif r.safe is False:
            external_votes["malicious"] += 1
        else:
            external_votes["unknown"] += 1

    return {
        "metadata": metadata,
        "external_results": results,
        "external_votes": external_votes,
    }
