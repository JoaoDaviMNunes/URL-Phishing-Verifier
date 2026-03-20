import datetime as dt
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class CertificateInfo:
    success: bool
    is_valid: bool
    days_to_expiry: Optional[float]
    days_since_start: Optional[float]


def _parse_cert_time(value: str) -> Optional[dt.datetime]:
    # Ex: 'May  1 12:00:00 2026 GMT'
    try:
        return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except Exception:
        # Alguns retornos variam em spacing
        try:
            return dt.datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc
            )
        except Exception:
            return None


def fetch_certificate_info(
    hostname: str, port: int = 443, timeout_s: int = 3, verify_hostname: bool = True
) -> CertificateInfo:
    if not hostname:
        return CertificateInfo(False, False, None, None)

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname if verify_hostname else None) as ssock:
                cert = ssock.getpeercert()

        not_before = _parse_cert_time(cert.get("notBefore"))
        not_after = _parse_cert_time(cert.get("notAfter"))
        if not_before is None or not_after is None:
            return CertificateInfo(True, False, None, None)

        now = dt.datetime.now(dt.timezone.utc)
        is_valid = (not_before <= now <= not_after)
        days_to_expiry = (not_after - now).total_seconds() / 86400.0
        days_since_start = (now - not_before).total_seconds() / 86400.0
        return CertificateInfo(True, bool(is_valid), float(days_to_expiry), float(days_since_start))
    except Exception:
        return CertificateInfo(False, False, None, None)


def ssl_features(url: str, hostname: str) -> dict:
    # SSL features presumem handshake/consulta em tempo real.
    # Em treino, isso é caro: use enable_ssl=False por padrão.
    # Esta função fica "genérica" e o caller decide se chama.
    return {
        "ssl_has_valid_cert": 0.0,
        "ssl_cert_days_to_expiry": None,
        "ssl_cert_days_since_start": None,
    }

