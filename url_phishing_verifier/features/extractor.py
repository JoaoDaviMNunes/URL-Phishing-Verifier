from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd
import tldextract

from url_phishing_verifier.features.geolocation import (
    resolve_country_by_cc_tld,
    resolve_country_by_dns_and_api,
)
from url_phishing_verifier.features.lexical import lexical_features
from url_phishing_verifier.features.ssl import fetch_certificate_info
from url_phishing_verifier.features.structural import structural_features
from url_phishing_verifier.config import DEFAULT_GEO_RISK


def _normalize_url(url: str) -> str:
    s = (url or "").strip()
    return s


@dataclass
class ExtractorOptions:
    enable_ssl: bool = False
    enable_geo: bool = False
    ssl_timeout_s: int = 3
    geo_timeout_s: int = 2
    # "dns_api" usa consulta DNS + API; "ccTLD" é só heuristica via sufixo.
    geo_method: str = "dns_api"


class URLFeatureExtractor:
    """
    Extrai features numéricas a partir de uma URL.

    Observação: SSL/Geo podem exigir rede e demorar; por isso são "opt-in".
    Para cumprir o pipeline, as colunas existem sempre, mas podem vir com NaN.
    """

    def __init__(self, options: Optional[ExtractorOptions] = None, tld_cache_dir: Optional[str] = None):
        self.options = options or ExtractorOptions()
        self.tldextractor = tldextract.TLDExtract(cache_dir=tld_cache_dir)

        self.feature_names: List[str] = [
            # Lexical
            "url_length",
            "url_entropy",
            "num_digits",
            "digits_ratio",
            "has_at",
            "has_dash",
            "has_question_mark",
            "has_suspicious_words",
            "suspicious_words_count",
            "excessive_digits",
            # Structural
            "num_subdomains",
            "subdomain_length",
            "domain_length",
            "suffix_length",
            "is_ip_address",
            "is_shortened_url",
            "has_path",
            "path_length",
            "has_query",
            "query_length",
            "uses_https",
            # SSL
            "ssl_has_valid_cert",
            "ssl_cert_days_to_expiry",
            "ssl_cert_days_since_start",
            # Geo
            "country_risk",
            "country_cc",
            "country_method",
        ]

    def extract_single(self, url: str) -> Dict[str, Any]:
        url = _normalize_url(url)

        feats: Dict[str, Any] = {}
        feats.update(lexical_features(url))
        feats.update(structural_features(url, self.tldextractor))

        # SSL
        ssl_has_valid_cert = np.nan
        ssl_days_to_expiry = np.nan
        ssl_days_since_start = np.nan
        if self.options.enable_ssl:
            # structural_features usa urlparse internamente; aqui precisamos do hostname.
            from urllib.parse import urlparse
            import re

            u = url
            if u and not re.match(r"^https?://", u, flags=re.IGNORECASE):
                u = "http://" + u
            host = urlparse(u).hostname or ""
            cert_info = fetch_certificate_info(hostname=host, timeout_s=self.options.ssl_timeout_s)
            ssl_has_valid_cert = 1.0 if cert_info.is_valid else 0.0 if cert_info.success else 0.0
            ssl_days_to_expiry = cert_info.days_to_expiry
            ssl_days_since_start = cert_info.days_since_start

        feats["ssl_has_valid_cert"] = float(ssl_has_valid_cert) if ssl_has_valid_cert is not None else np.nan
        feats["ssl_cert_days_to_expiry"] = ssl_days_to_expiry
        feats["ssl_cert_days_since_start"] = ssl_days_since_start

        # Geolocalização
        country_risk = np.nan
        country_cc = None
        country_method = None
        if self.options.enable_geo:
            if self.options.geo_method == "ccTLD":
                geo = resolve_country_by_cc_tld(url, self.tldextractor)
            else:
                geo = resolve_country_by_dns_and_api(
                    url, self.tldextractor, timeout_s=self.options.geo_timeout_s
                )

            country_cc = geo.country_cc
            country_risk = geo.country_risk
            country_method = geo.method
        else:
            # Mantém colunas numéricas e "method" como string para não quebrar o schema.
            # O modelo treinado (LightGBM) vai ignorar strings, então evitamos string na feature_names.
            # Aqui: country_cc e country_method viram NaN para evitar treino com strings.
            country_risk = DEFAULT_GEO_RISK.risk_for_cc("")
            country_cc = None
            country_method = None

        # LightGBM: precisamos de numerico; por isso:
        # - `country_risk` é o que modelamos
        # - `country_cc` e `country_method` existem só para debug no dashboard (não entram em treino por padrão)
        feats["country_risk"] = float(country_risk) if country_risk is not None else np.nan
        feats["country_cc"] = country_cc if country_cc is not None else ""
        feats["country_method"] = country_method if country_method is not None else ""

        return feats

    def transform(self, urls: Iterable[str]) -> pd.DataFrame:
        rows = [self.extract_single(u) for u in urls]
        df = pd.DataFrame(rows)

        # Garante todas as colunas esperadas.
        for c in self.feature_names:
            if c not in df.columns:
                df[c] = np.nan

        # O modelo só vai usar colunas numéricas. Mantemos country_cc/method no df
        # mas a camada de treino/predição seleciona apenas colunas numéricas.
        return df[self.feature_names]

    def numeric_feature_names(self) -> List[str]:
        # LightGBM só com numericos; country_cc/country_method são strings.
        numeric = [
            n
            for n in self.feature_names
            if n
            not in {
                "country_cc",
                "country_method",
            }
        ]
        return numeric

