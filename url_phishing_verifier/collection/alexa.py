from __future__ import annotations

import os
from typing import Optional

import pandas as pd

from url_phishing_verifier.collection.utils import write_url_label_csv


def collect_alexa_legit(
    input_csv_or_txt: str,
    out_csv_path: str,
    url_scheme: str = "https",
    domain_column: Optional[str] = "domain",
    limit: Optional[int] = None,
) -> str:
    """
    Coleta URLs legítimas (ex: Alexa Top Sites).

    Espera um CSV com coluna de domínio (default: `domain`) ou um TXT com 1 domínio por linha.
    Converte domínio -> `https://{dominio}/`.
    """

    if not os.path.exists(input_csv_or_txt):
        raise FileNotFoundError(f"Arquivo não encontrado: {input_csv_or_txt}")

    urls = []
    if input_csv_or_txt.lower().endswith(".txt"):
        with open(input_csv_or_txt, "r", encoding="utf-8", errors="ignore") as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        df = pd.read_csv(input_csv_or_txt)
        if domain_column and domain_column in df.columns:
            domains = df[domain_column].astype(str).tolist()
        else:
            # tenta a primeira coluna
            domains = df.iloc[:, 0].astype(str).tolist()

    for d in domains:
        d = (d or "").strip().lower()
        if not d or d.startswith("http"):
            # Se já vier com scheme, mantém.
            if d.startswith("https://") or d.startswith("http://"):
                urls.append(d)
            continue
        urls.append(f"{url_scheme}://{d}/")

    # Dedup
    urls = list(dict.fromkeys(urls))
    if limit is not None:
        urls = urls[: int(limit)]

    write_url_label_csv(urls, label=0, out_csv_path=out_csv_path)
    return out_csv_path

