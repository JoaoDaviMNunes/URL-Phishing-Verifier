from __future__ import annotations

import os
from typing import Optional

import pandas as pd

from url_phishing_verifier.collection.utils import write_url_label_csv


def collect_mendeley_phishing(
    input_csv_or_tsv: str,
    out_csv_path: str,
    url_column: str = "url",
    sep: Optional[str] = None,
    limit: Optional[int] = None,
) -> str:
    """
    Coleta URLs maliciosas a partir do "Mendeley Phishing Dataset".

    Este coletor assume que o dataset já está baixado e é um CSV/TSV com coluna de URL.
    Como a estrutura real pode variar, você pode ajustar `url_column`/`sep`.
    """

    if not os.path.exists(input_csv_or_tsv):
        raise FileNotFoundError(
            f"Arquivo não encontrado: {input_csv_or_tsv}. Baixe o dataset e aponte o caminho."
        )

    if sep is None:
        # Detecta separador simples: tenta CSV, depois TSV.
        try:
            df = pd.read_csv(input_csv_or_tsv)
        except Exception:
            df = pd.read_csv(input_csv_or_tsv, sep="\t")
    else:
        df = pd.read_csv(input_csv_or_tsv, sep=sep)

    if url_column not in df.columns:
        # tentativas comuns
        for alt in ["URL", "link", "Link", "target", "phish_url"]:
            if alt in df.columns:
                df = df.rename(columns={alt: url_column})
                break

    if url_column not in df.columns:
        raise ValueError(f"Não encontrei coluna de URL `{url_column}` no dataset.")

    urls = df[url_column].astype(str).tolist()
    urls = urls[: int(limit)] if limit is not None else urls
    write_url_label_csv(urls, label=1, out_csv_path=out_csv_path)
    return out_csv_path

