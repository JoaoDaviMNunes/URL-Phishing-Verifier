from __future__ import annotations

import os
import re
from typing import List, Optional, Set

from url_phishing_verifier.collection.utils import download_text_file, extract_urls_from_text, write_url_label_csv


def collect_phishtank(
    dump_url_or_path: str,
    out_csv_path: str,
    limit: Optional[int] = None,
    encoding: str = "utf-8",
) -> str:
    """
    Coleta URLs maliciosas a partir de um "dump/feed" de texto.

    Observação: o projeto não fixa um endpoint específico do PhishTank (pode mudar
    e também depende de chaves/APIs). Você deve apontar `dump_url_or_path` para um
    arquivo (local) ou URL HTTP que contenha URLs no corpo do texto.
    """

    source = (dump_url_or_path or "").strip()
    text = ""

    if os.path.exists(source):
        with open(source, "r", encoding=encoding, errors="ignore") as f:
            text = f.read()
    elif re.match(r"^https?://", source, flags=re.IGNORECASE):
        try:
            text = download_text_file(source)
        except Exception as exc:
            # Nao derruba o pipeline por problema de rede/endpoint.
            print(f"[WARN] Falha ao baixar feed PhishTank: {exc}")
            print("[WARN] Gerando CSV vazio para seguir o fluxo.")
            text = ""
    else:
        # Fonte invalida: cria CSV vazio em vez de quebrar o Makefile.
        print(f"[WARN] Fonte PhishTank invalida: {source}")
        print("[WARN] Use arquivo local existente ou URL iniciando com http(s)://")
        text = ""

    urls = extract_urls_from_text(text)
    # Dedup para reduzir ruído.
    deduped = list(dict.fromkeys(urls))
    if limit is not None:
        deduped = deduped[: int(limit)]

    write_url_label_csv(deduped, label=1, out_csv_path=out_csv_path)
    return out_csv_path

