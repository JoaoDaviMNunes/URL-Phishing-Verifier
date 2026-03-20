from __future__ import annotations

import os
import re
from typing import Iterable, Iterator, List, Optional, Set, Tuple

import requests


def download_text_file(url: str, timeout_s: int = 30) -> str:
    resp = requests.get(url, timeout=timeout_s)
    resp.raise_for_status()
    return resp.text


def extract_urls_from_text(text: str) -> List[str]:
    # Extrai URLs http(s) de textos "dump" (txt/xml/json). Remove trailing caracteres comuns.
    candidates = re.findall(r"https?://[^\s\"'<>()]+", text, flags=re.IGNORECASE)
    cleaned: List[str] = []
    for c in candidates:
        cc = c.strip()
        cc = cc.rstrip(").,;]}")
        cleaned.append(cc)
    return cleaned


def normalize_url(url: str) -> str:
    return (url or "").strip()


def write_url_label_csv(urls: Iterable[str], label: int, out_csv_path: str, url_column: str = "url"):
    os.makedirs(os.path.dirname(out_csv_path) or ".", exist_ok=True)
    with open(out_csv_path, "w", encoding="utf-8") as f:
        f.write(f"{url_column},label\n")
        for u in urls:
            u = normalize_url(u)
            if not u:
                continue
            f.write(f"{u},{int(label)}\n")

