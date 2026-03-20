from __future__ import annotations

from typing import Iterable, List, Optional

import pandas as pd


def load_labeled_urls(
    csv_paths: Iterable[str],
    url_column: str = "url",
    label_column: str = "label",
    label_safe: int = 0,
    label_phishing: int = 1,
) -> pd.DataFrame:
    """
    Lê CSVs e espera que já tenham `url` e `label`.

    Se o seu dataset não tiver label, você pode:
    - pré-processar e criar `label` antes, ou
    - adaptar esta função.
    """

    frames: List[pd.DataFrame] = []
    for p in csv_paths:
        df = pd.read_csv(p)
        if url_column not in df.columns:
            # tenta alternativas comuns
            for alt in ["URL", "link", "Link", "target"]:
                if alt in df.columns:
                    df = df.rename(columns={alt: url_column})
                    break
        if label_column not in df.columns:
            raise ValueError(f"CSV `{p}` não tem coluna `{label_column}`. Atualize/prepare antes do treino.")
        df = df[[url_column, label_column]].copy()
        df[label_column] = df[label_column].astype(int)
        frames.append(df)

    if not frames:
        raise ValueError("Nenhum CSV foi fornecido.")

    out = pd.concat(frames, ignore_index=True)
    out = out.dropna(subset=[url_column, label_column])
    out[url_column] = out[url_column].astype(str)
    out[label_column] = out[label_column].astype(int)
    return out

