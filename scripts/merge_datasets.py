from __future__ import annotations

import sys
import argparse
import os
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no PYTHONPATH para encontrar 'url_phishing_verifier'
sys.path.append(str(Path(__file__).parent.parent))

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser(description="Junta CSVs rotulados (url,label) em um dataset único.")
    parser.add_argument("--inputs", nargs="+", required=True, help="CSV(s) com colunas `url` e `label`.")
    parser.add_argument("--out", required=True, help="Caminho do CSV final (dataset.csv).")
    args = parser.parse_args()

    frames = []
    for p in args.inputs:
        filename = os.path.basename(p)
        print(f"Processando: {filename}")
        
        if "legit_alexa.csv" in filename:
            # legit_alexa.csv: no header, rank index 0, domain index 1
            df = pd.read_csv(p, header=None, names=["rank", "url"])
            df["label"] = 0
            df = df[["url", "label"]]
        
        elif "phishing_mendeley.csv" in filename:
            # phishing_mendeley.csv: url, Type (legitimate/phishing)
            df = pd.read_csv(p)
            df["label"] = df["Type"].map({"legitimate": 0, "phishing": 1})
            df = df[["url", "label"]]
        
        elif "phishing_phishtank.csv" in filename:
            # phishing_phishtank.csv: many columns, including URL and label
            df = pd.read_csv(p)
            df = df.rename(columns={"URL": "url"})
            df = df[["url", "label"]]
        
        else:
            # Fallback for other files possibly following (url, label)
            df = pd.read_csv(p)
            if "url" not in df.columns or "label" not in df.columns:
                print(f"Aviso: Arquivo `{filename}` ignorado pois não tem colunas `url` e `label`.")
                continue
            df = df[["url", "label"]]
            
        frames.append(df)

    if not frames:
        print("Nenhum dado para processar.")
        return

    out_df = pd.concat(frames, ignore_index=True).dropna(subset=["url", "label"])
    out_df["url"] = out_df["url"].astype(str)
    out_df["label"] = out_df["label"].astype(int)
    out_df = out_df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out_df.to_csv(args.out, index=False)
    print(f"Dataset final criado em: {os.path.abspath(args.out)}")
    print(f"Total de linhas (sem duplicatas): {len(out_df)}")
    print(f"Distribuição:\n{out_df['label'].value_counts()}")


if __name__ == "__main__":
    main()

