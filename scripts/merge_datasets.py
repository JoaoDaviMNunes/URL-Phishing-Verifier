from __future__ import annotations

import argparse
import os

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser(description="Junta CSVs rotulados (url,label) em um dataset único.")
    parser.add_argument("--inputs", nargs="+", required=True, help="CSV(s) com colunas `url` e `label`.")
    parser.add_argument("--out", required=True, help="Caminho do CSV final (dataset.csv).")
    args = parser.parse_args()

    frames = []
    for p in args.inputs:
        df = pd.read_csv(p)
        if "url" not in df.columns or "label" not in df.columns:
            raise ValueError(f"Arquivo `{p}` precisa ter colunas `url` e `label`.")
        df = df[["url", "label"]].copy()
        frames.append(df)

    out_df = pd.concat(frames, ignore_index=True).dropna(subset=["url", "label"])
    out_df["url"] = out_df["url"].astype(str)
    out_df["label"] = out_df["label"].astype(int)
    out_df = out_df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out_df.to_csv(args.out, index=False)
    print(f"Dataset final criado em: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()

