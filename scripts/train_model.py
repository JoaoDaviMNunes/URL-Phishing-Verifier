from __future__ import annotations

import argparse
import os

import pandas as pd

from url_phishing_verifier.data.io import load_labeled_urls
from url_phishing_verifier.features.extractor import ExtractorOptions
from url_phishing_verifier.model.trainer import train_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Treina modelo LightGBM para phishing em URLs.")
    parser.add_argument(
        "--csv",
        nargs="+",
        required=True,
        help="Um ou mais CSVs com colunas `url` e `label` (0=seguro, 1=phishing).",
    )
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--beta-fbeta", type=float, default=2.0, help="Beta do F-beta para escolher threshold (beta>1 privilegia recall).")
    parser.add_argument("--enable-ssl", action="store_true", help="Habilita features de SSL (pode ser lento).")
    parser.add_argument("--enable-geo", action="store_true", help="Habilita geolocalização (pode ser lento).")
    parser.add_argument("--geo-method", default="dns_api", choices=["dns_api", "ccTLD"])
    args = parser.parse_args()

    df = load_labeled_urls(
        csv_paths=args.csv, url_column=args.url_column, label_column=args.label_column
    )

    # Drop de duplicados e limpeza básica.
    df = df.drop_duplicates(subset=[args.url_column]).reset_index(drop=True)

    extractor_options = ExtractorOptions(
        enable_ssl=args.enable_ssl,
        enable_geo=args.enable_geo,
        geo_method=args.geo_method,
    )

    train_model(
        df=df,
        url_column=args.url_column,
        label_column=args.label_column,
        artifacts_dir=args.artifacts_dir,
        extractor_options=extractor_options,
        beta_fbeta=args.beta_fbeta,
    )

    print(f"Treino concluido. Artifacts em: {os.path.abspath(args.artifacts_dir)}")


if __name__ == "__main__":
    main()

