from __future__ import annotations

import argparse
import os

from url_phishing_verifier.collection.alexa import collect_alexa_legit


def main() -> None:
    parser = argparse.ArgumentParser(description="Coleta URLs legítimas tipo Alexa Top Sites.")
    parser.add_argument("--input", required=True, help="CSV ou TXT baixado localmente.")
    parser.add_argument("--out", required=True, help="CSV de saída (url,label).")
    parser.add_argument("--domain-column", default="domain", help="Coluna do domínio (CSV).")
    parser.add_argument("--scheme", default="https", help="Scheme para montar URLs.")
    parser.add_argument("--limit", type=int, default=None, help="Limite de URLs.")
    args = parser.parse_args()

    out_csv = collect_alexa_legit(
        input_csv_or_txt=args.input,
        out_csv_path=args.out,
        domain_column=args.domain_column,
        url_scheme=args.scheme,
        limit=args.limit,
    )
    print(f"Coleta concluida: {os.path.abspath(out_csv)}")


if __name__ == "__main__":
    main()

