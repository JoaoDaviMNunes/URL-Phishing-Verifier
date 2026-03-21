from __future__ import annotations

import sys
import argparse
import os
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no PYTHONPATH para encontrar 'url_phishing_verifier'
sys.path.append(str(Path(__file__).parent.parent))

from url_phishing_verifier.collection.mendeley import collect_mendeley_phishing


def main() -> None:
    parser = argparse.ArgumentParser(description="Coleta URLs maliciosas a partir do Mendeley Phishing Dataset.")
    parser.add_argument("--input", required=True, help="CSV/TSV baixado localmente.")
    parser.add_argument("--out", required=True, help="CSV de saída (url,label).")
    parser.add_argument("--url-column", default="url", help="Nome da coluna com a URL.")
    parser.add_argument("--sep", default=None, help="Separador (opcional). Ex: ',' ou '\\t'.")
    parser.add_argument("--limit", type=int, default=None, help="Limite de URLs.")
    args = parser.parse_args()

    out_csv = collect_mendeley_phishing(
        input_csv_or_tsv=args.input,
        out_csv_path=args.out,
        url_column=args.url_column,
        sep=args.sep,
        limit=args.limit,
    )
    print(f"Coleta concluida: {os.path.abspath(out_csv)}")


if __name__ == "__main__":
    main()

